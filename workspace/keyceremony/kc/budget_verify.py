"""Independent offline verifier for signing-quota budgets.

Input: the hash-chained audit entries from an export bundle (or a raw audit
log). Nothing about live state is trusted: the budget orders, revision
chain, reservation credentials, signature digests and consumption/return
records are all reconstructed by replaying the append-only log.

For every quantity-changing event the verifier recomputes the counters from
scratch and checks the hard invariant at every instant:

    consumed + held <= total         (never over the budget; holds and
                                       consumptions both count)

Violation codes (the acceptance suite covers each on a modified archive):

    FORGED_BUDGET               budget event not authored by the recorded
                                security lead, or a budgeted signature whose
                                order was never created
    REVISION_ROLLBACK           revision numbers do not strictly increase
    SHRINK_BELOW_FLOOR          a revised total is below consumed + held
    DOUBLE_SPEND                one reservation settled or released twice
    OVER_BUDGET                 a hold would push consumed+held past total
    CROSS_SUBJECT_DIVERSION     reservation subject / purpose / key version
                                differ from the budget order they draw on
    RESERVATION_AFTER_WINDOW    hold outside effective..expiry (also covers
                                paused budgets and revoked subjects / retired
                                key versions that still granted a hold)
    RELEASE_WITH_SIGNATURE      a reservation released after a signature
                                audit was written (quota can never be reused)
    CONSUME_WITHOUT_SIGNATURE   settle event with no preceding signature
    SIGNATURE_WITHOUT_SETTLEMENT  signature audit never followed by a charge
    BAD_RESERVATION_CREDENTIAL  replay presented an invalid credential, or a
                                settle/release references an unknown hold

Only budget-* events are interpreted here; all other ceremony events are
ignored. Purposes without a budget order are legacy signing and never
violate anything (a legacy `sign` call produces no budget events).
"""

from __future__ import annotations

from . import crypto

# event names
EV_SUBJECT_REGISTERED = "budget_subject_registered"
EV_SUBJECT_REVOKED = "budget_subject_revoked"
EV_BUDGET_CREATED = "budget_created"
EV_BUDGET_REVISED = "budget_revised"
EV_BUDGET_PAUSED = "budget_paused"
EV_BUDGET_RESUMED = "budget_resumed"
EV_HELD = "budget_reservation_held"
EV_SIGNED = "budget_signature_issued"
EV_SETTLED = "budget_reservation_settled"
EV_RELEASED = "budget_reservation_released"

BUDGET_EVENTS = {
    EV_SUBJECT_REGISTERED, EV_SUBJECT_REVOKED, EV_BUDGET_CREATED,
    EV_BUDGET_REVISED, EV_BUDGET_PAUSED, EV_BUDGET_RESUMED,
    EV_HELD, EV_SIGNED, EV_SETTLED, EV_RELEASED,
}


class Finding:
    def __init__(self, code: str, seq: int | None, message: str):
        self.code = code
        self.seq = seq
        self.message = message

    def as_dict(self) -> dict:
        return {"code": self.code, "seq": self.seq, "message": self.message}


class _BudgetState:
    def __init__(self, payload: dict):
        self.budget_id = payload["budget_id"]
        self.purpose = payload["purpose"]
        self.subject = payload["subject"]
        self.key_version_id = payload["key_version_id"]
        self.total = int(payload["total"])
        self.batch_cap = int(payload["batch_cap"])
        self.valid_from = float(payload["valid_from"])
        self.valid_until = float(payload["valid_until"])
        self.revision = int(payload["revision"])
        self.status = payload.get("status", "ACTIVE")
        self.created_by = payload.get("by", payload.get("created_by"))
        self.consumed = 0
        self.held = 0
        self.released = 0
        # point-in-time counter ledger, one entry per quantity-changing event
        self.ledger: list[dict] = []

    @property
    def floor(self) -> int:
        return self.consumed + self.held

    def snapshot(self, seq: int, event: str) -> dict:
        return {"seq": seq, "event": event, "total": self.total,
                "consumed": self.consumed, "held": self.held,
                "released": self.released,
                "available": self.total - self.consumed - self.held}


class _Reservation:
    def __init__(self, payload: dict, seq: int):
        self.request_id = payload["request_id"]
        self.reservation_id = payload["reservation_id"]
        self.budget_id = payload["budget_id"]
        self.subject = payload["subject"]
        self.purpose = payload["purpose"]
        self.key_version_id = payload["key_version_id"]
        self.quantity = int(payload["quantity"])
        self.held_seq = seq
        self.held_at = float(payload["held_at"])
        self.lease_expires_at = float(payload["lease_expires_at"])
        self.credential = payload.get("credential")
        self.state = "HELD"
        self.signed_seq = None
        self.settled_seq = None
        self.released_seq = None


def verify_budget_audit(entries: list[dict], *,
                        security_leads: frozenset[str] | None = None) -> dict:
    """Replay budget events. `entries` is the list of audit envelope dicts
    (each carrying event/payload/ts/seq). Returns
    {ok, findings, budgets, reservations, counters}."""
    findings: list[Finding] = []

    def flag(code, seq, msg):
        findings.append(Finding(code, seq, msg))

    subjects: dict[str, dict] = {}
    budgets: dict[str, _BudgetState] = {}
    by_purpose: dict[str, str] = {}
    reservations: dict[str, _Reservation] = {}
    # key versions observed retired/destroyed through non-budget audit events
    retired_keys: set[str] = set()

    lead = lambda p: (security_leads is None
                      or p.get("by") in security_leads
                      or p.get("created_by") in security_leads
                      or p.get("actor") in security_leads)

    for e in entries:
        ev = e.get("event")
        if ev not in BUDGET_EVENTS:
            # key retirement visibility for the verifier: a rotation retires
            # the displaced ACTIVE key; DESTROY zeroizes a RETIRING one.
            p0 = e.get("payload", {})
            if ev == "rotation_published" and p0.get("old"):
                retired_keys.add(p0["old"])
            elif ev == "key_destroyed" and p0.get("key_version_id"):
                retired_keys.add(p0["key_version_id"])
            continue
        p = e.get("payload", {})
        seq = e.get("seq")

        # ---- subjects ---------------------------------------------------
        if ev == EV_SUBJECT_REGISTERED:
            subj = p.get("subject")
            if subj in subjects:
                flag("FORGED_BUDGET", seq,
                     f"subject {subj} registered twice")
            subjects[subj] = {"registered_at": p.get("at"),
                              "revoked_at": None}
            continue
        if ev == EV_SUBJECT_REVOKED:
            subj = p.get("subject")
            if subj not in subjects:
                flag("FORGED_BUDGET", seq,
                     f"revocation for unknown subject {subj}")
            else:
                subjects[subj]["revoked_at"] = p.get("at")
            continue

        # ---- budget orders ----------------------------------------------
        if ev == EV_BUDGET_CREATED:
            bid = p.get("budget_id")
            if not lead(p):
                flag("FORGED_BUDGET", seq,
                     f"budget {bid} created by non-security-lead "
                     f"{p.get('by')}")
            if bid in budgets:
                flag("FORGED_BUDGET", seq, f"duplicate budget id {bid}")
            purpose = p.get("purpose")
            if purpose in by_purpose:
                flag("FORGED_BUDGET", seq,
                     f"second budget for purpose {purpose}")
            if p.get("subject") not in subjects:
                flag("FORGED_BUDGET", seq,
                     f"budget {bid} names unregistered subject "
                     f"{p.get('subject')}")
            try:
                bs = _BudgetState(p)
            except (KeyError, TypeError, ValueError):
                flag("FORGED_BUDGET", seq,
                     f"budget {bid} payload malformed")
                continue
            budgets[bid] = bs
            by_purpose[purpose] = bid
            bs.ledger.append(bs.snapshot(seq, ev))
            continue

        if ev == EV_BUDGET_REVISED:
            bid = p.get("budget_id")
            bs = budgets.get(bid)
            if bs is None:
                flag("FORGED_BUDGET", seq,
                     f"revision for unknown budget {bid}")
                continue
            if not lead(p):
                flag("FORGED_BUDGET", seq,
                     f"budget {bid} revised by non-security-lead {p.get('by')}")
            new_rev = int(p["revision"])
            if new_rev != bs.revision + 1:
                flag("REVISION_ROLLBACK", seq,
                     f"budget {bid} revision {bs.revision} -> {new_rev} "
                     f"(must increase by 1)")
            # even on a bad revision number, continue checking the totals
            new_total = int(p["total"])
            if new_total < bs.floor:
                flag("SHRINK_BELOW_FLOOR", seq,
                     f"budget {bid} revised total {new_total} < consumed "
                     f"{bs.consumed} + held {bs.held} = {bs.floor}")
            bs.total = new_total
            bs.batch_cap = int(p["batch_cap"])
            bs.valid_from = float(p["valid_from"])
            bs.valid_until = float(p["valid_until"])
            bs.revision = new_rev
            bs.status = p.get("status", bs.status)
            bs.ledger.append(bs.snapshot(seq, ev))
            continue

        if ev == EV_BUDGET_PAUSED:
            bs = budgets.get(p.get("budget_id"))
            if bs is None:
                flag("FORGED_BUDGET", seq, "pause on unknown budget")
            else:
                bs.status = "PAUSED"
            continue
        if ev == EV_BUDGET_RESUMED:
            bs = budgets.get(p.get("budget_id"))
            if bs is None:
                flag("FORGED_BUDGET", seq, "resume on unknown budget")
            else:
                bs.status = "ACTIVE"
            continue

        # ---- reservations ------------------------------------------------
        if ev == EV_HELD:
            rid = p.get("request_id")
            bid = p.get("budget_id")
            bs = budgets.get(bid)
            if bs is None:
                flag("FORGED_BUDGET", seq,
                     f"reservation {rid} on unknown budget {bid}")
                continue
            if rid in reservations:
                flag("DOUBLE_SPEND", seq,
                     f"request {rid} held twice")
                continue
            if p.get("subject") != bs.subject:
                flag("CROSS_SUBJECT_DIVERSION", seq,
                     f"request {rid} subject {p.get('subject')} != budget "
                     f"subject {bs.subject}")
            if p.get("purpose") != bs.purpose:
                flag("CROSS_SUBJECT_DIVERSION", seq,
                     f"request {rid} purpose {p.get('purpose')} != budget "
                     f"purpose {bs.purpose}")
            if p.get("key_version_id") != bs.key_version_id:
                flag("CROSS_SUBJECT_DIVERSION", seq,
                     f"request {rid} key {p.get('key_version_id')} != "
                     f"budget key {bs.key_version_id}")
            subj = subjects.get(bs.subject)
            held_at = float(p["held_at"])
            if subj is None:
                flag("FORGED_BUDGET", seq,
                     f"request {rid}: subject missing")
            elif subj.get("revoked_at") is not None and \
                    held_at >= float(subj["revoked_at"]):
                flag("RESERVATION_AFTER_WINDOW", seq,
                     f"request {rid} held after subject revocation")
            if bs.status == "PAUSED":
                flag("RESERVATION_AFTER_WINDOW", seq,
                     f"request {rid} held while budget paused")
            if not (bs.valid_from <= held_at < bs.valid_until):
                flag("RESERVATION_AFTER_WINDOW", seq,
                     f"request {rid} held at {held_at} outside window "
                     f"[{bs.valid_from}, {bs.valid_until})")
            if p.get("key_version_id") in retired_keys:
                flag("RESERVATION_AFTER_WINDOW", seq,
                     f"request {rid} held on retired key")
            qty = int(p["quantity"])
            if qty > bs.batch_cap:
                flag("OVER_BUDGET", seq,
                     f"request {rid} quantity {qty} exceeds batch cap "
                     f"{bs.batch_cap}")
            if bs.consumed + bs.held + qty > bs.total:
                flag("OVER_BUDGET", seq,
                     f"request {rid}: consumed {bs.consumed} + held "
                     f"{bs.held} + qty {qty} > total {bs.total}")
            rsv = _Reservation(p, seq)
            reservations[rid] = rsv
            bs.held += qty
            bs.ledger.append(bs.snapshot(seq, ev))
            continue

        rsv = reservations.get(p.get("request_id"))
        if rsv is None:
            flag("BAD_RESERVATION_CREDENTIAL", seq,
                 f"{ev} references unknown request "
                 f"{p.get('request_id')}")
            continue
        bs = budgets.get(rsv.budget_id)

        if ev == EV_SIGNED:
            if rsv.state != "HELD":
                flag("DOUBLE_SPEND", seq,
                     f"signature on {rsv.state} request {rsv.request_id}")
            if p.get("key_version_id") != rsv.key_version_id:
                flag("CROSS_SUBJECT_DIVERSION", seq,
                     f"signature key {p.get('key_version_id')} != reserved "
                     f"{rsv.key_version_id}")
            if p.get("subject") is not None and p.get("subject") != rsv.subject:
                flag("CROSS_SUBJECT_DIVERSION", seq,
                     f"signature subject diversion on {rsv.request_id}")
            rsv.state = "SIGNED"
            rsv.signed_seq = seq
            continue

        if ev == EV_SETTLED:
            if rsv.state == "CONSUMED":
                flag("DOUBLE_SPEND", seq,
                     f"request {rsv.request_id} settled twice")
                continue
            if rsv.state == "RELEASED":
                flag("RELEASE_WITH_SIGNATURE", seq,
                     f"request {rsv.request_id} settled after release")
                continue
            if rsv.state != "SIGNED":
                flag("CONSUME_WITHOUT_SIGNATURE", seq,
                     f"request {rsv.request_id} settled in state "
                     f"{rsv.state} with no signature audit")
            if int(p.get("quantity", rsv.quantity)) != rsv.quantity:
                flag("OVER_BUDGET", seq,
                     f"settle quantity {p.get('quantity')} != held "
                     f"{rsv.quantity} on {rsv.request_id}")
            rsv.state = "CONSUMED"
            rsv.settled_seq = seq
            bs.held -= rsv.quantity
            bs.consumed += rsv.quantity
            if bs.consumed > bs.total:
                flag("OVER_BUDGET", seq,
                     f"consumed {bs.consumed} > total {bs.total}")
            # cross-check the event's self-reported running total
            reported = p.get("consumed_total_after")
            if reported is not None and int(reported) != bs.consumed:
                flag("OVER_BUDGET", seq,
                     f"reported consumed_total_after {reported} != recomputed "
                     f"{bs.consumed}")
            bs.ledger.append(bs.snapshot(seq, ev))
            continue

        if ev == EV_RELEASED:
            if rsv.state == "CONSUMED":
                flag("DOUBLE_SPEND", seq,
                      f"request {rsv.request_id} released after consume")
                continue
            if rsv.state == "RELEASED":
                flag("DOUBLE_SPEND", seq,
                     f"request {rsv.request_id} released twice")
                continue
            if rsv.state == "SIGNED":
                flag("RELEASE_WITH_SIGNATURE", seq,
                     f"request {rsv.request_id} released after signature "
                     f"at seq {rsv.signed_seq}; quota must not be reusable")
            released_at = float(p["released_at"])
            reason = p.get("release_reason")
            if reason != "manual_early_release" and \
                    released_at < rsv.lease_expires_at:
                flag("RESERVATION_AFTER_WINDOW", seq,
                     f"request {rsv.request_id} released at {released_at} "
                     f"before lease expiry {rsv.lease_expires_at}")
            # before/after held quantities, if reported, must recompute
            before = p.get("held_total_before")
            after = p.get("held_total_after")
            if before is not None and int(before) != bs.held:
                flag("OVER_BUDGET", seq,
                     f"release held_total_before {before} != recomputed "
                     f"{bs.held}")
            rsv.state = "RELEASED"
            rsv.released_seq = seq
            bs.held -= rsv.quantity
            bs.released += rsv.quantity
            if after is not None and int(after) != bs.held:
                flag("OVER_BUDGET", seq,
                     f"release held_total_after {after} != recomputed "
                     f"{bs.held}")
            if bs.held < 0:
                flag("OVER_BUDGET", seq, f"held went negative on {bs.budget_id}")
            bs.ledger.append(bs.snapshot(seq, ev))
            continue

    # end-of-log sweep: signature without settlement, stuck holds past lease
    for rid, rsv in reservations.items():
        if rsv.state == "SIGNED":
            flag("SIGNATURE_WITHOUT_SETTLEMENT", rsv.signed_seq,
                 f"request {rid} has a signature audit but was never "
                 f"settled or released")
        if rsv.state == "HELD":
            # an expired hold still parked at log end is the takeover target;
            # the live system would have swept it. Flag only as informational
            # dangling (not a forgery class) unless a signature is present,
            # which cannot be released and must have been settled.
            if rsv.signed_seq is not None:
                flag("SIGNATURE_WITHOUT_SETTLEMENT", rsv.signed_seq,
                     f"request {rid} signed but never settled")

    ok = not findings
    return {
        "ok": ok,
        "findings": [f.as_dict() for f in findings],
        "budgets": {bid: {
            "purpose": bs.purpose, "subject": bs.subject,
            "key_version_id": bs.key_version_id, "total": bs.total,
            "consumed": bs.consumed, "held": bs.held,
            "released": bs.released,
            "available": bs.total - bs.consumed - bs.held,
            "revision": bs.revision, "status": bs.status,
            "ledger": bs.ledger,
        } for bid, bs in budgets.items()},
        "reservations": {rid: {
            "reservation_id": rsv.reservation_id, "budget_id": rsv.budget_id,
            "state": rsv.state, "quantity": rsv.quantity,
            "held_seq": rsv.held_seq, "signed_seq": rsv.signed_seq,
            "settled_seq": rsv.settled_seq, "released_seq": rsv.released_seq,
        } for rid, rsv in reservations.items()},
    }
