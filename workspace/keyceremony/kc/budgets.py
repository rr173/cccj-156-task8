"""Verifiable signing-quota budgets for the signing entry point.

A *security lead* issues a budget order for a `(purpose, key_version)` pair:
it names the calling subject allowed to draw on it, how many signatures may
be produced in total, the per-request batch cap, and an effective/expiry time
window. Budgets carry an increasing revision number; two admins editing at
once use optimistic concurrency (base_revision), and a shrink may never cut
below what is already consumed plus what is still reserved.

Every budgeted signing request follows the same three durable steps, each of
which appends an entry to the same hash-chained, service-signed audit log as
the rest of the system:

    budget_reservation_held      reserve quantity under a unique request id,
                                 with a short lease and a signed credential
    budget_signature_issued      signature digest written (the signature
                                 audit a takeover consults)
    budget_reservation_settled   hold -> consumed ("CONSUMED")

A reservation may instead be returned:

    budget_reservation_released  hold -> released ("RELEASED"), only ever
                                 possible when no signature was produced

Idempotency: re-submitting the same request id never produces a second
signature or a second charge; the caller receives the original signature and
settlement record. A worker that dies between the steps leaves exactly the
evidence a takeover needs - signature present means settle (the quota can
never be reused), signature absent and the lease expired means release.

The manager is a pure state machine over `state.json` collections and audit
append; every mutating method must be invoked inside `store.locked()` and
with the *freshest* loaded state, so cross-process contenders for the final
unit serialize correctly: consumed + currently held can never exceed total.

Purposes without a budget order keep signing exactly as before (the legacy
path in `Orchestrator.sign`); this module only intercepts purposes for which
an order exists.
"""

from __future__ import annotations

import os
import time

from . import crypto
from .errors import (
    ConflictState, Forbidden, NotFound, PolicyViolation,
    RevisionConflict,
)

# ---- budget lifecycle ------------------------------------------------------
ACTIVE_B = "ACTIVE"      # reservations allowed (inside the time window)
PAUSED = "PAUSED"        # security lead paused it: no new reservations

# ---- reservation lifecycle -------------------------------------------------
HELD = "HELD"
CONSUMED = "CONSUMED"
RELEASED = "RELEASED"
TERMINAL_RESERVATION_STATES = (CONSUMED, RELEASED)

# Reasons a new reservation is refused (machine-readable).
E_NO_BUDGET = "NO_BUDGET"                 # purpose is unbudgeted -> legacy path
E_BUDGET_PAUSED = "BUDGET_PAUSED"
E_SUBJECT_REVOKED = "SUBJECT_REVOKED"
E_SUBJECT_MISMATCH = "SUBJECT_MISMATCH"
E_KEY_RETIRED = "KEY_VERSION_RETIRED"
E_NOT_YET_VALID = "BUDGET_NOT_YET_VALID"
E_EXPIRED = "BUDGET_WINDOW_EXPIRED"
E_EXHAUSTED = "QUOTA_EXHAUSTED"
E_BATCH_CAP = "BATCH_CAP_EXCEEDED"
E_REQUEST_IN_FLIGHT = "REQUEST_IN_FLIGHT"
E_RESERVATION_NOT_FOUND = "RESERVATION_NOT_FOUND"
E_RESERVATION_NOT_HELD = "RESERVATION_NOT_HELD"
E_LEASE_NOT_EXPIRED = "LEASE_NOT_EXPIRED"
E_SIGNATURE_PRESENT = "RESERVATION_HAS_SIGNATURE"
E_BUDGET_REVISION = "BUDGET_REVISION_CONFLICT"
E_SHRINK_BELOW_FLOOR = "SHRINK_BELOW_CONSUMED_PLUS_HELD"
E_BAD_CREDENTIAL = "RESERVATION_CREDENTIAL_INVALID"

DEFAULT_LEASE_SECONDS = 30
MIN_LEASE_SECONDS = 1


# ---------------------------------------------------------------------------
# error types specific to budgets (kept here so errors.py stays stable)
# ---------------------------------------------------------------------------

class BudgetError(ConflictState):
    code = "BUDGET_ERROR"

    def __init__(self, message: str = "", reason: str | None = None,
                 *, details: dict | None = None):
        super().__init__(message)
        if reason:
            self.code = reason
        self.reason = reason or self.code
        self.details = details or {}


# ---------------------------------------------------------------------------
# manager
# ---------------------------------------------------------------------------

class BudgetManager:
    """State machine over state['sign_budgets'] / ['sign_requests'].

    The hash-chained audit log is the authoritative durable record: every
    state transition appends (and fsyncs) its audit entry first and saves
    state.json atomically right after. `recover()` (run at construction)
    rebuilds or advances records from audit events, so a process killed in
    the gap between the two writes loses nothing - a takeover decides using
    the *signature audit*, exactly as the protocol requires.
    """

    def __init__(self, state: dict, audit, keys_by_id: dict | None = None,
                 clock=time.time, persist=None):
        self.s = state
        self.audit = audit
        # directory key versions keyed by id; used to check retirement. The
        # orchestrator passes its KeyDirectory-backed collection; the offline
        # verifier reconstructs a plain dict from the export bundle.
        self.keys_by_id = keys_by_id if keys_by_id is not None else {}
        self.clock = clock
        self._persist = persist
        self.recover()

    def _save(self):
        if self._persist is not None:
            self._persist()

    # ======================================================================
    # event-sourced recovery: the fsynced audit log is the source of truth.
    # A worker killed after an audit append but before the atomic state.json
    # rename is rebuilt here. Replaying an up-to-date state is a no-op.
    # ======================================================================
    def recover(self) -> dict:
        n_subjects = n_budgets = n_requests = n_advanced = 0
        for e in self.audit.entries:
            ev, p = e.get("event"), e.get("payload", {})
            if ev == "budget_subject_registered":
                subj = p.get("subject")
                if subj not in self.s["sign_subjects"]:
                    self.s["sign_subjects"][subj] = {
                        "subject": subj, "name": p.get("name", ""),
                        "revoked": False,
                        "registered_at": p.get("at"),
                        "registered_by": p.get("actor")}
                    n_subjects += 1
            elif ev == "budget_subject_revoked":
                rec = self.s["sign_subjects"].get(p.get("subject"))
                if rec is not None and not rec.get("revoked"):
                    rec.update(revoked=True, revoked_at=p.get("at"),
                               revoked_by=p.get("actor"))
                    n_advanced += 1
            elif ev == "budget_created":
                bid = p["budget_id"]
                if bid not in self.s["sign_budgets"]:
                    self.s["sign_budgets"][bid] = {
                        "budget_id": bid, "purpose": p["purpose"],
                        "key_version_id": p["key_version_id"],
                        "subject": p["subject"], "total": int(p["total"]),
                        "batch_cap": int(p["batch_cap"]),
                        "valid_from": float(p["valid_from"]),
                        "valid_until": float(p["valid_until"]),
                        "lease_seconds": int(p["lease_seconds"]),
                        "revision": int(p["revision"]),
                        "status": p.get("status", ACTIVE_B),
                        "created_by": p.get("by"), "created_at": p.get("at"),
                        "reason": p.get("reason", ""),
                        "paused_at": None, "resumed_at": None,
                        "revisions": [{"revision": 1, "total": int(p["total"]),
                            "batch_cap": int(p["batch_cap"]),
                            "valid_from": float(p["valid_from"]),
                            "valid_until": float(p["valid_until"]),
                            "lease_seconds": int(p["lease_seconds"]),
                            "by": p.get("by"), "reason": p.get("reason", ""),
                            "at": p.get("at")}]}
                    n_budgets += 1
            elif ev == "budget_revised":
                b = self.s["sign_budgets"].get(p["budget_id"])
                rev = int(p["revision"])
                if b is not None and rev > b["revision"]:
                    b.update(total=int(p["total"]),
                             batch_cap=int(p["batch_cap"]),
                             valid_from=float(p["valid_from"]),
                             valid_until=float(p["valid_until"]),
                             lease_seconds=int(p["lease_seconds"]),
                             revision=rev, status=p.get("status", b["status"]))
                    b["revisions"].append({
                        "revision": rev, "total": int(p["total"]),
                        "batch_cap": int(p["batch_cap"]),
                        "valid_from": float(p["valid_from"]),
                        "valid_until": float(p["valid_until"]),
                        "lease_seconds": int(p["lease_seconds"]),
                        "by": p.get("by"), "reason": p.get("reason", ""),
                        "at": p.get("at")})
                    n_advanced += 1
                elif b is not None and rev == b["revision"] and \
                        not any(r["revision"] == rev for r in b["revisions"]):
                    b["revisions"].append({"revision": rev,
                        "total": int(p["total"]),
                        "batch_cap": int(p["batch_cap"]),
                        "valid_from": float(p["valid_from"]),
                        "valid_until": float(p["valid_until"]),
                        "lease_seconds": int(p["lease_seconds"]),
                        "by": p.get("by"), "reason": p.get("reason", ""),
                        "at": p.get("at")})
            elif ev in ("budget_paused", "budget_resumed"):
                b = self.s["sign_budgets"].get(p.get("budget_id"))
                want = PAUSED if ev == "budget_paused" else ACTIVE_B
                if b is not None and b["status"] != want:
                    b["status"] = want
                    if want == PAUSED:
                        b["paused_at"] = p.get("at")
                    else:
                        b["resumed_at"] = p.get("at")
                    n_advanced += 1
            elif ev == "budget_reservation_held":
                rid = p["request_id"]
                if rid not in self.s["sign_requests"]:
                    self.s["sign_requests"][rid] = {
                        "reservation_id": p["reservation_id"],
                        "request_id": rid, "budget_id": p["budget_id"],
                        "purpose": p["purpose"], "subject": p["subject"],
                        "key_version_id": p["key_version_id"],
                        "quantity": int(p["quantity"]), "state": HELD,
                        "held_at": float(p["held_at"]),
                        "lease_expires_at": float(p["lease_expires_at"]),
                        "settled_at": None, "released_at": None,
                        "release_reason": None, "released_by": None,
                        "signature": None,
                        "credential": p.get("credential")}
                    n_requests += 1
            elif ev == "budget_signature_issued":
                rec = self.s["sign_requests"].get(p.get("request_id"))
                if rec is not None and rec.get("signature") is None:
                    rec["signature"] = {
                        "key_version_id": p["key_version_id"],
                        "message_digest": p["message_digest"],
                        "signature": p["signature"],
                        "issued_at": float(p["issued_at"]),
                        "audit_digest": p["audit_digest"]}
                    n_advanced += 1
            elif ev == "budget_reservation_settled":
                rec = self.s["sign_requests"].get(p.get("request_id"))
                if rec is not None and rec["state"] != CONSUMED:
                    rec["state"] = CONSUMED
                    rec["settled_at"] = float(p["settled_at"])
                    n_advanced += 1
            elif ev == "budget_reservation_released":
                rec = self.s["sign_requests"].get(p.get("request_id"))
                if rec is not None and rec["state"] != RELEASED:
                    rec.update(state=RELEASED,
                               released_at=float(p["released_at"]),
                               release_reason=p.get("release_reason"),
                               released_by=p.get("released_by"))
                    n_advanced += 1
        return {"subjects_rebuilt": n_subjects, "budgets_rebuilt": n_budgets,
                "requests_rebuilt": n_requests,
                "records_advanced": n_advanced}

    # ======================================================================
    # subjects (calling principals)
    # ======================================================================
    def register_subject(self, subject: str, name: str = "",
                         actor: str = "system") -> dict:
        rec = self.s["sign_subjects"].get(subject)
        if rec is not None:
            raise ConflictState(f"subject {subject} already registered")
        rec = {"subject": subject, "name": name, "revoked": False,
               "registered_at": self._now(),
               "registered_by": actor}
        self.s["sign_subjects"][subject] = rec
        self.audit.append("budget_subject_registered",
                          {"subject": subject, "name": name, "actor": actor,
                           "at": rec["registered_at"]})
        self._save()
        return dict(rec)

    def revoke_subject(self, subject: str, actor: str = "system",
                       reason: str = "") -> dict:
        rec = self._subject(subject)
        if rec["revoked"]:
            return dict(rec)
        rec["revoked"] = True
        rec["revoked_at"] = self._now()
        rec["revoked_by"] = actor
        self.audit.append("budget_subject_revoked",
                          {"subject": subject, "actor": actor,
                           "reason": reason, "at": rec["revoked_at"]})
        self._save()
        return dict(rec)

    def _subject(self, subject: str) -> dict:
        rec = self.s["sign_subjects"].get(subject)
        if rec is None:
            raise NotFound(f"unknown signing subject {subject}")
        return rec

    # ======================================================================
    # budget orders / revision chain
    # ======================================================================
    def create_budget(self, *, purpose: str, key_version_id: str,
                      subject: str, total: int, batch_cap: int,
                      valid_from: float | None, valid_until: float,
                      actor: str, reason: str = "",
                      lease_seconds: int = DEFAULT_LEASE_SECONDS) -> dict:
        self._require_int(total, "total", min_value=0)
        self._require_int(batch_cap, "batch_cap", min_value=1)
        self._require_int(lease_seconds, "lease_seconds",
                          min_value=MIN_LEASE_SECONDS)
        now = self._now()
        if valid_from is None:
            valid_from = now
        self._check_window(valid_from, valid_until)
        self._subject(subject)  # must exist
        if key_version_id not in self.keys_by_id:
            raise NotFound(f"unknown key version {key_version_id}")
        kv = self.keys_by_id[key_version_id]
        if kv.get("purpose") != purpose:
            raise PolicyViolation(
                f"key version {key_version_id} belongs to purpose "
                f"{kv.get('purpose')}, not {purpose}")
        existing = self._budget_for_purpose(purpose)
        if existing is not None:
            raise ConflictState(
                f"purpose {purpose} already has budget {existing['budget_id']}")
        bid = "bg_" + crypto.b64e(crypto.digest(
            {"purpose": purpose, "subject": subject,
             "r": crypto.b64e(os.urandom(8))}))[:22].replace("+", "-").replace("/", "_")
        rec = {
            "budget_id": bid,
            "purpose": purpose,
            "key_version_id": key_version_id,
            "subject": subject,
            "total": total,
            "batch_cap": batch_cap,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "lease_seconds": lease_seconds,
            "revision": 1,
            "status": ACTIVE_B,
            "created_by": actor,
            "created_at": now,
            "reason": reason,
            "paused_at": None,
            "resumed_at": None,
            "revisions": [{
                "revision": 1, "total": total, "batch_cap": batch_cap,
                "valid_from": valid_from, "valid_until": valid_until,
                "lease_seconds": lease_seconds,
                "by": actor, "reason": reason, "at": now,
            }],
        }
        self.s["sign_budgets"][bid] = rec
        self.audit.append("budget_created", self._order_payload(rec))
        self._save()
        return self.public_budget(bid)

    def revise_budget(self, budget_id: str, *, base_revision: int,
                      actor: str, total: int | None = None,
                      batch_cap: int | None = None,
                      valid_from: float | None = None,
                      valid_until: float | None = None,
                      lease_seconds: int | None = None,
                      reason: str = "") -> dict:
        b = self._budget(budget_id)
        cur = b["revision"]
        if int(base_revision) != cur:
            snap = self.public_budget(budget_id)
            raise RevisionConflict(
                f"budget {budget_id} is at revision {cur}; your change was "
                f"based on {base_revision}",
                base_revision=int(base_revision),
                current_revision=cur,
                base_snapshot={"revision": int(base_revision),
                               "total": b["revisions"][int(base_revision) - 1]["total"]
                               if 1 <= int(base_revision) <= len(b["revisions"])
                               else None},
                current_snapshot=snap)
        now = self._now()
        new_total = b["total"] if total is None else total
        new_batch = b["batch_cap"] if batch_cap is None else batch_cap
        new_from = b["valid_from"] if valid_from is None else valid_from
        new_until = b["valid_until"] if valid_until is None else valid_until
        new_lease = b["lease_seconds"] if lease_seconds is None else lease_seconds
        self._require_int(new_total, "total", min_value=0)
        self._require_int(new_batch, "batch_cap", min_value=1)
        self._require_int(new_lease, "lease_seconds",
                          min_value=MIN_LEASE_SECONDS)
        self._check_window(new_from, new_until)
        floor = self.consumed(budget_id) + self.held(budget_id, now=now)
        if new_total < floor:
            raise BudgetError(
                f"cannot shrink budget {budget_id} to {new_total}: "
                f"consumed {self.consumed(budget_id)} + held "
                f"{self.held(budget_id, now=now)} = {floor}",
                reason=E_SHRINK_BELOW_FLOOR,
                details={"budget_id": budget_id, "proposed_total": new_total,
                         "consumed": self.consumed(budget_id),
                         "held": self.held(budget_id, now=now),
                         "floor": floor, "current_total": b["total"]})
        new_rev = cur + 1
        entry = {"revision": new_rev, "total": new_total,
                 "batch_cap": new_batch, "valid_from": new_from,
                 "valid_until": new_until, "lease_seconds": new_lease,
                 "by": actor, "reason": reason, "at": now}
        b.update(total=new_total, batch_cap=new_batch, valid_from=new_from,
                 valid_until=new_until, lease_seconds=new_lease,
                 revision=new_rev)
        b["revisions"].append(entry)
        self.audit.append("budget_revised",
                          {"budget_id": budget_id, "purpose": b["purpose"],
                           "key_version_id": b["key_version_id"],
                           "subject": b["subject"], "total": new_total,
                           "batch_cap": new_batch,
                           "valid_from": new_from,
                           "valid_until": new_until,
                           "lease_seconds": new_lease,
                           "revision": new_rev, "status": b["status"],
                           "by": actor, "reason": reason, "at": now,
                           "base_revision": cur,
                           "previous_total": self._previous_total(b, cur)})
        self._save()
        return self.public_budget(budget_id)

    def pause(self, budget_id: str, actor: str, reason: str = "") -> dict:
        b = self._budget(budget_id)
        if b["status"] != PAUSED:
            b["status"] = PAUSED
            b["paused_at"] = self._now()
            self.audit.append("budget_paused",
                              {"budget_id": budget_id, "purpose": b["purpose"],
                               "actor": actor, "reason": reason,
                               "revision": b["revision"],
                               "at": b["paused_at"]})
            self._save()
        return self.public_budget(budget_id)

    def resume(self, budget_id: str, actor: str, reason: str = "") -> dict:
        b = self._budget(budget_id)
        if b["status"] == PAUSED:
            b["status"] = ACTIVE_B
            b["resumed_at"] = self._now()
            self.audit.append("budget_resumed",
                              {"budget_id": budget_id, "purpose": b["purpose"],
                               "actor": actor, "reason": reason,
                               "revision": b["revision"],
                               "at": b["resumed_at"]})
            self._save()
        return self.public_budget(budget_id)

    # ======================================================================
    # reservation hold / settle / release
    # ======================================================================
    def hold(self, *, request_id: str, purpose: str, subject: str,
             quantity: int = 1) -> dict:
        """Reserve quantity for a brand-new request.

        Replays of a request id already known to *this* budget return the
        stored request view (idempotent success) without holding anything.
        A live (unexpired, unsettled) retry by a competing worker that has
        not produced a signature is refused as in-flight.
        """
        self._require_int(quantity, "quantity", min_value=1)
        existing = self.s["sign_requests"].get(request_id)
        if existing is not None:
            return self._replay_view(existing)
        b = self._budget_for_purpose(purpose)
        if b is None:
            raise NotFound(f"no budget for purpose {purpose}")
        self._guard_new_reservation(b, subject, quantity)
        now = self._now()
        if self.available(b["budget_id"], now=now) < quantity:
            raise BudgetError(
                f"budget {b['budget_id']} has "
                f"{self.available(b['budget_id'], now=now)} available; "
                f"{quantity} requested",
                reason=E_EXHAUSTED,
                details={"budget_id": b["budget_id"],
                         "available": self.available(b["budget_id"], now=now),
                         "requested": quantity})
        expires_at = now + b["lease_seconds"]
        rid = "rsv_" + crypto.b64e(crypto.digest(
            {"request_id": request_id, "budget_id": b["budget_id"],
             "at": now, "r": crypto.b64e(os.urandom(8))}))[:22] \
            .replace("+", "-").replace("/", "_")
        rec = {
            "reservation_id": rid,
            "request_id": request_id,
            "budget_id": b["budget_id"],
            "purpose": purpose,
            "subject": subject,
            "key_version_id": b["key_version_id"],
            "quantity": quantity,
            "state": HELD,
            "held_at": now,
            "lease_expires_at": expires_at,
            "settled_at": None,
            "released_at": None,
            "release_reason": None,
            "released_by": None,
            "signature": None,
        }
        rec["credential"] = self._credential(rec)
        self.s["sign_requests"][request_id] = rec
        self.audit.append("budget_reservation_held",
                          self._reservation_payload(rec,
                                                    before_available=self.available(b["budget_id"], now=now) + quantity))
        self._save()
        return self.request_view(request_id)

    def record_signature(self, *, request_id: str, credential: str,
                         key_version_id: str, message_digest: str,
                         signature: str) -> dict:
        """Attach the signature audit to a held reservation (step 2).

        Idempotent: re-recording after a crash between step 2 and step 3
        returns the stored signature record unchanged.
        """
        rec = self._request(request_id)
        self._check_credential(rec, credential)
        if rec["signature"] is not None:
            return self.request_view(request_id)
        if rec["state"] != HELD:
            raise BudgetError(
                f"request {request_id} is {rec['state']}, not held",
                reason=E_RESERVATION_NOT_HELD)
        if rec["key_version_id"] != key_version_id:
            raise PolicyViolation(
                f"reservation bound to {rec['key_version_id']}; cannot sign "
                f"with {key_version_id}")
        now = self._now()
        sig_rec = {"key_version_id": key_version_id,
                   "message_digest": message_digest,
                   "signature": signature, "issued_at": now,
                   "audit_digest": crypto.digest_hex({
                       "request_id": request_id,
                       "reservation_id": rec["reservation_id"],
                       "key_version_id": key_version_id,
                       "message_digest": message_digest,
                       "signature": signature, "issued_at": now})}
        rec["signature"] = sig_rec
        self.audit.append("budget_signature_issued",
                          {"request_id": request_id,
                           "reservation_id": rec["reservation_id"],
                           "budget_id": rec["budget_id"],
                           "subject": rec["subject"],
                           "purpose": rec["purpose"],
                           "key_version_id": key_version_id,
                           "message_digest": message_digest,
                           "signature": signature,
                           "issued_at": now,
                           "audit_digest": sig_rec["audit_digest"]})
        self._save()
        return self.request_view(request_id)

    def settle(self, *, request_id: str, credential: str) -> dict:
        """Convert the hold into consumption (step 3). Idempotent: an already
        settled request returns its settlement record."""
        rec = self._request(request_id)
        self._check_credential(rec, credential)
        if rec["state"] == CONSUMED:
            return self.request_view(request_id)
        if rec["state"] != HELD:
            raise BudgetError(
                f"request {request_id} is {rec['state']}",
                reason=E_RESERVATION_NOT_HELD)
        if rec["signature"] is None:
            # The protocol order is hold -> sign -> settle. Settle of a hold
            # with no signature audit is exactly the "charge without signing"
            # shape the verifier flags; refuse it on the live path.
            raise BudgetError(
                f"cannot settle {request_id}: no signature audit",
                reason="SETTLE_WITHOUT_SIGNATURE")
        now = self._now()
        rec["state"] = CONSUMED
        rec["settled_at"] = now
        b = self._budget(rec["budget_id"])
        self.audit.append("budget_reservation_settled",
                          {"request_id": request_id,
                           "reservation_id": rec["reservation_id"],
                           "budget_id": rec["budget_id"],
                           "subject": rec["subject"],
                           "purpose": rec["purpose"],
                           "quantity": rec["quantity"],
                           "key_version_id": rec["key_version_id"],
                           "settled_at": now,
                           "signature_audit_digest":
                               rec["signature"]["audit_digest"],
                           "consumed_total_after":
                               self.consumed(rec["budget_id"])})
        self._save()
        return self.request_view(request_id)

    def release_expired(self, *, request_id: str,
                        actor: str = "lease-reaper",
                        force: bool = False,
                        reason: str = "") -> dict:
        """Return an expired, never-signed hold to the pool.

        A hold whose signature audit exists can never be released: a takeover
        settles it instead. `force` is the operator's manual path for a
        long-hung reservation; it still may not release a signed hold, and
        must carry a non-empty reason that lands in the audit together with
        the held quantities before and after.
        """
        rec = self._request(request_id)
        if rec["state"] != HELD:
            raise BudgetError(
                f"request {request_id} is {rec['state']}",
                reason=E_RESERVATION_NOT_HELD)
        if rec["signature"] is not None:
            raise BudgetError(
                f"request {request_id} already produced signature "
                f"{rec['signature']['audit_digest']}; it must be settled, "
                f"never released",
                reason=E_SIGNATURE_PRESENT,
                details={"signature_audit_digest":
                         rec["signature"]["audit_digest"]})
        now = self._now()
        early = now < rec["lease_expires_at"]
        if not force and early:
            raise BudgetError(
                f"lease for {request_id} expires at "
                f"{rec['lease_expires_at']} (now {now})",
                reason=E_LEASE_NOT_EXPIRED,
                details={"lease_expires_at": rec["lease_expires_at"],
                         "now": now})
        if force and not reason.strip():
            raise PolicyViolation(
                "manual handling of a hung reservation requires a reason")
        if force and early:
            # manual handling before lease expiry is allowed with reason,
            # but the audit must say so explicitly.
            release_reason = "manual_early_release"
        elif force:
            release_reason = "manual_expired_release"
        else:
            release_reason = "lease_expired"
        before = self.held(rec["budget_id"], now=now)
        rec["state"] = RELEASED
        rec["released_at"] = now
        rec["release_reason"] = release_reason
        rec["released_by"] = actor
        payload = {"request_id": request_id,
                   "reservation_id": rec["reservation_id"],
                   "budget_id": rec["budget_id"],
                   "subject": rec["subject"],
                   "purpose": rec["purpose"],
                   "quantity": rec["quantity"],
                   "released_at": now,
                   "released_by": actor,
                   "release_reason": release_reason,
                   "manual_reason": reason if force else "",
                   "lease_expires_at": rec["lease_expires_at"],
                   "held_total_before": before,
                   "held_total_after": before - rec["quantity"]}
        self.audit.append("budget_reservation_released", payload)
        self._save()
        return self.request_view(request_id)

    def manual_release(self, *, request_id: str, operator: str,
                       reason: str) -> dict:
        """Operator handling of a long-hung reservation. Refuses any hold
        that already has a signature audit (those must be settled)."""
        return self.release_expired(request_id=request_id, actor=operator,
                                    force=True, reason=reason)

    # ======================================================================
    # crash takeover / reaper
    # ======================================================================
    def take_over(self, *, request_id: str, actor: str = "takeover",
                  now: float | None = None) -> dict:
        """Decide from durable evidence what happened to a dead worker's hold.

        Signature audit present  -> settle (consumed), quota never reusable.
        No signature, lease over  -> release (safe to return).
        No signature, lease live  -> leave it; caller may retry later.
        """
        rec = self._request(request_id)
        if rec["state"] == CONSUMED:
            return {"request_id": request_id, "action": "already_consumed",
                    "view": self.request_view(request_id)}
        if rec["state"] == RELEASED:
            return {"request_id": request_id, "action": "already_released",
                    "view": self.request_view(request_id)}
        cur = now if now is not None else self._now()
        if rec["signature"] is not None:
            view = self.settle(request_id=request_id,
                               credential=rec["credential"])
            return {"request_id": request_id, "action": "settled_signature",
                    "view": view}
        if cur >= rec["lease_expires_at"]:
            view = self.release_expired(request_id=request_id, actor=actor)
            return {"request_id": request_id, "action": "released_expired",
                    "view": view}
        return {"request_id": request_id, "action": "lease_still_active",
                "lease_expires_at": rec["lease_expires_at"], "now": cur,
                "view": self.request_view(request_id)}

    def sweep_expired(self, actor: str = "lease-reaper") -> list[dict]:
        """Process every held reservation whose lease has elapsed. Signed
        holds settle; unsigned holds release. Returns takeover verdicts."""
        now = self._now()
        pending = [r for r in self.s["sign_requests"].values()
                   if r["state"] == HELD and r["lease_expires_at"] <= now]
        out = []
        for rec in pending:
            out.append(self.take_over(request_id=rec["request_id"],
                                      actor=actor, now=now))
        return out

    # ======================================================================
    # counters / views
    # ======================================================================
    def consumed(self, budget_id: str) -> int:
        return sum(r["quantity"]
                   for r in self.s["sign_requests"].values()
                   if r["budget_id"] == budget_id and r["state"] == CONSUMED)

    def released(self, budget_id: str) -> int:
        return sum(r["quantity"]
                   for r in self.s["sign_requests"].values()
                   if r["budget_id"] == budget_id and r["state"] == RELEASED)

    def held(self, budget_id: str, now: float | None = None) -> int:
        cur = now if now is not None else self._now()
        return sum(r["quantity"]
                   for r in self.s["sign_requests"].values()
                   if r["budget_id"] == budget_id and r["state"] == HELD)

    def available(self, budget_id: str, now: float | None = None) -> int:
        b = self._budget(budget_id)
        return b["total"] - self.consumed(budget_id) - self.held(budget_id, now)

    def counts(self, budget_id: str) -> dict:
        now = self._now()
        b = self._budget(budget_id)
        held = self.held(budget_id, now)
        consumed = self.consumed(budget_id)
        return {"budget_id": budget_id, "purpose": b["purpose"],
                "subject": b["subject"],
                "key_version_id": b["key_version_id"],
                "revision": b["revision"], "status": b["status"],
                "total": b["total"], "consumed": consumed, "held": held,
                "released": self.released(budget_id),
                "available": b["total"] - consumed - held,
                "lease_seconds": b["lease_seconds"],
                "batch_cap": b["batch_cap"],
                "valid_from": b["valid_from"],
                "valid_until": b["valid_until"],
                "window_open": b["valid_from"] <= now < b["valid_until"],
                "now": now}

    def public_budget(self, budget_id: str) -> dict:
        b = self._budget(budget_id)
        out = {k: b[k] for k in (
            "budget_id", "purpose", "key_version_id", "subject", "total",
            "batch_cap", "valid_from", "valid_until", "lease_seconds",
            "revision", "status", "created_by", "created_at", "reason",
            "paused_at", "resumed_at")}
        out["revisions"] = [dict(r) for r in b["revisions"]]
        out.update({k: self.counts(budget_id)[k]
                    for k in ("consumed", "held", "released", "available",
                              "window_open")})
        return out

    def list_budgets(self) -> list[dict]:
        return [self.public_budget(bid)
                for bid in sorted(self.s["sign_budgets"].keys())]

    def request_view(self, request_id: str) -> dict:
        rec = self._request(request_id)
        out = {k: v for k, v in rec.items() if k != "credential"}
        out["has_credential"] = True
        return out

    def list_requests(self, budget_id: str | None = None) -> list[dict]:
        out = [self.request_view(rid)
               for rid in sorted(self.s["sign_requests"].keys())]
        if budget_id:
            out = [r for r in out if r["budget_id"] == budget_id]
        return out

    def budget_for_purpose(self, purpose: str) -> dict | None:
        b = self._budget_for_purpose(purpose)
        return self.public_budget(b["budget_id"]) if b else None

    # ======================================================================
    # internals
    # ======================================================================
    def _now(self) -> float:
        return float(self.clock())

    @staticmethod
    def _require_int(value, field: str, *, min_value: int):
        if isinstance(value, bool) or not isinstance(value, int):
            raise PolicyViolation(f"{field} must be an integer")
        if value < min_value:
            raise PolicyViolation(
                f"{field} must be >= {min_value}, got {value}")

    @staticmethod
    def _check_window(valid_from: float, valid_until: float):
        if not valid_until > valid_from:
            raise PolicyViolation(
                "valid_until must be strictly after valid_from")

    def _budget(self, budget_id: str) -> dict:
        b = self.s["sign_budgets"].get(budget_id)
        if b is None:
            raise NotFound(f"unknown budget {budget_id}")
        return b

    def _budget_for_purpose(self, purpose: str) -> dict | None:
        for b in self.s["sign_budgets"].values():
            if b["purpose"] == purpose:
                return b
        return None

    def _request(self, request_id: str) -> dict:
        rec = self.s["sign_requests"].get(request_id)
        if rec is None:
            raise NotFound(f"unknown signing request {request_id}")
        return rec

    def _guard_new_reservation(self, b: dict, subject: str, quantity: int):
        now = self._now()
        if b["status"] == PAUSED:
            raise BudgetError(f"budget {b['budget_id']} is paused",
                              reason=E_BUDGET_PAUSED)
        # The budget may only ever be drawn by its named subject; a different
        # caller is a cross-subject diversion attempt and gets 403.
        if subject != b["subject"]:
            raise Forbidden(
                f"budget {b['budget_id']} belongs to subject "
                f"{b['subject']}, not {subject}")
        subj = self.s["sign_subjects"].get(b["subject"])
        if subj is None or subj.get("revoked"):
            raise BudgetError(
                f"subject {b['subject']} is revoked or missing",
                reason=E_SUBJECT_REVOKED)
        kv = self.keys_by_id.get(b["key_version_id"])
        if kv is not None and kv.get("status") in ("RETIRING", "DESTROYED",
                                                   "ABORTED"):
            raise BudgetError(
                f"key version {b['key_version_id']} is {kv.get('status')}",
                reason=E_KEY_RETIRED)
        if now < b["valid_from"]:
            raise BudgetError(
                f"budget becomes valid at {b['valid_from']} (now {now})",
                reason=E_NOT_YET_VALID)
        if now >= b["valid_until"]:
            raise BudgetError(
                f"budget window ended at {b['valid_until']} (now {now})",
                reason=E_EXPIRED)
        if quantity > b["batch_cap"]:
            raise BudgetError(
                f"quantity {quantity} exceeds per-request batch cap "
                f"{b['batch_cap']}",
                reason=E_BATCH_CAP,
                details={"batch_cap": b["batch_cap"],
                         "requested": quantity})

    def _replay_view(self, rec: dict) -> dict:
        now = self._now()
        view = self.request_view(rec["request_id"])
        view["replay"] = True
        if rec["state"] == HELD:
            if rec["signature"] is not None:
                # crashed after step 2: settle from the replay path so the
                # caller gets the completed signature + settlement record
                settled = self.settle(request_id=rec["request_id"],
                                      credential=rec["credential"])
                settled["replay"] = True
                return settled
            if now < rec["lease_expires_at"]:
                raise BudgetError(
                    f"request {rec['request_id']} is held by another worker "
                    f"until {rec['lease_expires_at']}",
                    reason=E_REQUEST_IN_FLIGHT,
                    details={"lease_expires_at": rec["lease_expires_at"],
                             "request": view})
        return view

    def _credential(self, rec: dict) -> str:
        """HMAC credential binding the hold to its reservation/request ids;
        the audit-log service seed is the shared secret (live manager only)."""
        body = crypto.dumps({
            "rid": rec["reservation_id"], "req": rec["request_id"],
            "bg": rec["budget_id"], "q": rec["quantity"],
            "exp": rec["lease_expires_at"]})
        mac = crypto.hkdf(
            (self.audit.signer_seed or b"budget").hex().encode(), 32,
            info=("budget-cred|" + body).encode())
        return crypto.b64e(mac)

    def _check_credential(self, rec: dict, credential: str):
        expected = self._credential(rec)
        import hmac as _hmac
        if not credential or not _hmac.compare_digest(expected, credential):
            raise Forbidden("reservation credential mismatch")

    @staticmethod
    def _order_payload(b: dict) -> dict:
        return {"budget_id": b["budget_id"], "purpose": b["purpose"],
                "key_version_id": b["key_version_id"],
                "subject": b["subject"], "total": b["total"],
                "batch_cap": b["batch_cap"],
                "valid_from": b["valid_from"],
                "valid_until": b["valid_until"],
                "lease_seconds": b["lease_seconds"],
                "revision": b["revision"], "status": b["status"],
                "by": b["created_by"], "reason": b.get("reason", ""),
                "at": b["created_at"]}

    @staticmethod
    def _reservation_payload(rec: dict, before_available: int | None = None):
        return {"request_id": rec["request_id"],
                "reservation_id": rec["reservation_id"],
                "budget_id": rec["budget_id"],
                "subject": rec["subject"], "purpose": rec["purpose"],
                "key_version_id": rec["key_version_id"],
                "quantity": rec["quantity"], "state": HELD,
                "held_at": rec["held_at"],
                "lease_expires_at": rec["lease_expires_at"],
                "credential": rec["credential"]}

    @staticmethod
    def _previous_total(b: dict, cur_rev: int):
        for r in b["revisions"]:
            if r["revision"] == cur_rev:
                return r["total"]
        return None
