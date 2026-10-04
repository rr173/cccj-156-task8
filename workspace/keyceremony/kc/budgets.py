"""Verifiable usage budgets for the signing entry point.

The security lead issues *budget sheets* scoped by signing purpose and key
version, naming the calling subject, the total number of signatures
permitted, the per-batch (per-request) cap, and a validity time window.
Signing then runs as an explicit two-phase protocol:

    reserve (unique request_id, short lease)
        -> sign (signature audit recorded against the reservation)
        -> settle (reservation becomes consumption; unused units return)

Identical request_ids are idempotent: they replay the first reservation,
its signature audit and its settlement record instead of consuming twice.

Invariant enforced under the store lock (cross-thread + cross-process):

        consumed + valid_held <= total     must never be violated

"valid_held" covers live reservations and *expired reservations that
already carry a signature*: produced signatures are spend, never
releasable. Expired reservations without a signature are safely returned.

Every quantity change appends a hash-chained audit entry; budget sheets
carry an incrementing revision number signed by a registered security
officer. The independent re-checker is `kc.budget_verify`.

Purposes without a budget sheet keep signing exactly as before.
"""

from __future__ import annotations

import hashlib
import os
import time

from . import crypto, ed25519
from .errors import (
    ConflictState, KeyVersionRetired, NotFound, PolicyViolation,
    BudgetCredentialInvalid, BudgetExhausted, BudgetNotFound, BudgetPaused,
    BudgetRevisionConflict, BudgetWindowClosed,
    ReservationExpired, ReservationHasSignature, ReservationState,
    ReplayError, SubjectRevoked,
)

# ---- reservation lifecycle ------------------------------------------------
R_HELD = "HELD"            # quota reserved, lease live, not yet settled
R_CONSUMED = "CONSUMED"    # settled as consumption (settlement record)
R_RELEASED = "RELEASED"    # unused units returned (lease expiry/manual)
R_SIGNED = "SIGNED"        # live lease but signature(s) already produced

ACTIVE_RES_STATES = (R_HELD, R_SIGNED)
SETTLED_RES_STATES = (R_CONSUMED, R_RELEASED)

# ---- budget sheet lifecycle -----------------------------------------------
B_ACTIVE = "ACTIVE"
B_PAUSED = "PAUSED"

DEFAULT_LEASE_SECONDS = 30

# signatures made without a governing budget (purposes without a sheet) are
# explicitly marked exempt, so an offline auditor can never confuse them
# with governed-but-unsettled signing.
GOV_GOVERNED = "governed"
GOV_EXEMPT = "exempt"


def _now(clock) -> float:
    return float(clock())


def new_officer_keypair() -> tuple[bytes, bytes]:
    """A security-lead officer identity (seed32 kept off the service; the
    public key is registered and budget/credentials are verified against it
    by the offline archive checker)."""
    seed = os.urandom(32)
    return seed, ed25519.public_from_secret(seed)


def _bid() -> str:
    return "bdg_" + os.urandom(10).hex()


def _rid() -> str:
    return "rsv_" + os.urandom(10).hex()


def officer_body(kind: str, fields: dict) -> dict:
    """Canonical body an officer signs over. The service stores exactly
    this body plus `officer_sig`; anyone can recompute the signature."""
    return {"kind": kind, "fields": fields}


def sign_officer_body(seed: bytes, body: dict) -> str:
    return crypto.b64e(ed25519.sign(seed, crypto.dumps(body).encode()))


def verify_officer_body(pub: bytes, body: dict, sig_b64: str) -> bool:
    try:
        return ed25519.verify(pub, crypto.dumps(body).encode(),
                              crypto.b64d(sig_b64))
    except Exception:
        return False


class BudgetManager:
    """All mutating methods must run within `with store.locked():`.

    `keydir` is the live KeyDirectory, used to refuse reservations against
    retired/destroyed versions while historical signatures keep verifying.
    """

    def __init__(self, state: dict, audit, service_seed: bytes, keydir=None,
                 clock=time.time):
        self.s = state
        self.audit = audit
        self.seed = service_seed
        self.keydir = keydir
        self.clock = clock

    # ======================================================================
    # officers / subjects
    # ======================================================================
    def register_officer(self, officer_id: str, pub: bytes, label: str = "",
                         *, _body: dict | None = None,
                         _sig: str | None = None) -> dict:
        if officer_id in self.s["budget_officers"]:
            raise ConflictState(f"budget officer {officer_id} already exists")
        if _body is not None:
            self._check_officer_registration(_body, _sig, officer_id,
                                             crypto.b64e(pub), label)
        rec = {"officer_id": officer_id, "pub": crypto.b64e(pub),
               "label": label, "registered_at": _now(self.clock),
               "registration": {"body": _body, "officer_sig": _sig}}
        self.s["budget_officers"][officer_id] = rec
        self.audit.append("budget_officer_registered",
                          {"officer_id": officer_id, "pub": rec["pub"],
                           "label": label, "self_attested": _sig is not None})
        return rec

    @staticmethod
    def _check_officer_registration(body, sig, officer_id, pub_b64, label):
        if sig is None:
            raise PolicyViolation("officer registration requires a signature")
        f = body.get("fields", {}) if body.get("kind") == \
                "budget-officer-register-v1" else None
        if f is None or f.get("officer_id") != officer_id \
                or f.get("pub") != pub_b64 or f.get("label") != label:
            raise PolicyViolation("officer registration body is not consistent")
        if not verify_officer_body(crypto.b64d(pub_b64), body, sig):
            raise BudgetCredentialInvalid("officer self-signature invalid")

    def _officer_pub(self, officer_id: str) -> bytes:
        rec = self.s["budget_officers"].get(officer_id)
        if rec is None:
            raise PolicyViolation(f"unknown budget officer {officer_id}")
        return crypto.b64d(rec["pub"])

    def _require_officer_sig(self, kind: str, fields: dict,
                             officer_id: str, sig: str | None):
        """Verify the officer signature over the canonical sheet fields."""
        if sig is None:
            raise PolicyViolation("budget sheet must be signed by an officer")
        pub = self._officer_pub(officer_id)
        if not verify_officer_body(pub, officer_body(kind, fields), sig):
            raise BudgetCredentialInvalid(
                f"officer signature over {kind} does not verify")

    def register_subject(self, subject_id: str, label: str = "") -> dict:
        if subject_id in self.s["budget_subjects"]:
            raise ConflictState(f"subject {subject_id} already registered")
        rec = {"subject_id": subject_id, "label": label,
               "revoked": False, "registered_at": _now(self.clock),
               "revoked_at": None}
        self.s["budget_subjects"][subject_id] = rec
        self.audit.append("budget_subject_registered",
                          {"subject_id": subject_id, "label": label})
        return rec

    def revoke_subject(self, subject_id: str, reason: str = "",
                       actor: str = "") -> dict:
        rec = self.s["budget_subjects"].get(subject_id)
        if rec is None:
            raise NotFound(f"unknown subject {subject_id}")
        rec["revoked"] = True
        rec["revoked_at"] = _now(self.clock)
        self.audit.append("budget_subject_revoked",
                          {"subject_id": subject_id, "reason": reason,
                           "actor": actor})
        return rec

    # ======================================================================
    # budget sheets: create / revise / pause / resume
    # ======================================================================
    def _find_budget(self, budget_id: str) -> dict:
        b = self.s["budgets"].get(budget_id)
        if b is None:
            raise BudgetNotFound(f"unknown budget {budget_id}")
        return b

    def budget_for(self, purpose: str, key_version_id: str,
                   subject: str) -> dict | None:
        """The single ACTIVE/PAUSED sheet governing (purpose, version).

        A paused sheet still "exists" (so signing stays governed and is
        refused); only a missing sheet makes the purpose fall back to the
        legacy unsigned-by-budget path."""
        for b in self.s["budgets"].values():
            if b["purpose"] == purpose \
                    and b["key_version_id"] == key_version_id \
                    and b["subject"] == subject \
                    and b.get("superseded_by") is None:
                return b
        return None

    def governing_budget(self, purpose: str, key_version_id: str) -> dict | None:
        """Any non-superseded sheet for purpose+version regardless of
        subject; used to tell governed purposes from exempt ones."""
        for b in self.s["budgets"].values():
            if b["purpose"] == purpose \
                    and b["key_version_id"] == key_version_id \
                    and b.get("superseded_by") is None:
                return b
        return None

    @staticmethod
    def _validate_quantities(total: int, per_batch_cap: int, lease_seconds):
        if not isinstance(total, int) or isinstance(total, bool) or total < 0:
            raise PolicyViolation("total must be a non-negative integer")
        if not isinstance(per_batch_cap, int) or isinstance(per_batch_cap, bool) \
                or per_batch_cap <= 0:
            raise PolicyViolation("per_batch_cap must be a positive integer")
        if per_batch_cap > total and total > 0:
            raise PolicyViolation("per_batch_cap cannot exceed total")
        if lease_seconds is not None and (
                not isinstance(lease_seconds, int)
                or isinstance(lease_seconds, bool) or lease_seconds <= 0):
            raise PolicyViolation("lease_seconds must be a positive integer")

    def create_budget(self, *, purpose: str, key_version_id: str,
                      subject: str, total: int, per_batch_cap: int,
                      effective_at: float, deadline: float,
                      officer_id: str, officer_sig: str,
                      lease_seconds: int = DEFAULT_LEASE_SECONDS,
                      label: str = "") -> dict:
        total, per_batch_cap = int(total), int(per_batch_cap)
        effective_at, deadline = float(effective_at), float(deadline)
        lease_seconds = int(lease_seconds or DEFAULT_LEASE_SECONDS)
        self._validate_quantities(total, per_batch_cap, lease_seconds)
        if deadline <= effective_at:
            raise PolicyViolation("deadline must be after effective_at")
        if self.keydir is not None:
            kv = self.keydir.get(key_version_id)  # NotFound if unknown
            if kv["purpose"] != purpose:
                raise PolicyViolation(
                    f"key version {key_version_id} belongs to purpose "
                    f"{kv['purpose']}, not {purpose}")
        if self.governing_budget(purpose, key_version_id) is not None:
            raise ConflictState(
                f"a budget already governs {purpose}/{key_version_id}; "
                f"revise it instead of creating another")
        # officer signs exactly the issued sheet content
        fields = {"purpose": purpose, "key_version_id": key_version_id,
                  "subject": subject, "total": total,
                  "per_batch_cap": per_batch_cap,
                  "effective_at": effective_at, "deadline": deadline,
                  "lease_seconds": lease_seconds, "label": label}
        self._require_officer_sig("budget-issue-v1", fields,
                                  officer_id, officer_sig)
        now = _now(self.clock)
        b = {
            "id": _bid(),
            "purpose": purpose, "key_version_id": key_version_id,
            "subject": subject,
            "revision": 1,
            "status": B_ACTIVE,
            "total": total,
            "per_batch_cap": per_batch_cap,
            "effective_at": effective_at, "deadline": deadline,
            "lease_seconds": lease_seconds,
            "label": label,
            "issued_by": officer_id,
            "created_at": now, "updated_at": now,
            "superseded_by": None,
            "revision_chain": [{
                "revision": 1, "total": total,
                "per_batch_cap": per_batch_cap,
                "effective_at": effective_at, "deadline": deadline,
                "lease_seconds": lease_seconds,
                "status": B_ACTIVE,
                "officer_id": officer_id, "officer_sig": officer_sig,
                "issued_at": now, "reason": "issue"}],
        }
        self.s["budgets"][b["id"]] = b
        self.audit.append("budget_issued",
                          {"budget_id": b["id"], "purpose": purpose,
                           "key_version_id": key_version_id,
                           "subject": subject, "total": total,
                           "per_batch_cap": per_batch_cap,
                           "effective_at": effective_at,
                           "deadline": deadline,
                           "lease_seconds": lease_seconds,
                           "label": label,
                           "revision": 1, "officer_id": officer_id,
                           "officer_sig": officer_sig})
        return b

    def revise_budget(self, budget_id: str, *, base_revision: int,
                      total: int, per_batch_cap: int,
                      effective_at: float | None = None,
                      deadline: float | None = None,
                      lease_seconds: int | None = None,
                      officer_id: str, officer_sig: str,
                      reason: str = "") -> dict:
        b = self._find_budget(budget_id)
        base_revision, total, per_batch_cap = \
            int(base_revision), int(total), int(per_batch_cap)
        if base_revision != b["revision"]:
            # two admins editing concurrently: stale revision never overwrites
            snap = self.budget_view(b)
            raise BudgetRevisionConflict(
                f"budget {budget_id} revised since your revision "
                f"{base_revision} (current {b['revision']})",
                base_revision=base_revision,
                current_revision=b["revision"],
                base_snapshot={"revision": base_revision, "total": None},
                current_snapshot={
                    "revision": b["revision"],
                    "total": b["total"],
                    "per_batch_cap": b["per_batch_cap"],
                    "available": snap["available"],
                    "reserved": snap["reserved"],
                    "consumed": snap["consumed"],
                    "total_delta": total - b["total"],
                    "status": b["status"]})
        self._validate_quantities(total, per_batch_cap, lease_seconds)
        effective_at = float(b["effective_at"]
                             if effective_at is None else effective_at)
        deadline = float(b["deadline"] if deadline is None else deadline)
        if deadline <= effective_at:
            raise PolicyViolation("deadline must be after effective_at")
        lease_seconds = int(b["lease_seconds"]
                            if lease_seconds is None else lease_seconds)
        self._sweep_budget(b)
        view = self.budget_view(b)
        floor = view["consumed"] + view["reserved"]
        if total < floor:
            raise PolicyViolation(
                f"reduced total {total} cannot be below consumed "
                f"{view['consumed']} + valid reservations {view['reserved']} "
                f"= {floor}")
        new_rev = b["revision"] + 1
        fields = {"budget_id": budget_id, "base_revision": base_revision,
                  "revision": new_rev, "total": total,
                  "per_batch_cap": per_batch_cap,
                  "effective_at": effective_at, "deadline": deadline,
                  "lease_seconds": lease_seconds, "reason": reason}
        self._require_officer_sig("budget-revise-v1", fields,
                                  officer_id, officer_sig)
        old_total = b["total"]
        old_lease = b["lease_seconds"]
        b.update({"total": total, "per_batch_cap": per_batch_cap,
                  "effective_at": effective_at, "deadline": deadline,
                  "lease_seconds": lease_seconds, "revision": new_rev,
                  "updated_at": _now(self.clock)})
        b["revision_chain"].append({
            "revision": new_rev, "total": total,
            "per_batch_cap": per_batch_cap,
            "effective_at": effective_at, "deadline": deadline,
            "lease_seconds": lease_seconds, "status": b["status"],
            "officer_id": officer_id, "officer_sig": officer_sig,
            "issued_at": b["updated_at"], "reason": reason,
            "old_total": old_total})
        self.audit.append("budget_revised",
                          {"budget_id": budget_id, "revision": new_rev,
                           "base_revision": base_revision,
                           "old_total": old_total, "total": total,
                           "per_batch_cap": per_batch_cap,
                           "old_lease": old_lease,
                           "lease_seconds": lease_seconds,
                           "effective_at": effective_at,
                           "deadline": deadline,
                           "consumed_at_revise": view["consumed"],
                           "reserved_at_revise": view["reserved"],
                           "officer_id": officer_id,
                           "officer_sig": officer_sig, "reason": reason})
        return b

    def _set_status(self, b: dict, status: str, actor: str,
                    officer_id: str | None, officer_sig: str | None,
                    reason: str):
        fields = {"budget_id": b["id"], "base_revision": b["revision"],
                  "revision": b["revision"] + 1, "status": status,
                  "reason": reason}
        if officer_id is not None and officer_sig is not None:
            self._require_officer_sig("budget-status-v1", fields,
                                      officer_id, officer_sig)
            signed = True
        else:
            # console/HTTP ops are an officer action; the caller may instead
            # supply the signed body. An unsigned internal transition is
            # allowed for the library but marked actor_only.
            signed = False
        old = b["status"]
        b["status"] = status
        b["revision"] += 1
        b["updated_at"] = _now(self.clock)
        b["revision_chain"].append({
            "revision": b["revision"], "total": b["total"],
            "per_batch_cap": b["per_batch_cap"],
            "effective_at": b["effective_at"], "deadline": b["deadline"],
            "lease_seconds": b["lease_seconds"], "status": status,
            "officer_id": officer_id, "officer_sig": officer_sig,
            "issued_at": b["updated_at"], "reason": reason,
            "status_change_from": old})
        self.audit.append("budget_status_changed",
                          {"budget_id": b["id"], "revision": b["revision"],
                           "old_status": old, "new_status": status,
                           "actor": actor, "officer_id": officer_id,
                           "officer_signed": signed, "reason": reason})
        return b

    def pause_budget(self, budget_id: str, actor: str, reason: str = "",
                     officer_id: str | None = None,
                     officer_sig: str | None = None) -> dict:
        b = self._find_budget(budget_id)
        if b["status"] == B_PAUSED:
            return b
        return self._set_status(b, B_PAUSED, actor, officer_id,
                                officer_sig, reason)

    def resume_budget(self, budget_id: str, actor: str, reason: str = "",
                      officer_id: str | None = None,
                      officer_sig: str | None = None) -> dict:
        b = self._find_budget(budget_id)
        if b["status"] == B_ACTIVE:
            return b
        return self._set_status(b, B_ACTIVE, actor, officer_id,
                                officer_sig, reason)

    # ======================================================================
    # lease accounting
    # ======================================================================
    def _iter_reservations(self, budget_id: str):
        return (r for r in self.s["budget_reservations"].values()
                if r["budget_id"] == budget_id)

    def _sweep_budget(self, b: dict) -> list[dict]:
        """Expire overdue reservations.

        A reservation carrying signature audit is *never* released: its held
        units are converted to consumption (the signatures really happened)
        and a settlement record is written. Empty expired holds return their
        units and become RELEASED.
        """
        now = _now(self.clock)
        changed = []
        for r in self._iter_reservations(b["id"]):
            if r["status"] in ACTIVE_RES_STATES and r["lease_expires_at"] <= now:
                if r["signatures"]:
                    self._force_consume(b, r, "lease-expired-with-signatures")
                else:
                    self._mark_released(b, r, "lease-expired", actor=None,
                                        reason="short lease lapsed; no "
                                               "signature was produced")
                changed.append(r)
        return changed

    def _mark_released(self, b: dict, r: dict, kind: str, *, actor,
                       reason: str, manual: bool = False):
        released = r["amount"] - r["consumed_amount"]
        r["status"] = R_RELEASED
        r["settled_at"] = _now(self.clock)
        r["settlement"] = {"kind": kind, "released": released,
                           "consumed": r["consumed_amount"],
                           "actor": actor, "reason": reason,
                           "manual": manual}
        self.audit.append("budget_reservation_released",
                          {"budget_id": b["id"], "reservation_id": r["id"],
                           "request_id": r["request_id"],
                           "released_amount": released,
                           "consumed_amount": r["consumed_amount"],
                           "kind": kind, "actor": actor,
                           "manual": manual, "reason": reason})

    def _force_consume(self, b: dict, r: dict, kind: str):
        """Lease expired but signatures exist: those units are spend and the
        reservation is settled to consumption (takeover rule)."""
        signed = len(r["signatures"])
        consumed = max(r["consumed_amount"], signed)
        if consumed > r["amount"]:
            consumed = r["amount"]
        r["consumed_amount"] = consumed
        r["status"] = R_CONSUMED
        r["settled_at"] = _now(self.clock)
        r["settlement"] = {"kind": kind, "consumed": consumed,
                           "released": r["amount"] - consumed,
                           "actor": None,
                           "reason": "reservation expired after signatures "
                                     "were produced; quota is non-releasable"}
        self.audit.append("budget_reservation_consumed",
                          {"budget_id": b["id"], "reservation_id": r["id"],
                           "request_id": r["request_id"],
                           "amount": r["amount"], "consumed_amount": consumed,
                           "released_amount": r["amount"] - consumed,
                           "kind": kind, "actor": None})

    def budget_view(self, b: dict) -> dict:
        consumed = reserved = 0
        for r in self._iter_reservations(b["id"]):
            if r["status"] == R_CONSUMED:
                consumed += r["consumed_amount"]
            elif r["status"] in ACTIVE_RES_STATES:
                reserved += r["amount"] - r["consumed_amount"]
            # released reservations hold nothing
        now = _now(self.clock)
        live = sum(1 for r in self._iter_reservations(b["id"])
                   if r["status"] in ACTIVE_RES_STATES
                   and r["lease_expires_at"] > now)
        return {
            "budget_id": b["id"], "purpose": b["purpose"],
            "key_version_id": b["key_version_id"], "subject": b["subject"],
            "revision": b["revision"], "status": b["status"],
            "total": b["total"], "per_batch_cap": b["per_batch_cap"],
            "lease_seconds": b["lease_seconds"],
            "effective_at": b["effective_at"], "deadline": b["deadline"],
            "consumed": consumed, "reserved": reserved,
            "available": b["total"] - consumed - reserved,
            "active_reservations": live,
            "now": now,
        }

    def list_budgets(self) -> list[dict]:
        return [self.budget_view(b) for b in self.s["budgets"].values()]

    def get_reservation(self, request_id: str) -> dict:
        r = self.s["budget_reservations"].get(request_id)
        if r is None:
            raise NotFound(f"unknown request_id {request_id}")
        return r

    # ======================================================================
    # phase 1: reserve
    # ======================================================================
    def reserve(self, *, purpose: str, subject: str, request_id: str,
                amount: int = 1, key_version_id: str | None = None,
                actor: str = "") -> dict:
        amount = int(amount)
        if not request_id:
            raise PolicyViolation("request_id is required")
        # idempotency: same request_id replays the original record. A request
        # number reused with different purpose/subject/amount is a conflict
        # (it would otherwise return an unrelated reservation as if replayed).
        existing = self.s["budget_reservations"].get(request_id)
        if existing is not None:
            if existing["purpose"] != purpose \
                    or existing["subject"] != subject \
                    or existing["amount"] != amount:
                raise ReplayError(
                    f"request_id {request_id} already exists for "
                    f"{existing['purpose']}/{existing['subject']}/"
                    f"{existing['amount']}; a request number is bound to one "
                    f"reservation")
            return self._replay(existing)
        if amount <= 0:
            raise PolicyViolation("reservation amount must be positive")
        # signing always happens on the ACTIVE version; the budget must match
        if key_version_id is None:
            if self.keydir is None:
                raise PolicyViolation("key_version_id required without keydir")
            kv = self.keydir.active(purpose)
            if kv is None:
                raise NotFound(f"no ACTIVE key for purpose {purpose}")
            key_version_id = kv["id"]
        b = self.budget_for(purpose, key_version_id, subject)
        if b is None:
            raise BudgetNotFound(
                f"no budget for subject {subject} on {purpose}/"
                f"{key_version_id}")
        # gate set: paused / revoked / retired / time window
        self._admit_check(b, amount)
        self._sweep_budget(b)
        view = self.budget_view(b)
        if amount > b["per_batch_cap"]:
            raise PolicyViolation(
                f"requested {amount} exceeds per-batch cap "
                f"{b['per_batch_cap']}")
        if view["available"] < amount:
            raise BudgetExhausted(
                f"only {view['available']} free of total {b['total']} "
                f"(consumed {view['consumed']}, reserved {view['reserved']})")
        now = _now(self.clock)
        r = {
            "id": _rid(), "request_id": request_id, "budget_id": b["id"],
            "purpose": purpose, "key_version_id": key_version_id,
            "subject": subject, "amount": amount,
            "consumed_amount": 0,
            "status": R_HELD,
            "reserved_at": now, "actor": actor,
            "lease_expires_at": now + b["lease_seconds"],
            "lease_seconds": b["lease_seconds"],
            "signatures": [],
            "settlement": None, "settled_at": None,
        }
        cred_body = self._credential_body(r, b)
        r["credential"] = {
            "body": cred_body,
            "service_sig": crypto.b64e(
                ed25519.sign(self.seed,
                             crypto.dumps(cred_body).encode())),
        }
        self.s["budget_reservations"][request_id] = r
        self.audit.append("budget_reserved",
                          {"budget_id": b["id"], "reservation_id": r["id"],
                           "request_id": request_id, "purpose": purpose,
                           "key_version_id": key_version_id,
                           "subject": subject, "amount": amount,
                           "reserved_at": now,
                           "lease_expires_at": r["lease_expires_at"],
                           "budget_revision": b["revision"]})
        return self._replay(r, duplicate=False)

    def _admit_check(self, b: dict, amount: int):
        now = _now(self.clock)
        if b["status"] == B_PAUSED:
            raise BudgetPaused(f"budget {b['id']} is paused")
        subj = self.s["budget_subjects"].get(b["subject"])
        if subj is not None and subj.get("revoked"):
            raise SubjectRevoked(f"subject {b['subject']} is revoked")
        if self.keydir is not None:
            kv = self.keydir.get(b["key_version_id"])
            if kv["status"] != "ACTIVE":
                raise KeyVersionRetired(
                    f"key version {b['key_version_id']} is {kv['status']}")
        if now < b["effective_at"]:
            raise BudgetWindowClosed(
                f"budget becomes effective at {b['effective_at']} (now {now})")
        if now >= b["deadline"]:
            raise BudgetWindowClosed(
                f"budget window ended at {b['deadline']} (now {now})")

    def _credential_body(self, r: dict, b: dict) -> dict:
        """Verifiable reservation credential. Its signature ties the unique
        request number, budget, subject, amount and lease together and is
        re-checkable by the offline archive."""
        return {"kind": "budget-reservation-v1",
                "reservation_id": r["id"], "request_id": r["request_id"],
                "budget_id": b["id"], "purpose": r["purpose"],
                "key_version_id": r["key_version_id"],
                "subject": r["subject"], "amount": r["amount"],
                "reserved_at": r["reserved_at"],
                "lease_expires_at": r["lease_expires_at"]}

    def verify_credential(self, r: dict) -> bool:
        cred = r.get("credential")
        if not cred:
            return False
        try:
            return ed25519.verify(
                ed25519.public_from_secret(self.seed),
                crypto.dumps(cred["body"]).encode(),
                crypto.b64d(cred["service_sig"]))
        except Exception:
            return False

    def _replay(self, r: dict, *, duplicate: bool = True) -> dict:
        """Return the first-ever reservation/settlement record for a request.
        A caller that crashed after reserve sees exactly what happened."""
        out = self.reservation_view(r)
        out["duplicate"] = duplicate
        return out

    def reservation_view(self, r: dict) -> dict:
        now = _now(self.clock)
        expired = r["status"] in ACTIVE_RES_STATES \
            and r["lease_expires_at"] <= now
        return {
            "reservation_id": r["id"], "request_id": r["request_id"],
            "budget_id": r["budget_id"], "purpose": r["purpose"],
            "key_version_id": r["key_version_id"], "subject": r["subject"],
            "amount": r["amount"], "consumed_amount": r["consumed_amount"],
            "status": r["status"], "reserved_at": r["reserved_at"],
            "lease_expires_at": r["lease_expires_at"],
            "lease_expired": expired,
            "n_signatures": len(r["signatures"]),
            "signatures": list(r["signatures"]),
            "settlement": r["settlement"], "settled_at": r["settled_at"],
            "credential": r.get("credential"),
            "manual_handling": r.get("manual_handling"),
        }

    def list_reservations(self, budget_id: str | None = None) -> list[dict]:
        out = []
        for r in self.s["budget_reservations"].values():
            if budget_id is None or r["budget_id"] == budget_id:
                out.append(self.reservation_view(r))
        return sorted(out, key=lambda x: x["reserved_at"])

    def _live_reservation(self, request_id: str, *, allow_expired=False):
        r = self.get_reservation(request_id)
        if r["status"] not in ACTIVE_RES_STATES:
            raise ReservationState(
                f"request {request_id} already {r['status']}; "
                f"replaying settlement: {r['settlement']}")
        if not allow_expired and r["lease_expires_at"] <= _now(self.clock):
            raise ReservationExpired(
                f"reservation lease for {request_id} expired at "
                f"{r['lease_expires_at']}")
        b = self._find_budget(r["budget_id"])
        if not self.verify_credential(r):
            raise BudgetCredentialInvalid("reservation credential invalid")
        return r, b

    # ======================================================================
    # phase 2: produce signature under the reservation
    # ======================================================================
    def sign_under_fn(self, request_id: str, messages: list[bytes],
                      sign_fn) -> dict:
        """Produce signature(s) against a live reservation. Records a
        signature audit (message digest + key version + sig digest) BEFORE
        the caller may settle, so a produced signature can never be released.

        ``sign_fn(version_id, message) -> bytes`` does the actual signing.
        Concrete signatures come back in ``signatures_raw`` (in order); only
        digests enter the audit trail.
        """
        if sign_fn is None:
            raise PolicyViolation("sign function required")
        r, b = self._live_reservation(request_id)
        # signing rules re-checked at production time
        self._admit_check(b, 0)
        n = len(messages)
        if n <= 0:
            raise PolicyViolation("at least one message is required")
        if r["consumed_amount"] + n > r["amount"]:
            raise PolicyViolation(
                f"{n} signature(s) would exceed the reserved {r['amount']}")
        produced, raw = [], []
        for msg in messages:
            sig = bytes(sign_fn(r["key_version_id"], msg))
            raw.append(sig)
            produced.append({
                "seq": len(r["signatures"]),
                "message_digest": hashlib.sha256(msg).hexdigest(),
                "key_version_id": r["key_version_id"],
                "sig_digest": hashlib.sha256(sig).hexdigest(),
                "produced_at": _now(self.clock),
            })
        r["signatures"].extend(produced)
        r["status"] = R_SIGNED
        self.audit.append("budget_signature_recorded",
                          {"budget_id": b["id"], "reservation_id": r["id"],
                           "request_id": request_id,
                           "key_version_id": r["key_version_id"],
                           "count": n,
                           "produced": produced,
                           "subject": r["subject"]})
        view = self.reservation_view(r)
        view["signatures_raw"] = raw
        return view

    # ======================================================================
    # phase 3: settle reservation -> consumption (unused units returned)
    # ======================================================================
    def settle(self, request_id: str, signed_count: int | None = None) -> dict:
        r0 = self.get_reservation(request_id)
        if r0["status"] in ACTIVE_RES_STATES \
                and r0["lease_expires_at"] <= _now(self.clock):
            # Lease lapsed: resolve from signature audit first. A hold with
            # signatures is force-settled to consumption; an empty hold is
            # released - the caller then gets RELEASED (not a zero-consume
            # CONSUMED) from the state check below.
            self._sweep_budget(self._find_budget(r0["budget_id"]))
        r, b = self._live_reservation(request_id, allow_expired=True)
        n_sig = len(r["signatures"])
        consume = n_sig if signed_count is None else int(signed_count)
        if signed_count is not None and consume != n_sig:
            raise PolicyViolation(
                f"signed_count {consume} does not match signature audit "
                f"{n_sig}; consumption cannot be invented")
        if consume > r["amount"]:
            raise PolicyViolation("consumption exceeds reservation")
        released = r["amount"] - consume
        r["consumed_amount"] = consume
        r["status"] = R_CONSUMED
        r["settled_at"] = _now(self.clock)
        r["settlement"] = {
            "kind": "settled", "consumed": consume, "released": released,
            "actor": r.get("actor"),
            "sig_digests": [s["sig_digest"] for s in r["signatures"]],
            "reason": "reservation settled as consumption"}
        self.audit.append("budget_reservation_consumed",
                          {"budget_id": b["id"], "reservation_id": r["id"],
                           "request_id": request_id,
                           "amount": r["amount"], "consumed_amount": consume,
                           "released_amount": released,
                           "kind": "settled", "actor": r.get("actor"),
                           "n_signatures": n_sig})
        return self.reservation_view(r)

    # ======================================================================
    # takeover after worker crash, and manual handling
    # ======================================================================
    def takeover(self, request_id: str) -> dict:
        """A replacement worker decides from the signature audit what state
        the crashed original reached.

        * signatures exist -> already CONSUMED (settled or force-settled):
          quota must not be reused; the signatures are returned;
        * live lease, no signature -> still held, can continue signing;
        * expired lease, no signature -> safely returned (RELEASED).
        """
        r = self.get_reservation(request_id)
        now = _now(self.clock)
        if r["status"] in ACTIVE_RES_STATES and r["lease_expires_at"] <= now:
            b = self._find_budget(r["budget_id"])
            self._sweep_budget(b)
            r = self.get_reservation(request_id)
        view = self.reservation_view(r)
        if r["status"] == R_CONSUMED:
            view["takeover"] = "completed"
            view["action"] = "signature already produced; quota spent"
        elif r["status"] == R_RELEASED:
            view["takeover"] = "released"
            view["action"] = "no signature was produced; quota returned; " \
                             "reserve again with a new request number"
        elif r["signatures"]:
            view["takeover"] = "signed-pending-settle"
            view["action"] = "signature exists but not settled; settle now"
        else:
            view["takeover"] = "held"
            view["action"] = "no signature yet; continue within the lease"
        return view

    def manual_release(self, request_id: str, operator: str,
                       reason: str) -> dict:
        """Human handling of a long-hung reservation. Refuses to release any
        request that carries signature audit, and records operator + reason
        + quantities before/after."""
        if not reason:
            raise PolicyViolation("manual handling requires a reason")
        r = self.get_reservation(request_id)
        b = self._find_budget(r["budget_id"])
        if r["status"] not in ACTIVE_RES_STATES:
            raise ReservationState(
                f"request {request_id} is already {r['status']}")
        if r["signatures"]:
            raise ReservationHasSignature(
                f"request {request_id} has {len(r['signatures'])} signature "
                f"audit record(s); it cannot be released - settle it instead")
        before = self.budget_view(b)
        self._mark_released(b, r, "manual-release", actor=operator,
                            reason=reason, manual=True)
        after = self.budget_view(b)
        r["manual_handling"] = {
            "operator": operator, "reason": reason,
            "handled_at": _now(self.clock),
            "before": {"consumed": before["consumed"],
                       "reserved": before["reserved"],
                       "available": before["available"],
                       "total": before["total"]},
            "after": {"consumed": after["consumed"],
                      "reserved": after["reserved"],
                      "available": after["available"],
                      "total": after["total"]}}
        return self.reservation_view(r)

    def manual_settle(self, request_id: str, operator: str,
                      reason: str) -> dict:
        """Settle a hung reservation whose signatures exist (crash between
        signature production and settlement)."""
        if not reason:
            raise PolicyViolation("manual handling requires a reason")
        r = self.get_reservation(request_id)
        b = self._find_budget(r["budget_id"])
        if r["status"] not in ACTIVE_RES_STATES:
            raise ReservationState(
                f"request {request_id} is already {r['status']}")
        if not r["signatures"]:
            raise ReservationState(
                f"request {request_id} has no signature audit; release it "
                f"instead of settling")
        before = self.budget_view(b)
        n = len(r["signatures"])
        r["consumed_amount"] = n
        r["status"] = R_CONSUMED
        r["settled_at"] = _now(self.clock)
        released = r["amount"] - n
        r["settlement"] = {"kind": "manual-settle", "consumed": n,
                           "released": released, "actor": operator,
                           "reason": reason, "manual": True,
                           "sig_digests": [s["sig_digest"]
                                           for s in r["signatures"]]}
        self.audit.append("budget_reservation_consumed",
                          {"budget_id": b["id"], "reservation_id": r["id"],
                           "request_id": request_id, "amount": r["amount"],
                           "consumed_amount": n,
                           "released_amount": released,
                           "kind": "manual-settle", "actor": operator,
                           "reason": reason, "n_signatures": n})
        after = self.budget_view(b)
        r["manual_handling"] = {
            "operator": operator, "reason": reason,
            "handled_at": _now(self.clock),
            "before": {"consumed": before["consumed"],
                       "reserved": before["reserved"],
                       "available": before["available"],
                       "total": before["total"]},
            "after": {"consumed": after["consumed"],
                      "reserved": after["reserved"],
                      "available": after["available"],
                      "total": after["total"]}}
        return self.reservation_view(r)

    # ======================================================================
    # views for console/network
    # ======================================================================
    def status(self) -> dict:
        return {
            "budgets": self.list_budgets(),
            "reservations": self.list_reservations(),
            "subjects": dict(self.s["budget_subjects"]),
            "officers": {oid: {"officer_id": oid, "label": r.get("label"),
                               "pub": r["pub"]}
                         for oid, r in self.s["budget_officers"].items()},
        }
