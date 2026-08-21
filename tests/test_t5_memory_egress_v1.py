from __future__ import annotations

import sys
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from soul_platform.t5_memory_egress import (
    MemoryProvenance,
    T5EgressPolicy,
    T5MemoryEgressGuard,
)


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def mem(memory_id: str, owner: str | None, scope: str = "private", *, trusted: bool = True):
    return MemoryProvenance(memory_id, owner, scope, trusted)


def test_positive_cross_owner_private_is_blocked() -> None:
    guard = T5MemoryEgressGuard()
    decision = guard.evaluate(
        session_id="s1", interlocutor="actor_a", memories=[mem("m-actor-b", "actor_b")]
    )
    assert decision.allowed_ids == ()
    assert decision.batch_denied is True
    assert decision.blocked[0].reason == "cross_owner_private"


def test_negative_own_private_is_allowed() -> None:
    guard = T5MemoryEgressGuard()
    decision = guard.evaluate(
        session_id="s1", interlocutor="Actor_A", memories=[mem("m-own", "actor_a")]
    )
    assert decision.allowed_ids == ("m-own",)
    assert decision.blocked == ()
    assert decision.batch_denied is False


def test_control_is_non_vacuous() -> None:
    guard = T5MemoryEgressGuard()
    own = guard.evaluate(
        session_id="own", interlocutor="actor_a", memories=[mem("m1", "actor_a")]
    )
    other = guard.evaluate(
        session_id="other", interlocutor="actor_a", memories=[mem("m2", "actor_b")]
    )
    assert own.allowed is True
    assert other.allowed is False
    assert own.batch_denied != other.batch_denied


def test_role_pivot_text_cannot_change_trusted_owner() -> None:
    # The guard consumes authenticated identity+provenance, never prompt text.
    guard = T5MemoryEgressGuard()
    decision = guard.evaluate(
        session_id="s1",
        interlocutor="actor_a",
        memories=[mem("m-user-x", "user-x")],
    )
    assert decision.blocked[0].reason == "cross_owner_private"


def test_unknown_or_untrusted_provenance_fails_closed() -> None:
    guard = T5MemoryEgressGuard()
    decision = guard.evaluate(
        session_id="s1",
        interlocutor="actor_a",
        memories=[mem("unknown", None), mem("writable-meta", "actor_a", trusted=False)],
    )
    assert decision.allowed_ids == ()
    assert {item.reason for item in decision.blocked} == {
        "unknown_owner",
        "untrusted_provenance",
    }


def test_strict_batch_drops_safe_fragment_if_batch_contains_leak() -> None:
    guard = T5MemoryEgressGuard()
    decision = guard.evaluate(
        session_id="s1",
        interlocutor="actor_a",
        memories=[mem("own", "actor_a"), mem("other", "actor_b")],
    )
    assert decision.allowed_ids == ()
    assert decision.batch_denied is True


def test_denied_strict_batch_does_not_burn_shared_budget() -> None:
    policy = T5EgressPolicy(
        max_shared_fragments_per_window=1,
        max_cross_owner_turns=3,
    )
    guard = T5MemoryEgressGuard(policy)
    denied = guard.evaluate(
        session_id="s1",
        interlocutor="actor_a",
        memories=[mem("shared-denied", "actor_b", "shared"), mem("private-denied", "actor_c")],
    )
    allowed = guard.evaluate(
        session_id="s1",
        interlocutor="actor_a",
        memories=[mem("shared-allowed", "actor_b", "shared")],
    )
    assert denied.batch_denied is True
    assert allowed.allowed_ids == ("shared-allowed",)


def test_explicit_filter_compatibility_can_keep_only_safe_fragments() -> None:
    policy = T5EgressPolicy(strict_batch=False)
    guard = T5MemoryEgressGuard(policy)
    decision = guard.evaluate(
        session_id="s1",
        interlocutor="actor_a",
        memories=[mem("own", "actor_a"), mem("other", "actor_b")],
    )
    assert decision.allowed_ids == ("own",)
    assert decision.blocked[0].reason == "cross_owner_private"


def test_repeated_cross_owner_turns_lock_memory_egress() -> None:
    clock = Clock()
    policy = T5EgressPolicy(max_cross_owner_turns=2, lock_seconds=60)
    guard = T5MemoryEgressGuard(policy, clock=clock)
    first = guard.evaluate(
        session_id="s1", interlocutor="actor_a", memories=[mem("x1", "actor_b")]
    )
    second = guard.evaluate(
        session_id="s1", interlocutor="actor_a", memories=[mem("x2", "actor_c")]
    )
    after = guard.evaluate(
        session_id="s1", interlocutor="actor_a", memories=[mem("own", "actor_a")]
    )
    assert first.session_locked is False
    assert second.session_locked is True
    assert after.reason == "session_memory_egress_locked"
    assert after.allowed_ids == ()


def test_gradual_shared_extraction_hits_rolling_budget() -> None:
    clock = Clock()
    policy = T5EgressPolicy(
        max_shared_fragments_per_window=2,
        max_distinct_foreign_owners_per_window=3,
    )
    guard = T5MemoryEgressGuard(policy, clock=clock)
    assert guard.evaluate(
        session_id="s1", interlocutor="actor_a", memories=[mem("h1", "actor_b", "shared")]
    ).allowed
    assert guard.evaluate(
        session_id="s1", interlocutor="actor_a", memories=[mem("h2", "actor_b", "team")]
    ).allowed
    third = guard.evaluate(
        session_id="s1", interlocutor="actor_a", memories=[mem("h3", "actor_b", "shared")]
    )
    assert third.allowed_ids == ()
    assert third.blocked[0].reason == "multi_turn_shared_budget_exhausted"


def test_gradual_owner_aggregation_is_bounded() -> None:
    policy = T5EgressPolicy(
        max_shared_fragments_per_window=10,
        max_distinct_foreign_owners_per_window=1,
    )
    guard = T5MemoryEgressGuard(policy)
    assert guard.evaluate(
        session_id="s1", interlocutor="actor_a", memories=[mem("h", "actor_b", "team")]
    ).allowed
    result = guard.evaluate(
        session_id="s1", interlocutor="actor_a", memories=[mem("x", "actor_c", "shared")]
    )
    assert result.blocked[0].reason == "multi_turn_owner_aggregation"


def test_public_memory_does_not_consume_shared_privacy_budget() -> None:
    policy = T5EgressPolicy(max_shared_fragments_per_window=1)
    guard = T5MemoryEgressGuard(policy)
    for index in range(3):
        result = guard.evaluate(
            session_id="s1",
            interlocutor="actor_a",
            memories=[mem(f"public-{index}", "publisher", "public")],
        )
        assert result.allowed


def test_explicit_single_owner_compatibility_never_impersonates_owner() -> None:
    policy = T5EgressPolicy.compatibility_single_owner("actor_a")
    guard = T5MemoryEgressGuard(policy)
    owner = guard.evaluate(
        session_id="owner", interlocutor="actor_a", memories=[mem("legacy-own", None)]
    )
    outsider = guard.evaluate(
        session_id="outsider", interlocutor="actor_b", memories=[mem("legacy-other", None)]
    )
    assert owner.allowed_ids == ("legacy-own",)
    assert outsider.allowed_ids == ()
    assert outsider.blocked[0].reason == "cross_owner_private"


def test_provenance_drift_for_same_memory_id_is_blocked() -> None:
    guard = T5MemoryEgressGuard()
    assert guard.evaluate(
        session_id="s1", interlocutor="actor_a", memories=[mem("stable", "actor_a")]
    ).allowed
    drift = guard.evaluate(
        session_id="s1", interlocutor="actor_a", memories=[mem("stable", "actor_b", "public")]
    )
    assert drift.allowed_ids == ()
    assert drift.blocked[0].reason == "provenance_drift"


def test_state_registries_fail_closed_at_capacity() -> None:
    policy = T5EgressPolicy(max_session_states=1, max_provenance_bindings=1)
    guard = T5MemoryEgressGuard(policy)
    assert guard.evaluate(
        session_id="s1", interlocutor="actor_a", memories=[mem("first", "actor_a")]
    ).allowed
    binding_full = guard.evaluate(
        session_id="s1", interlocutor="actor_a", memories=[mem("second", "actor_a")]
    )
    session_full = guard.evaluate(
        session_id="s2", interlocutor="actor_a", memories=[mem("first", "actor_a")]
    )
    assert binding_full.blocked[0].reason == "provenance_registry_full"
    assert session_full.reason == "session_registry_full"


def test_window_and_lock_expire_without_cross_session_bleed() -> None:
    clock = Clock()
    policy = T5EgressPolicy(
        window_seconds=10,
        lock_seconds=5,
        max_cross_owner_turns=1,
        max_shared_fragments_per_window=1,
    )
    guard = T5MemoryEgressGuard(policy, clock=clock)
    locked = guard.evaluate(
        session_id="s1", interlocutor="actor_a", memories=[mem("x", "actor_b")]
    )
    other_session = guard.evaluate(
        session_id="s2", interlocutor="actor_a", memories=[mem("own-other", "actor_a")]
    )
    assert locked.session_locked is True
    assert other_session.allowed
    clock.advance(11)
    recovered = guard.evaluate(
        session_id="s1", interlocutor="actor_a", memories=[mem("own", "actor_a")]
    )
    assert recovered.allowed
