"""Policy enforcement and tamper-evident audit for agent tool calls."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import time
from typing import Any


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    handler: Callable[..., Any]
    risk: int
    sensitive_arguments: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ToolCall:
    tool: str
    arguments: Mapping[str, Any]
    idempotency_key: str


@dataclass(frozen=True)
class ActorContext:
    principal: str
    roles: frozenset[str]
    environment: str


@dataclass(frozen=True)
class PolicyRule:
    name: str
    effect: Effect
    tools: frozenset[str] = frozenset({"*"})
    roles: frozenset[str] = frozenset({"*"})
    environments: frozenset[str] = frozenset({"*"})
    minimum_risk: int = 0

    def matches(self, spec: ToolSpec, context: ActorContext) -> bool:
        tool_matches = "*" in self.tools or spec.name in self.tools
        role_matches = "*" in self.roles or bool(self.roles & context.roles)
        env_matches = "*" in self.environments or context.environment in self.environments
        return tool_matches and role_matches and env_matches and spec.risk >= self.minimum_risk


@dataclass(frozen=True)
class Decision:
    effect: Effect
    matched_rules: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class Approval:
    tool: str
    idempotency_key: str
    approver: str
    expires_at: float

    def valid_for(self, call: ToolCall, now: float) -> bool:
        return (
            self.tool == call.tool
            and self.idempotency_key == call.idempotency_key
            and now <= self.expires_at
        )


class PolicyEngine:
    """Deny overrides approval, which overrides allow; default is deny."""

    def __init__(self, rules: tuple[PolicyRule, ...]):
        self.rules = rules

    def decide(self, spec: ToolSpec, context: ActorContext) -> Decision:
        matches = tuple(rule for rule in self.rules if rule.matches(spec, context))
        names = tuple(rule.name for rule in matches)
        if any(rule.effect is Effect.DENY for rule in matches):
            return Decision(Effect.DENY, names, "explicit deny policy")
        if any(rule.effect is Effect.REQUIRE_APPROVAL for rule in matches):
            return Decision(Effect.REQUIRE_APPROVAL, names, "human approval required")
        if any(rule.effect is Effect.ALLOW for rule in matches):
            return Decision(Effect.ALLOW, names, "allowed by policy")
        return Decision(Effect.DENY, (), "no matching allow policy")


@dataclass(frozen=True)
class AuditRecord:
    sequence: int
    action: str
    principal: str
    tool: str
    decision: str
    arguments: Mapping[str, Any]
    previous_hash: str
    hash: str


class AuditLog:
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def append(
        self,
        action: str,
        context: ActorContext,
        spec: ToolSpec,
        decision: Decision,
        arguments: Mapping[str, Any],
    ) -> AuditRecord:
        safe_arguments = {
            key: "[REDACTED]" if key in spec.sensitive_arguments else value
            for key, value in arguments.items()
        }
        previous = self.records[-1].hash if self.records else "GENESIS"
        payload = {
            "sequence": len(self.records) + 1,
            "action": action,
            "principal": context.principal,
            "tool": spec.name,
            "decision": decision.effect.value,
            "arguments": safe_arguments,
            "previous_hash": previous,
        }
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
        record = AuditRecord(**payload, hash=digest)
        self.records.append(record)
        return record

    def verify(self) -> bool:
        previous = "GENESIS"
        for record in self.records:
            payload = asdict(record)
            digest = payload.pop("hash")
            if payload["previous_hash"] != previous:
                return False
            expected = hashlib.sha256(
                json.dumps(payload, sort_keys=True, default=str).encode()
            ).hexdigest()
            if digest != expected:
                return False
            previous = digest
        return True


class SlidingWindowLimiter:
    def __init__(self, calls: int = 10, window_seconds: float = 60.0):
        self.calls = calls
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def permit(self, principal: str, now: float) -> bool:
        events = self._events[principal]
        while events and now - events[0] >= self.window_seconds:
            events.popleft()
        if len(events) >= self.calls:
            return False
        events.append(now)
        return True


class AgentControlPlane:
    def __init__(
        self,
        tools: tuple[ToolSpec, ...],
        policies: PolicyEngine,
        audit: AuditLog | None = None,
        limiter: SlidingWindowLimiter | None = None,
    ):
        self.tools = {tool.name: tool for tool in tools}
        self.policies = policies
        self.audit = audit or AuditLog()
        self.limiter = limiter or SlidingWindowLimiter()
        self._results: dict[str, Any] = {}

    def execute(
        self,
        call: ToolCall,
        context: ActorContext,
        approval: Approval | None = None,
        now: float | None = None,
    ) -> Any:
        current = time.time() if now is None else now
        if call.idempotency_key in self._results:
            return self._results[call.idempotency_key]
        spec = self.tools.get(call.tool)
        if spec is None:
            raise ToolDenied(f"unknown tool: {call.tool}")
        decision = self.policies.decide(spec, context)
        if not self.limiter.permit(context.principal, current):
            denied = Decision(Effect.DENY, decision.matched_rules, "rate limit exceeded")
            self.audit.append("tool.denied", context, spec, denied, call.arguments)
            raise ToolDenied(denied.reason)
        if decision.effect is Effect.DENY:
            self.audit.append("tool.denied", context, spec, decision, call.arguments)
            raise ToolDenied(decision.reason)
        if decision.effect is Effect.REQUIRE_APPROVAL and not (
            approval and approval.valid_for(call, current)
        ):
            self.audit.append("tool.awaiting_approval", context, spec, decision, call.arguments)
            raise ApprovalRequired(decision.reason)
        self.audit.append("tool.started", context, spec, decision, call.arguments)
        result = spec.handler(**dict(call.arguments))
        self._results[call.idempotency_key] = result
        self.audit.append("tool.succeeded", context, spec, decision, call.arguments)
        return result


class ToolDenied(RuntimeError):
    pass


class ApprovalRequired(RuntimeError):
    pass
