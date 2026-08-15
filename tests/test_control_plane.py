import unittest

from agent_ops import ActorContext, AgentControlPlane, Approval, AuditLog, Effect, PolicyEngine, PolicyRule, ToolCall, ToolSpec
from agent_ops.control_plane import ApprovalRequired, SlidingWindowLimiter, ToolDenied


class AgentControlPlaneTests(unittest.TestCase):
    def setUp(self):
        self.calls = 0

        def deploy(service, token="hidden"):
            self.calls += 1
            return {"service": service, "revision": self.calls}

        tools = (ToolSpec("deploy", deploy, risk=8, sensitive_arguments=frozenset({"token"})),)
        policies = PolicyEngine(
            (
                PolicyRule("deny production interns", Effect.DENY, frozenset({"deploy"}), frozenset({"intern"}), frozenset({"production"})),
                PolicyRule("approve production deploys", Effect.REQUIRE_APPROVAL, frozenset({"deploy"}), frozenset({"engineer"}), frozenset({"production"}), minimum_risk=5),
                PolicyRule("allow development", Effect.ALLOW, frozenset({"deploy"}), frozenset({"engineer"}), frozenset({"development"})),
            )
        )
        self.plane = AgentControlPlane(tools, policies)

    def test_executes_allowed_call(self):
        context = ActorContext("agent-1", frozenset({"engineer"}), "development")

        result = self.plane.execute(ToolCall("deploy", {"service": "api"}, "key-1"), context, now=100)

        self.assertEqual(result["revision"], 1)
        self.assertTrue(self.plane.audit.verify())

    def test_requires_scoped_approval(self):
        context = ActorContext("agent-1", frozenset({"engineer"}), "production")
        call = ToolCall("deploy", {"service": "api"}, "key-2")

        with self.assertRaises(ApprovalRequired):
            self.plane.execute(call, context, now=100)

        approval = Approval("deploy", "key-2", "on-call", expires_at=110)
        result = self.plane.execute(call, context, approval, now=105)
        self.assertEqual(result["service"], "api")

    def test_explicit_deny_overrides(self):
        context = ActorContext("agent-2", frozenset({"intern", "engineer"}), "production")

        with self.assertRaises(ToolDenied):
            self.plane.execute(ToolCall("deploy", {"service": "api"}, "key-3"), context, now=100)

    def test_idempotency_prevents_duplicate_side_effects(self):
        context = ActorContext("agent-1", frozenset({"engineer"}), "development")
        call = ToolCall("deploy", {"service": "api"}, "same-key")

        first = self.plane.execute(call, context, now=100)
        second = self.plane.execute(call, context, now=101)

        self.assertEqual(first, second)
        self.assertEqual(self.calls, 1)

    def test_audit_redacts_sensitive_arguments(self):
        context = ActorContext("agent-1", frozenset({"engineer"}), "development")
        self.plane.execute(ToolCall("deploy", {"service": "api", "token": "secret"}, "key-4"), context, now=100)

        self.assertEqual(self.plane.audit.records[0].arguments["token"], "[REDACTED]")
        self.assertNotIn("secret", repr(self.plane.audit.records))

    def test_rate_limit_is_enforced(self):
        tools = (ToolSpec("read", lambda: "ok", risk=1),)
        policy = PolicyEngine((PolicyRule("allow", Effect.ALLOW),))
        plane = AgentControlPlane(tools, policy, AuditLog(), SlidingWindowLimiter(calls=1, window_seconds=10))
        context = ActorContext("agent-3", frozenset({"reader"}), "development")

        plane.execute(ToolCall("read", {}, "r1"), context, now=100)
        with self.assertRaisesRegex(ToolDenied, "rate limit"):
            plane.execute(ToolCall("read", {}, "r2"), context, now=101)


if __name__ == "__main__":
    unittest.main()
