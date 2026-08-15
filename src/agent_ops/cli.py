from .control_plane import ActorContext, AgentControlPlane, Effect, PolicyEngine, PolicyRule, ToolCall, ToolSpec


def main() -> None:
    plane = AgentControlPlane(
        (ToolSpec("lookup", lambda account: {"account": account, "status": "active"}, risk=1),),
        PolicyEngine((PolicyRule("support reads", Effect.ALLOW, frozenset({"lookup"}), frozenset({"support"})),)),
    )
    result = plane.execute(
        ToolCall("lookup", {"account": "ACME"}, "demo-1"),
        ActorContext("demo-agent", frozenset({"support"}), "development"),
    )
    print(result)


if __name__ == "__main__":
    main()
