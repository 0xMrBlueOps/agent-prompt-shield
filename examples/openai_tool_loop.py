from agent_prompt_shield import AgentGuard


def lookup_weather(city: str) -> str:
    return f"{city}: 72F"


guard = AgentGuard(policy="balanced")
guard.add_system("You may call tools to answer the user's question.")
guard.add_untrusted("What's the weather in Austin?", source="user")

tool_call = {
    "function": {
        "name": "lookup_weather",
        "arguments": '{"city": "Austin"}',
    }
}

execution = guard.openai_tool_call(tool_call, {"lookup_weather": lookup_weather})

if execution.allowed:
    print(execution.output)
else:
    print(execution.result.decision.reason)
