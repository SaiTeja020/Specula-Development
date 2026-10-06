import asyncio
import json
from src.agents.visualizer_api import app, _active_investigations, _get_specula_graph
from fastapi.testclient import TestClient

client = TestClient(app)

def test_hitl_interrupt_and_resume():
    # 1. Start the investigation via the visualizer API
    # Since trigger_pipeline uses asyncio.create_task and runs in the background,
    # we might need to mock or just wait for it.
    
    # We can directly use the investigation_runner to test the core logic
    from src.agents.investigation_runner import run_investigation, HITLPausedResult, _resume_after_hitl
    from langgraph.checkpoint.memory import InMemorySaver
    
    checkpointer = InMemorySaver()
    thread_id = "test-thread-hitl-1"
    case_id = "test-case-hitl-1"
    
    # Force a guardrail failure to trigger HITL
    # We use raw_input_prefix to inject test instructions
    # Actually, we can just run it, but maybe it won't hit HITL normally unless it fails.
    # Let's inject a test_control via state if possible, but run_investigation doesn't accept state directly.
    # We can use the mock investigation from the graph tests.
    
    # Just call run_investigation with a query that triggers HITL or mock the state.
    # We can't guarantee HITL without test control.
    # Let's manually trigger hitl_node by starting graph at 'hitl' node!
    
    from src.agents.graph import build_graph
    graph = build_graph(checkpointer=checkpointer)
    config = {"configurable": {"thread_id": thread_id}}
    
    initial_state = {
        "case_id": case_id,
        "raw_input": "Test query",
        "findings": [],
        "guardrail_fail_tier": 2, # force HITL
        "debate_round": 1
    }
    
    # 1. Run graph directly up to hitl (or start it at hitl)
    try:
        from langgraph.types import Command
        # langgraph 0.1/0.2 compatibility for starting at a node
        graph.invoke(Command(resume=None, goto="hitl", update=initial_state), config)
    except Exception as e:
        # Check if it interrupted
        from src.agents.investigation_runner import _is_hitl_interrupt, _handle_hitl_pause
        assert _is_hitl_interrupt(e)
        
        # 2. Extract interrupt
        result = _handle_hitl_pause(graph, config, thread_id, case_id)
        assert isinstance(result, HITLPausedResult)
        
        # 3. Check snapshot payload
        assert result.snapshot["type"] == "hitl_required"
        assert "message" in result.snapshot
        assert "options" in result.snapshot
        
        # 4. Resume with free-form text
        decision = "clarify"
        query = "Focus on the suspicious network activity."
        
        resume_result = _resume_after_hitl(
            query=query,
            thread_id=thread_id,
            decision=decision,
            checkpointer=checkpointer
        )
        
        # 5. Check if it resumed properly
        # Because we mocked by going directly to hitl and jumping to supervisor, it should finish or run
        assert resume_result is not None
        
        # Check the state after resume
        final_state = graph.get_state(config).values
        assert "Focus on the suspicious network activity." in final_state.get("raw_input", "")
        
        print("Backend HITL test passed!")
        return

if __name__ == "__main__":
    test_hitl_interrupt_and_resume()
