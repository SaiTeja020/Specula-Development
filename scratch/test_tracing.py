import asyncio
import os
import sys
sys.path.insert(0, os.path.abspath("."))
from src.agents.visualizer_api import trigger_pipeline

async def test_tracing():
    os.environ["SPECULA_LLM_BACKEND"] = "stub"
    req = {
        "case_id": "CASE-2026-0915-ALPHA",
        "query": "Investigate suspicious network activity."
    }
    result = await trigger_pipeline(req)
    print('Trigger result:', result)
    
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    if tasks:
        await asyncio.gather(*tasks)

if __name__ == '__main__':
    asyncio.run(test_tracing())
