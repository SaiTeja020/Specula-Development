import os
import sys

# Ensure src can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.agents.config import get_llm

def test_backend(backend: str, model: str = None, extra_env: dict = None):
    print(f"\n{'='*50}")
    print(f"Testing Backend: {backend.upper()}")
    print(f"{'='*50}")
    
    # Save original env
    orig_env = dict(os.environ)
    
    try:
        # Set up env for this test
        os.environ["SPECULA_LLM_BACKEND"] = backend
        if model:
            os.environ["SPECULA_LLM_MODEL"] = model
        elif "SPECULA_LLM_MODEL" in os.environ:
            del os.environ["SPECULA_LLM_MODEL"]
            
        if extra_env:
            for k, v in extra_env.items():
                os.environ[k] = v
                
        # 1. Instantiate the LLM
        try:
            print(f"Attempting to instantiate agent 'supervisor' with backend '{backend}'...")
            llm_wrapper = get_llm("supervisor", case_id="test_case")
            actual_model = getattr(llm_wrapper._llm, "model", getattr(llm_wrapper._llm, "model_name", "stub"))
            print(f"[PASS] Successfully created LangChain model class: {type(llm_wrapper._llm).__name__}")
            print(f"[PASS] Model string: {actual_model}")
        except Exception as e:
            print(f"[FAIL] Instantiation failed: {e}")
            return
            
        # 2. Test invocation
        try:
            print("Attempting simple invocation ('Say hello')...")
            # For stub, it doesn't matter what we pass
            response = llm_wrapper.invoke("Say hello")
            content = response.content if hasattr(response, "content") else str(response)
            print(f"[PASS] Invocation succeeded. Response snippet: {content[:100]}")
        except Exception as e:
            print(f"[EXPECTED/FAIL] Invocation failed (this is expected if the server is not actually running):")
            print(f"    Reason: {type(e).__name__}: {e}")
            
    finally:
        # Restore env
        os.environ.clear()
        os.environ.update(orig_env)


if __name__ == "__main__":
    # 1. Test Stub
    test_backend("stub")
    
    # 2. Test LM Studio (configured as requested)
    test_backend("lmstudio", model="qwen/qwen3-1.7b", extra_env={"LMSTUDIO_BASE_URL": "http://localhost:1234/v1"})
    
    # 3. Test Ollama
    test_backend("ollama", model="qwen2.5-coder:1.5b")
    
    # 4. Test Gemini (fake key to test instantiation and expected auth error)
    test_backend("gemini", extra_env={"GEMINI_API_KEY": "fake_key_for_test"})

