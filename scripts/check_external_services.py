"""Read-only credential and endpoint probes. Never print credentials or responses."""
import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv


def main():
    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("component", choices=["gcp", "gemini", "attribution"])
    args = parser.parse_args()
    result = {"component": args.component, "status": "unavailable"}
    try:
        if args.component == "gcp":
            import google.auth
            from google.cloud import logging_v2
            if not os.getenv("GCP_PROJECT_ID"):
                result["reason"] = "GCP_PROJECT_ID is not configured"
            else:
                credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/logging.read"])
                client = logging_v2.services.logging_service_v2.LoggingServiceV2Client(credentials=credentials)
                start = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
                entries = client.list_log_entries(request={
                    "resource_names": ["projects/" + os.environ["GCP_PROJECT_ID"]],
                    "filter": f'logName:"cloudaudit.googleapis.com" AND timestamp >= "{start}"',
                    "page_size": 1,
                }, timeout=10, retry=None)
                # Force the request; an empty authorized result proves access, not ingestion.
                entry = next(iter(entries), None)
                result = {**result, "status": "reachable", "audit_entry_present": entry is not None,
                          "ingestion_verified": False}
                client.close()
        elif args.component == "gemini":
            from google import genai
            from google.genai import types
            key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
            if not key:
                result["reason"] = "Gemini API key is not configured"
            else:
                client = genai.Client(api_key=key, http_options=types.HttpOptions(timeout=10000))
                # Use the repository's actual provider model resolution.
                import sys
                sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
                from src.agents.config import _get_gemini_model
                model = _get_gemini_model()
                response = client.models.generate_content(model=model, contents="Reply with the word SPECULA_OK only.")
                result = {**result, "status": "verified" if (response.text or "").strip() == "SPECULA_OK" else "unexpected_response",
                          "model": model}
                client.close()
        else:
            if not all(os.getenv(name) for name in ("SPECULA_THREAT_ATTRIBUTION_BASE_URL", "SPECULA_THREAT_ATTRIBUTION_API_KEY")):
                result["reason"] = "Attribution endpoint/key are not configured"
            else:
                from openai import OpenAI
                with OpenAI(api_key=os.environ["SPECULA_THREAT_ATTRIBUTION_API_KEY"],
                    base_url=os.environ["SPECULA_THREAT_ATTRIBUTION_BASE_URL"], timeout=10, max_retries=0) as client:
                    response = client.chat.completions.create(model=os.getenv("SPECULA_THREAT_ATTRIBUTION_MODEL", "kimi-k2.6"),
                        messages=[{"role": "user", "content": "Reply SPECULA_OK only."}], max_tokens=20)
                    result["status"] = "verified" if response.choices[0].message.content.strip() == "SPECULA_OK" else "unexpected_response"
    except Exception as exc:
        result["error_type"] = type(exc).__name__
        code = getattr(exc, "code", None)
        if isinstance(code, int): result["http_status"] = code
        message = str(getattr(exc, "message", "")).lower()
        if "api key" in message:
            result["reason"] = "Provider rejected the API key"
        elif "quota" in message or "resource exhausted" in message:
            result["reason"] = "Provider quota unavailable"
        elif "not found" in message or "not supported" in message:
            result["reason"] = "Requested model is unavailable for this endpoint"
        # Exception text may contain credential URLs; record only the exception class.
    target = Path("data/verification")
    target.mkdir(parents=True, exist_ok=True)
    (target / (args.component + "_latest.json")).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result))
    return 0 if result["status"] == "verified" else 2


if __name__ == "__main__":
    raise SystemExit(main())
