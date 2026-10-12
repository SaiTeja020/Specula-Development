"""Check live dual report delivery for a saved local case and retain review copies."""
import argparse
from hashlib import sha256
from pathlib import Path
import re

import requests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("case_id")
    args = parser.parse_args()
    if not re.fullmatch(r"LOCAL-[a-f0-9]{32}", args.case_id):
        raise ValueError("Expected a local case UUID")
    directory = Path(__file__).resolve().parents[1] / "data" / "report_review" / args.case_id
    directory.mkdir(parents=True, exist_ok=True)
    headers = {"Origin": "http://localhost:5173", "X-Specula-Local-Boot": "1"}
    with requests.Session() as client:
        client.trust_env = False
        for kind in ("court", "technical"):
            response = client.get(f"http://127.0.0.1:8400/api/local/cases/{args.case_id}/reports/{kind}",
                                  headers=headers, timeout=45)
            response.raise_for_status()
            assert response.headers["X-Report-SHA256"] == sha256(response.content).hexdigest()
            assert '<!doctype html>' in response.text and 'End of report' in response.text
            if kind == "court":
                assert "NOT CERTIFIED" in response.text and "UNSIGNED" in response.text
            path = directory / f"{kind}.html"
            path.write_bytes(response.content)
            print(f"{kind}: HTTP {response.status_code}, SHA-256 verified, {len(response.content)} bytes; {path}")
        response = client.post("http://127.0.0.1:8400/api/local/investigations/upload",
                               headers={**headers, "Content-Type": "application/zip"}, data=b"not a zip", timeout=10)
        assert response.status_code == 422
        print("Invalid archive rejected with HTTP 422")


if __name__ == "__main__":
    main()
