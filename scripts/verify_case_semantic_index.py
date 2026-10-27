"""Real local semantic indexing/query/isolation oracle; removes only its test IDs."""
from uuid import uuid4
from src.ingestion.indexing.case_evidence import CaseEvidenceIndex


def main():
    index = CaseEvidenceIndex()
    prefix = "semantic-oracle-"+uuid4().hex
    a,b = prefix+"A",prefix+"B"
    try:
        rows = [{"uid": prefix+"ps", "summary": "Encoded PowerShell process execution on Windows"},
                {"uid": prefix+"cloud", "summary": "Google Cloud IAM service account key creation"},
                {"uid": prefix+"backup", "summary": "Scheduled database backup completed normally"}]
        assert index.index(a, rows)["stored"] == 3
        assert index.index(b, rows[:1])["stored"] == 1
        result = index.retrieve_similar_events("Windows PowerShell encoded command", case_id=a, top_k=1)
        assert result["results"][0]["citation_uid"] == prefix+"ps"
        assert result["results"][0]["metadata"]["case_id"] == a
        print("PASS: real semantic vectors/write receipt, closest PowerShell citation, shared UID case isolation; model="+index.embedder.model)
    finally:
        for case in (a,b):
            ids = index.collection.get(where={"case_id": case}, include=[])['ids']
            if ids:
                index.collection.delete(ids=ids)


if __name__ == "__main__":
    main()
