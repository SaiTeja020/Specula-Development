from datetime import datetime, timezone
import logging
from typing import List, Generator
from google.cloud import logging_v2

logger = logging.getLogger("GCPAuditFetcher")

class GCPAuditFetcher:
    def __init__(self, project_id: str, credentials_path: str = None):
        self.project_id = project_id
        if credentials_path:
            self.client = logging_v2.Client.from_service_account_json(credentials_path, project=project_id)
        else:
            self.client = logging_v2.Client(project=project_id)

    def fetch_audit_logs(
        self,
        start_time: datetime,
        end_time: datetime = None,
        page_size: int = 500
    ) -> Generator[dict, None, None]:
        """
        Yields raw GCP Audit Log entries within an explicit historical window.
        """
        if end_time is None:
            end_time = datetime.now(timezone.utc)

        start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        filter_expr = (
            f'logName:"cloudaudit.googleapis.com" AND '
            f'timestamp >= "{start_str}" AND timestamp <= "{end_str}"'
        )

        entries = self.client.list_entries(
            resource_names=[f"projects/{self.project_id}"],
            filter_=filter_expr,
            page_size=page_size
        )

        for entry in entries:
            # Yield raw unmutated dict/JSON for SIMD hashing & preservation
            if hasattr(entry, "to_api_repr"):
                yield entry.to_api_repr()
            elif hasattr(entry, "to_dict"):
                yield entry.to_dict()
            else:
                yield dict(entry)
