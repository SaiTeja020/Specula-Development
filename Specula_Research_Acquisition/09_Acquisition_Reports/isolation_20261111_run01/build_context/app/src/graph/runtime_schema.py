"""Apply the repository-owned idempotent schema before runtime graph writes."""
from pathlib import Path


def apply_runtime_schema(driver):
    text=(Path(__file__).parent/'schema_constraints.cypher').read_text(encoding='utf-8')
    statements=['\n'.join(line for line in part.splitlines() if not line.strip().startswith('//')).strip()
                for part in text.split(';')]
    with driver.session() as session:
        for query in statements:
            if query:session.run(query).consume()
