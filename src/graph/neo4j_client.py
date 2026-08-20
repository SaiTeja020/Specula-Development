"""
Specula Neo4j Driver Wrapper.

Provides a thin, lifecycle-managed client around the neo4j Python driver.
All Cypher execution goes through this class — no agent or pipeline code
touches the driver directly.

Configuration via environment variables:
    NEO4J_URI       bolt://localhost:7687  (default)
    NEO4J_USER      neo4j                 (default)
    NEO4J_PASSWORD  ""                    (default — matches NEO4J_AUTH=none in docker-compose)

Reference: specula_ingestion_final_plan.md §8.1
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("Neo4jClient")

# ---------------------------------------------------------------------------
# Configuration — overridable via environment variables
# ---------------------------------------------------------------------------
NEO4J_URI: str = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER: str = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD: str = os.environ.get("NEO4J_PASSWORD", "")


class Neo4jClientError(Exception):
    """Raised when a Neo4j operation fails."""
    pass


class Neo4jClient:
    """
    Lifecycle-managed Neo4j driver wrapper.

    Supports both authenticated and no-auth modes (NEO4J_AUTH=none in dev).
    Use as a context manager or call close() explicitly.

    Example:
        client = Neo4jClient()
        client.execute(query, params)
        client.close()
    """

    def __init__(
        self,
        uri: str = NEO4J_URI,
        user: str = NEO4J_USER,
        password: str = NEO4J_PASSWORD,
    ):
        self.uri = uri
        self.user = user
        self.password = password
        self._driver = None
        self._connect()

    def _connect(self) -> None:
        """Initialize the neo4j driver. Lazy-imports neo4j to avoid import errors
        when the package is not installed and Neo4j is not enabled."""
        try:
            from neo4j import GraphDatabase
        except ImportError as e:
            raise Neo4jClientError(
                "neo4j package is not installed. "
                "Run: pip install 'neo4j>=5.14.1'"
            ) from e

        # NEO4J_AUTH=none in docker-compose: connect with no password (auth=None)
        # Authenticated mode: pass (user, password) tuple
        auth = (self.user, self.password) if self.password else None

        try:
            self._driver = GraphDatabase.driver(self.uri, auth=auth)
            # Verify connectivity immediately
            self._driver.verify_connectivity()
            logger.info(f"Neo4j connected: {self.uri}")
        except Exception as e:
            raise Neo4jClientError(
                f"Failed to connect to Neo4j at {self.uri}: {e}"
            ) from e

    # ------------------------------------------------------------------
    # Write path
    # ------------------------------------------------------------------

    def execute(self, query: str, params: Optional[Dict[str, Any]] = None) -> List[Dict]:
        """
        Execute a parameterized Cypher write query in a new session.

        Args:
            query:  Parameterized Cypher string (no string concatenation allowed).
            params: Parameter dict bound to the query.

        Returns:
            List of result record dicts.

        Raises:
            Neo4jClientError: On driver-level or query execution failure.
        """
        params = params or {}
        try:
            with self._driver.session() as session:
                result = session.run(query, **params)
                return [dict(record) for record in result]
        except Exception as e:
            raise Neo4jClientError(
                f"Cypher write failed: {e}\nQuery: {query[:200]}"
            ) from e

    # ------------------------------------------------------------------
    # Read path
    # ------------------------------------------------------------------

    def execute_read(self, query: str, params: Optional[Dict[str, Any]] = None) -> List[Dict]:
        """
        Execute a parameterized Cypher read query in a read-only session.

        Args:
            query:  Parameterized Cypher string.
            params: Parameter dict bound to the query.

        Returns:
            List of result record dicts.
        """
        params = params or {}
        try:
            with self._driver.session() as session:
                result = session.run(query, **params)
                return [dict(record) for record in result]
        except Exception as e:
            raise Neo4jClientError(
                f"Cypher read failed: {e}\nQuery: {query[:200]}"
            ) from e

    # ------------------------------------------------------------------
    # Schema lifecycle
    # ------------------------------------------------------------------

    def apply_schema(self, cypher_file_path: str) -> int:
        """
        Apply a Cypher schema file to Neo4j — splits on ';' and runs each statement.

        Skips blank lines and `//`-style comments. All constraint/index statements
        should use `IF NOT EXISTS` to be idempotent.

        Args:
            cypher_file_path: Absolute or relative path to the .cypher file.

        Returns:
            Number of statements executed.

        Raises:
            Neo4jClientError: If any statement fails.
            FileNotFoundError: If the cypher file does not exist.
        """
        path = Path(cypher_file_path)
        if not path.exists():
            raise FileNotFoundError(f"Cypher schema file not found: {cypher_file_path}")

        raw = path.read_text(encoding="utf-8")

        # Split on semicolons, strip comments and whitespace
        statements = []
        for raw_stmt in raw.split(";"):
            # Remove comment lines (lines starting with //)
            lines = [
                line for line in raw_stmt.splitlines()
                if not line.strip().startswith("//")
            ]
            stmt = "\n".join(lines).strip()
            if stmt:
                statements.append(stmt)

        executed = 0
        for stmt in statements:
            try:
                with self._driver.session() as session:
                    session.run(stmt)
                    executed += 1
                    logger.debug(f"Schema statement applied: {stmt[:80]}...")
            except Exception as e:
                raise Neo4jClientError(
                    f"Schema statement failed: {e}\nStatement: {stmt[:200]}"
                ) from e

        logger.info(f"Applied {executed} schema statements from: {cypher_file_path}")
        return executed

    # ------------------------------------------------------------------
    # Health & lifecycle
    # ------------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        """
        Verify connectivity and return server info.

        Returns:
            Dict with 'status', 'uri', and 'server_info' keys.

        Raises:
            Neo4jClientError: If connectivity check fails.
        """
        try:
            info = self._driver.get_server_info()
            return {
                "status": "connected",
                "uri": self.uri,
                "server_info": str(info),
            }
        except Exception as e:
            raise Neo4jClientError(f"Neo4j health check failed: {e}") from e

    def close(self) -> None:
        """Close the driver and release all connections."""
        if self._driver is not None:
            self._driver.close()
            self._driver = None
            logger.info("Neo4j driver closed.")

    def __enter__(self) -> "Neo4jClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
