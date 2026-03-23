"""Client for querying ClickHouse data via the data-query service."""

from __future__ import annotations

import re
from collections.abc import Generator
from typing import Any

import requests


class DataQueryError(Exception):
    """Raised when a data-query request fails."""

    def __init__(self, message: str, error_type: str | None = None):
        super().__init__(message)
        self.error_type = error_type


class DataQueryClient:
    """
    Interface for querying ClickHouse via the data-query service.

    Uses ``get_service_url`` from the connector template to resolve the
    data-query endpoint across all deployment modes (local, Kubernetes, OpenFaaS).

    Usage::

        from data_query import DataQueryClient

        # Inside your handler, pass the context object:
        db = DataQueryClient(context)

        # Simple query
        rows = db.query("SELECT * FROM access_analyzer.user LIMIT 10")

        # Query with pagination
        for page in db.paginate("SELECT * FROM access_analyzer.user", page_size=500):
            for row in page:
                process(row)

        # Count rows
        total = db.count("SELECT * FROM access_analyzer.user WHERE is_deleted = 0")

        # Get a single row (or None)
        row = db.query_one("SELECT * FROM access_analyzer.user WHERE object_guid = 'abc'")

        # Resolve a fully-qualified table name from a short name
        table = db.resolve_table_name("user")  # e.g. "access_analyzer.active_directory_user"
    """

    def __init__(
        self,
        context: Any,
        service_name: str = "data-query",
        timeout: int = 300,
        database: str = "access_analyzer",
    ):
        self._context = context
        self._service_name = service_name
        self._timeout = timeout
        self._database = database
        self._url = self._resolve_url()

    def _resolve_url(self) -> str:
        """Resolve the data-query service URL using the template's get_service_url."""
        # Lazy import to avoid circular imports at module load time.
        # At runtime, /home/app/ (where index.py lives) is on sys.path
        # because index.py is the main entry point.
        from index import get_service_url  # type: ignore[import-untyped]

        return get_service_url(self._service_name)

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if hasattr(self._context, "get_caller_headers"):
            headers.update(self._context.get_caller_headers())
        return headers

    def resolve_table_name(self, short_name: str) -> str:
        """Build a fully-qualified ClickHouse table name."""
        source_type = self._context.source_type
        return f"{self._database}.{source_type}_{short_name}".replace("-", "_")

    def query(self, sql: str) -> list[dict[str, Any]]:
        """
        Execute a SELECT query and return all result rows.

        Args:
            sql: A SELECT query string.

        Returns:
            List of dicts, one per row, keyed by column name.

        Raises:
            DataQueryError: On HTTP or query-level failure.
        """
        response = requests.post(
            self._url,
            json={"query": sql},
            headers=self._headers(),
            timeout=self._timeout,
        )

        if response.status_code != 200:
            raise DataQueryError(
                f"data-query returned HTTP {response.status_code}: {response.text[:500]}"
            )

        result = response.json()
        if not result.get("success"):
            raise DataQueryError(
                result.get("error", "Unknown error"),
                error_type=result.get("error_type"),
            )

        return result.get("data", [])

    def query_one(self, sql: str) -> dict[str, Any] | None:
        """
        Execute a query and return the first row, or ``None`` if empty.

        A ``LIMIT 1`` is appended automatically if the query does not already
        contain one.
        """
        if not re.search(r"\bLIMIT\b", sql, re.IGNORECASE):
            sql = f"{sql.rstrip().rstrip(';')} LIMIT 1"

        rows = self.query(sql)
        return rows[0] if rows else None

    def count(self, sql: str) -> int:
        """
        Convert a SELECT query to ``SELECT count(*)`` and return the count.

        Args:
            sql: A SELECT query (the column list will be replaced).

        Returns:
            Integer count of matching rows.
        """
        count_sql = self._to_count_query(sql)
        rows = self.query(count_sql)
        if rows:
            first_row = rows[0]
            return int(next(iter(first_row.values())))
        return 0

    def paginate(
        self, sql: str, page_size: int = 1000
    ) -> Generator[list[dict[str, Any]]]:
        """
        Yield pages of results for a query, automatically handling LIMIT/OFFSET.

        Args:
            sql: A SELECT query (any existing LIMIT/OFFSET is stripped).
            page_size: Number of rows per page.

        Yields:
            Lists of dicts, one list per page, until an empty page is returned.
        """
        base_sql = re.sub(
            r"\bLIMIT\s+\d+(\s+OFFSET\s+\d+)?",
            "",
            sql,
            flags=re.IGNORECASE,
        ).strip().rstrip(";")

        offset = 0
        while True:
            page_sql = f"{base_sql} LIMIT {page_size} OFFSET {offset}"
            rows = self.query(page_sql)
            if not rows:
                break
            yield rows
            if len(rows) < page_size:
                break
            offset += page_size

    def paginate_consuming(
        self, sql: str, page_size: int = 1000
    ) -> Generator[list[dict[str, Any]]]:
        """
        Yield pages by repeatedly executing the same query with only a LIMIT.

        Unlike ``paginate``, this method does not use OFFSET. It is intended
        for callers that mutate the result set between pages (e.g. by flushing
        hard-delete markers) so that already-processed rows no longer appear
        in subsequent fetches.

        Args:
            sql: A SELECT query (any existing LIMIT/OFFSET is stripped).
            page_size: Number of rows per page.

        Yields:
            Lists of dicts, one list per page, until an empty page is returned.
        """
        base_sql = re.sub(
            r"\bLIMIT\s+\d+(\s+OFFSET\s+\d+)?",
            "",
            sql,
            flags=re.IGNORECASE,
        ).strip().rstrip(";")
        page_sql = f"{base_sql} LIMIT {page_size}"

        stall_count = 0
        stall_limit = 3
        prev_count: int | None = None

        while True:
            rows = self.query(page_sql)
            if not rows:
                break
            yield rows
            if len(rows) < page_size:
                # Partial page — no more rows, skip COUNT entirely
                break

            # Full page returned after caller flush; count remaining rows
            # to detect stalls. Comparison starts on the second full page.
            current_count = self.count(base_sql)
            if current_count == 0:
                break
            if prev_count is not None and current_count >= prev_count:
                stall_count += 1
                if stall_count >= stall_limit:
                    raise DataQueryError(
                        f"paginate_consuming: row count has not decreased for {stall_limit} "
                        f"consecutive iterations (count={current_count}) — rows may not be draining"
                    )
            else:
                stall_count = 0
            prev_count = current_count

    @staticmethod
    def _to_count_query(sql: str) -> str:
        """Replace the SELECT columns with ``count(*)``."""
        from_match = re.search(r"\bFROM\b", sql, re.IGNORECASE)
        if not from_match:
            raise DataQueryError("Cannot build count query: no FROM clause found")
        return f"SELECT count(*) {sql[from_match.start():]}"
