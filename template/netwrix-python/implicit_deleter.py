"""Mark stale rows with hard_delete=1 after a full scan.

During a full scan every current object is inserted into ClickHouse.
Objects that existed in a previous scan but are no longer present simply don't
get re-inserted.  ImplicitDeleter runs at the end of a full scan and writes
``hard_delete=1`` rows for any records whose ``scan_execution_id`` differs from
the current execution.
"""

from __future__ import annotations

from typing import Any

from data_query import DataQueryClient, DataQueryError


class ImplicitDeleter:
    """Insert hard-delete markers for rows not touched by the current scan execution."""

    def __init__(self, context: Any, database: str = "access_analyzer"):
        self._context = context
        self._db = DataQueryClient(context)
        self._table_prefix = f"{context.source_type}_".replace("-", "_")
        self._database = database

    def perform_implicit_delete(self, tables: list[str]) -> None:
        """Mark stale rows in each *table* with ``hard_delete=1``.

        Each table is processed independently — a failure on one table is
        logged and does not prevent the remaining tables from being processed.
        """
        scan_id = self._context.scan_id
        scan_execution_id = self._context.scan_execution_id
        for table in tables:
            full_table_name = f"{self._table_prefix}{table}".replace("-", "_")
            try:
                self._process_table(table, full_table_name, scan_id, scan_execution_id)
            except DataQueryError as exc:
                self._context.log.warning(
                    "Implicit delete failed for table",
                    table=full_table_name,
                    error=str(exc),
                )
            except Exception as exc:
                self._context.log.warning(
                    "Unexpected error during implicit delete",
                    table=full_table_name,
                    error=str(exc),
                )

    def _process_table(
        self,
        short_table_name: str,
        full_table_name: str,
        scan_id: str,
        scan_execution_id: str,
    ) -> None:
        # --- 1. Validate table engine and required columns -------------------
        safe_table_name = full_table_name.replace("'", "''")
        safe_database = self._database.replace("'", "''")
        meta_sql = (
            f"SELECT t.engine as engine, c.name as name, c.type as type, "
            f"c.is_in_sorting_key as is_in_sorting_key, c.is_in_partition_key as is_in_partition_key "
            f"FROM system.tables AS t "
            f"JOIN system.columns AS c ON t.database = c.database AND t.name = c.table "
            f"WHERE t.database = '{safe_database}' AND t.name = '{safe_table_name}'"
        )
        self._context.log.info("Querying table metadata", table=full_table_name, query=meta_sql)
        meta_rows = self._db.query(meta_sql)

        if not meta_rows:
            self._context.log.warning(
                "Table not found or has no columns",
                table=full_table_name,
            )
            return

        engine = meta_rows[0].get("engine", "")
        if "ReplacingMergeTree" not in engine:
            self._context.log.warning(
                "Skipping table — engine is not ReplacingMergeTree",
                table=full_table_name,
                engine=engine,
            )
            return

        required_columns = {"hard_delete", "scan_id", "scan_execution_id"}
        found_columns: set[str] = set()
        key_columns: list[str] = []

        for row in meta_rows:
            col_name = row["name"]
            col_type = row.get("type", "")

            if (col_name == "hard_delete" and col_type in ("Bool", "UInt8")) or col_name in required_columns:
                found_columns.add(col_name)

            if (row.get("is_in_sorting_key") or row.get("is_in_partition_key")) and col_name not in key_columns:
                key_columns.append(col_name)

        missing = required_columns - found_columns
        if missing:
            self._context.log.warning(
                "Skipping table — missing required columns",
                table=full_table_name,
                missing_columns=sorted(missing),
            )
            return

        if not key_columns:
            self._context.log.warning(
                "Skipping table — no sorting or partition key columns found",
                table=full_table_name,
            )
            return

        # Flush any buffered objects
        self._context.flush_tables()

        # --- 2. Query stale rows and re-insert with hard_delete=1 -----------
        key_cols_str = ", ".join(f"`{col}`" if "'" in col else col for col in key_columns)
        safe_scan_id = scan_id.replace("'", "''")
        safe_exec_id = scan_execution_id.replace("'", "''")
        select_sql = (
            f"SELECT {key_cols_str} FROM {safe_table_name} FINAL "
            f"WHERE scan_id = '{safe_scan_id}' AND scan_execution_id != '{safe_exec_id}'"
        )

        self._context.log.info(
            "Querying stale rows",
            table=full_table_name,
            key_columns=key_cols_str,
            query=select_sql,
        )

        total_deleted = 0
        found_any = False
        for page in self._db.paginate_consuming(select_sql, page_size=10_000):
            found_any = True
            self._context.log.info(
                "Inserting hard deletes",
                table=full_table_name,
                page_count=len(page),
            )
            for row in page:
                row["hard_delete"] = 1
                self._context.save_object(short_table_name, row, update_status=False)
            total_deleted += len(page)
            self._context.flush_tables()

        if not found_any:
            self._context.log.info("No stale rows found", table=full_table_name)
            return

        self._context.log.info(
            "Implicit delete completed",
            table=full_table_name,
            deleted_count=total_deleted,
        )
