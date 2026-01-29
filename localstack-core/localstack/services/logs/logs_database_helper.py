import logging
import os
import sqlite3
import threading
from typing import Any

from localstack import config
from localstack.utils.files import mkdir

LOG = logging.getLogger(__name__)


class LogsDatabaseHelper:
    DB_NAME = "logs.db"
    LOGS_DATA_ROOT: str = os.path.join(config.dirs.data, "logs")
    LOGS_DB: str = os.path.join(LOGS_DATA_ROOT, DB_NAME)
    LOGS_DB_READ_ONLY: str = f"file:{LOGS_DB}?mode=ro"
    TABLE_LOG_EVENTS = "LOG_EVENTS"
    DATABASE_LOCK: threading.RLock

    def __init__(self):
        self.lock = threading.RLock()
        if os.path.exists(self.LOGS_DB):
            LOG.debug("database for logs already exists (%s)", self.LOGS_DB)
            return
        mkdir(self.LOGS_DATA_ROOT)
        self._create_tables()

    def _get_connection(self):
        return sqlite3.connect(self.LOGS_DB, check_same_thread=False)

    def _create_tables(self):
        with self.lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self.TABLE_LOG_EVENTS} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    log_group_name TEXT NOT NULL,
                    log_stream_name TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    message TEXT NOT NULL,
                    region TEXT NOT NULL,
                    account_id TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def put_log_events(
        self,
        log_group_name: str,
        log_stream_name: str,
        log_events: list[dict[str, Any]],
        region: str,
        account_id: str,
    ) -> list[dict[str, Any]]:
        with self.lock, self._get_connection() as conn:
            cursor = conn.cursor()
            for event in log_events:
                cursor.execute(
                    f"INSERT INTO {self.TABLE_LOG_EVENTS} (log_group_name, log_stream_name, timestamp, message, region, account_id) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        log_group_name,
                        log_stream_name,
                        event["timestamp"],
                        event["message"],
                        region,
                        account_id,
                    ),
                )
                event_id = cursor.lastrowid
                event["id"] = str(event_id)
            conn.commit()
            return log_events

    def get_log_events(
        self,
        log_group_name: str,
        log_stream_name: str,
        region: str,
        account_id: str,
        start_time: int | None = None,
        end_time: int | None = None,
        limit: int | None = None,
        start_from_head: bool | None = False,
    ) -> list[dict[str, Any]]:
        with self.lock, self._get_connection() as conn:
            cursor = conn.cursor()
            query = f"""
                SELECT timestamp, message
                FROM {self.TABLE_LOG_EVENTS}
                WHERE log_group_name = ? AND log_stream_name = ? AND region = ? AND account_id = ?
            """
            params = [log_group_name, log_stream_name, region, account_id]

            if start_time is not None:
                query += " AND timestamp >= ?"
                params.append(start_time)
            if end_time is not None:
                query += " AND timestamp <= ?"
                params.append(end_time)

            if start_from_head:
                query += " ORDER BY timestamp ASC"
            else:
                query += " ORDER BY timestamp DESC"

            if limit is not None:
                query += " LIMIT ?"
                params.append(limit)

            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()

            return [{"timestamp": row[0], "message": row[1]} for row in rows]

    def filter_log_events(
        self,
        log_group_name: str,
        region: str,
        account_id: str,
        log_stream_names: list[str] | None = None,
        start_time: int | None = None,
        end_time: int | None = None,
        filter_pattern: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        with self.lock, self._get_connection() as conn:
            cursor = conn.cursor()
            query = f"""
                SELECT id, log_stream_name, timestamp, message
                FROM {self.TABLE_LOG_EVENTS}
                WHERE log_group_name = ? AND region = ? AND account_id = ?
            """
            params = [log_group_name, region, account_id]

            if log_stream_names:
                placeholders = ",".join(["?"] * len(log_stream_names))
                query += f" AND log_stream_name IN ({placeholders})"
                params.extend(log_stream_names)
            if start_time is not None:
                query += " AND timestamp >= ?"
                params.append(start_time)
            if end_time is not None:
                query += " AND timestamp <= ?"
                params.append(end_time)
            if filter_pattern:
                query += " AND message LIKE ?"
                params.append(f"%{filter_pattern}%")  # Basic "contains" filtering

            query += " ORDER BY timestamp DESC"

            if limit is not None:
                query += " LIMIT ?"
                params.append(limit)

            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()

            return [
                {
                    "logStreamName": row[1],
                    "timestamp": row[2],
                    "message": row[3],
                    "id": f"{row[0]}",  # Simple eventId for now
                }
                for row in rows
            ]

    def clear_tables(self):
        with self.DATABASE_LOCK, sqlite3.connect(self.LOGS_DB) as conn:
            cur = conn.cursor()
            cur.execute(f"DELETE FROM {self.TABLE_LOG_EVENTS}")
            conn.commit()
            cur.execute("VACUUM")
            conn.commit()
