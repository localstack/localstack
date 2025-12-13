import sqlite3
import threading
from typing import List, Optional, Dict, Any


class DatabaseHelper:
    def __init__(self, db_file: str):
        self.db_file = db_file
        self.lock = threading.RLock()
        self._create_tables()

    def _get_connection(self):
        return sqlite3.connect(self.db_file, check_same_thread=False)

    def _create_tables(self):
        with self.lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS log_groups (
                    arn TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    region TEXT NOT NULL,
                    account_id TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS log_streams (
                    arn TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    log_group_name TEXT NOT NULL,
                    region TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    FOREIGN KEY (log_group_name) REFERENCES log_groups (name) ON DELETE CASCADE
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS log_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    log_group_name TEXT NOT NULL,
                    log_stream_name TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    message TEXT NOT NULL,
                    region TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    FOREIGN KEY (log_group_name) REFERENCES log_groups (name) ON DELETE CASCADE,
                    FOREIGN KEY (log_stream_name) REFERENCES log_streams (name) ON DELETE CASCADE
                )
                """
            )
            conn.commit()

    def _log_group_exists(self, log_group_name: str, region: str, account_id: str) -> bool:
        with self.lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM log_groups WHERE name = ? AND region = ? AND account_id = ?",
                (log_group_name, region, account_id),
            )
            return cursor.fetchone() is not None

    def _log_stream_exists(self, log_stream_name: str, log_group_name: str, region: str, account_id: str) -> bool:
        with self.lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM log_streams WHERE name = ? AND log_group_name = ? AND region = ? AND account_id = ?",
                (log_stream_name, log_group_name, region, account_id),
            )
            return cursor.fetchone() is not None

    def create_log_group(self, arn: str, log_group_name: str, region: str, account_id: str):
        if self._log_group_exists(log_group_name, region, account_id):
            raise ValueError("ResourceAlreadyExistsException")
        with self.lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO log_groups (arn, name, region, account_id) VALUES (?, ?, ?, ?)",
                (arn, log_group_name, region, account_id),
            )
            conn.commit()

    def describe_log_groups(self, region: str, account_id: str) -> List[Dict[str, str]]:
        with self.lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT arn, name FROM log_groups WHERE region = ? AND account_id = ?",
                (region, account_id),
            )
            rows = cursor.fetchall()
            return [{"arn": row[0], "logGroupName": row[1]} for row in rows]

    def delete_log_group(self, log_group_name: str, region: str, account_id: str):
        if not self._log_group_exists(log_group_name, region, account_id):
            raise ValueError("ResourceNotFoundException")
        with self.lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM log_groups WHERE name = ? AND region = ? AND account_id = ?",
                (log_group_name, region, account_id),
            )
            conn.commit()

    def create_log_stream(self, arn: str, log_stream_name: str, log_group_name: str, region: str, account_id: str):
        if not self._log_group_exists(log_group_name, region, account_id):
            raise ValueError("ResourceNotFoundException")
        if self._log_stream_exists(log_stream_name, log_group_name, region, account_id):
            raise ValueError("ResourceAlreadyExistsException")
        with self.lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO log_streams (arn, name, log_group_name, region, account_id) VALUES (?, ?, ?, ?, ?)",
                (
                    arn,
                    log_stream_name,
                    log_group_name,
                    region,
                    account_id,
                ),
            )
            conn.commit()

    def describe_log_streams(
        self, log_group_name: str, region: str, account_id: str
    ) -> List[Dict[str, str]]:
        if not self._log_group_exists(log_group_name, region, account_id):
            raise ValueError("ResourceNotFoundException")
        with self.lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT arn, name FROM log_streams WHERE log_group_name = ? AND region = ? AND account_id = ?",
                (log_group_name, region, account_id),
            )
            rows = cursor.fetchall()
            return [{"arn": row[0], "logStreamName": row[1]} for row in rows]

    def delete_log_stream(self, log_group_name: str, log_stream_name: str, region: str, account_id: str):
        if not self._log_stream_exists(log_stream_name, log_group_name, region, account_id):
            raise ValueError("ResourceNotFoundException")
        with self.lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM log_streams WHERE name = ? AND log_group_name = ? AND region = ? AND account_id = ?",
                (log_stream_name, log_group_name, region, account_id),
            )
            conn.commit()

    def put_log_events(
        self,
        log_group_name: str,
        log_stream_name: str,
        log_events: List[Dict[str, Any]],
        region: str,
        account_id: str,
    ):
        if not self._log_stream_exists(log_stream_name, log_group_name, region, account_id):
            raise ValueError("ResourceNotFoundException")
        with self.lock, self._get_connection() as conn:
            cursor = conn.cursor()
            for event in log_events:
                cursor.execute(
                    "INSERT INTO log_events (log_group_name, log_stream_name, timestamp, message, region, account_id) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        log_group_name,
                        log_stream_name,
                        event["timestamp"],
                        event["message"],
                        region,
                        account_id,
                    ),
                )
            conn.commit()

    def get_log_events(
        self,
        log_group_name: str,
        log_stream_name: str,
        region: str,
        account_id: str,
        start_time: Optional[int] = None,
        end_time: Optional[int] = None,
        limit: Optional[int] = None,
        start_from_head: Optional[bool] = False,
    ) -> List[Dict[str, Any]]:
        if not self._log_stream_exists(log_stream_name, log_group_name, region, account_id):
            raise ValueError("ResourceNotFoundException")
        with self.lock, self._get_connection() as conn:
            cursor = conn.cursor()
            query = """
                SELECT timestamp, message
                FROM log_events
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
        log_stream_names: Optional[List[str]] = None,
        start_time: Optional[int] = None,
        end_time: Optional[int] = None,
        filter_pattern: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        if not self._log_group_exists(log_group_name, region, account_id):
            raise ValueError("ResourceNotFoundException")

        with self.lock, self._get_connection() as conn:
            cursor = conn.cursor()
            query = """
                SELECT log_stream_name, timestamp, message
                FROM log_events
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
                params.append(f"%{filter_pattern}%") # Basic "contains" filtering

            query += " ORDER BY timestamp DESC"

            if limit is not None:
                query += " LIMIT ?"
                params.append(limit)

            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()

            return [
                {
                    "logStreamName": row[0],
                    "timestamp": row[1],
                    "message": row[2],
                    "eventId": f"{row[0]}-{row[1]}", # Simple eventId for now
                }
                for row in rows
            ]


db_helper = DatabaseHelper("logs.db")