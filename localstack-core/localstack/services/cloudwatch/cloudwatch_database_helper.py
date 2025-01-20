import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

from localstack import config
from localstack.aws.api.cloudwatch import MetricData, MetricDataQuery, ScanBy
from localstack.utils.files import mkdir

LOG = logging.getLogger(__name__)

STAT_TO_SQLITE_AGGREGATION_FUNC = {
    "Sum": "SUM(value)",
    "Average": "SUM(value)",  # we need to calculate the avg manually as we have also a table with aggregated data
    "Minimum": "MIN(value)",
    "Maximum": "MAX(value)",
    "SampleCount": "Sum(count)",
}

STAT_TO_SQLITE_COL_NAME_HELPER = {
    "Sum": "sum",
    "Average": "sum",
    "Minimum": "min",
    "Maximum": "max",
    "SampleCount": "sample_count",
}


class CloudwatchDatabase:
    DB_NAME = "metrics.db"
    CLOUDWATCH_DATA_ROOT: str = os.path.join(config.dirs.data, "cloudwatch")
    METRICS_DB: str = os.path.join(CLOUDWATCH_DATA_ROOT, DB_NAME)
    METRICS_DB_READ_ONLY: str = f"file:{METRICS_DB}?mode=ro"
    TABLE_SINGLE_METRICS = "SINGLE_METRICS"
    TABLE_AGGREGATED_METRICS = "AGGREGATED_METRICS"
    DATABASE_LOCK: threading.RLock

    def __init__(self):
        self.DATABASE_LOCK = threading.RLock()
        if os.path.exists(self.METRICS_DB):
            LOG.debug("database for metrics already exists (%s)", self.METRICS_DB)
            return

        mkdir(self.CLOUDWATCH_DATA_ROOT)
        with self.DATABASE_LOCK, sqlite3.connect(self.METRICS_DB) as conn:
            cur = conn.cursor()
            common_columns = """
                    "id"	                INTEGER,
                    "account_id"	        TEXT,
                    "region"	            TEXT,
                    "metric_name"	        TEXT,
                    "namespace" 	        TEXT,
                    "timestamp"	            NUMERIC,
                    "dimensions"	        TEXT,
                    "unit"	                TEXT,
                    "storage_resolution"	INTEGER
                """
            cur.execute(
                f"""
                CREATE TABLE "{self.TABLE_SINGLE_METRICS}" (
                    {common_columns},
                    "value"	                NUMERIC,
                    PRIMARY KEY("id")
                );
                """
            )

            cur.execute(
                f"""
                CREATE TABLE "{self.TABLE_AGGREGATED_METRICS}" (
                    {common_columns},
                    "sample_count"          NUMERIC,
                    "sum"	                NUMERIC,
                    "min"	                NUMERIC,
                    "max"	                NUMERIC,
                    PRIMARY KEY("id")
                );
                """
            )
            # create indexes
            cur.executescript(
                """
                CREATE INDEX idx_single_metrics_comp ON SINGLE_METRICS (metric_name, namespace);
                CREATE INDEX idx_aggregated_metrics_comp ON AGGREGATED_METRICS (metric_name, namespace);
                """
            )
            conn.commit()

    def add_metric_data(
        self, account_id: str, region: str, namespace: str, metric_data: MetricData
    ):
        def _get_current_unix_timestamp_utc():
            now = datetime.utcnow().replace(tzinfo=timezone.utc)
            return int(now.timestamp())

        for metric in metric_data:
            unix_timestamp = (
                self._convert_timestamp_to_unix(metric.get("Timestamp"))
                if metric.get("Timestamp")
                else _get_current_unix_timestamp_utc()
            )

            inserts = []
            if metric.get("Value") is not None:
                inserts.append({"Value": metric.get("Value"), "TimesToInsert": 1})
            elif metric.get("Values"):
                counts = metric.get("Counts", [1] * len(metric.get("Values")))
                inserts = [
                    {"Value": value, "TimesToInsert": int(counts[indexValue])}
                    for indexValue, value in enumerate(metric.get("Values"))
                ]
            all_data = []
            for insert in inserts:
                times_to_insert = insert.get("TimesToInsert")

                data = (
                    account_id,
                    region,
                    metric.get("MetricName"),
                    namespace,
                    unix_timestamp,
                    self._get_ordered_dimensions_with_separator(metric.get("Dimensions")),
                    metric.get("Unit"),
                    metric.get("StorageResolution"),
                    insert.get("Value"),
                )
                all_data.extend([data] * times_to_insert)

            if all_data:
                with self.DATABASE_LOCK, sqlite3.connect(self.METRICS_DB) as conn:
                    cur = conn.cursor()
                    query = f"INSERT INTO {self.TABLE_SINGLE_METRICS} (account_id, region, metric_name, namespace, timestamp, dimensions, unit, storage_resolution, value) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                    cur.executemany(query, all_data)
                    conn.commit()

            if statistic_values := metric.get("StatisticValues"):
                with self.DATABASE_LOCK, sqlite3.connect(self.METRICS_DB) as conn:
                    cur = conn.cursor()
                    cur.execute(
                        f"""INSERT INTO {self.TABLE_AGGREGATED_METRICS}
                    ("account_id", "region", "metric_name", "namespace", "timestamp", "dimensions", "unit", "storage_resolution", "sample_count", "sum", "min", "max")
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            account_id,
                            region,
                            metric.get("MetricName"),
                            namespace,
                            unix_timestamp,
                            self._get_ordered_dimensions_with_separator(metric.get("Dimensions")),
                            metric.get("Unit"),
                            metric.get("StorageResolution"),
                            statistic_values.get("SampleCount"),
                            statistic_values.get("Sum"),
                            statistic_values.get("Minimum"),
                            statistic_values.get("Maximum"),
                        ),
                    )

                    conn.commit()

    def get_units_for_metric_data_stat(
        self,
        account_id: str,
        region: str,
        start_time: datetime,
        end_time: datetime,
        metric_name: str,
        namespace: str,
    ):
        # prepare SQL query
        start_time_unix = self._convert_timestamp_to_unix(start_time)
        end_time_unix = self._convert_timestamp_to_unix(end_time)

        data = (
            account_id,
            region,
            namespace,
            metric_name,
            start_time_unix,
            end_time_unix,
        )

        sql_query = f"""
        SELECT GROUP_CONCAT(unit) AS unit_values
        FROM(
            SELECT
                DISTINCT COALESCE(unit, 'NULL_VALUE') AS unit
            FROM (
                SELECT
                account_id, region, metric_name, namespace, timestamp, unit
                FROM {self.TABLE_SINGLE_METRICS}
                UNION ALL
                SELECT
                account_id, region, metric_name, namespace, timestamp, unit
                FROM {self.TABLE_AGGREGATED_METRICS}
            ) AS combined
            WHERE account_id = ? AND region = ?
            AND namespace = ? AND metric_name = ?
            AND timestamp >= ? AND timestamp < ?
        ) AS subquery
        """
        with self.DATABASE_LOCK, sqlite3.connect(self.METRICS_DB_READ_ONLY, uri=True) as conn:
            cur = conn.cursor()
            cur.execute(
                sql_query,
                data,
            )
            result_row = cur.fetchone()
            return result_row[0].split(",") if result_row[0] else ["NULL_VALUE"]

    def get_metric_data_stat(
        self,
        account_id: str,
        region: str,
        query: MetricDataQuery,
        start_time: datetime,
        end_time: datetime,
        scan_by: str,
    ) -> Dict[str, List]:
        metric_stat = query.get("MetricStat")
        metric = metric_stat.get("Metric")
        period = metric_stat.get("Period")
        stat = metric_stat.get("Stat")
        dimensions = metric.get("Dimensions", [])
        unit = metric_stat.get("Unit")

        # prepare SQL query
        start_time_unix = self._convert_timestamp_to_unix(start_time)
        end_time_unix = self._convert_timestamp_to_unix(end_time)

        data = (
            account_id,
            region,
            metric.get("Namespace"),
            metric.get("MetricName"),
        )

        dimension_filter = "AND dimensions is null " if not dimensions else "AND dimensions LIKE ? "
        if dimensions:
            data = data + (
                self._get_ordered_dimensions_with_separator(dimensions, for_search=True),
            )

        unit_filter = ""
        if unit:
            if unit == "NULL_VALUE":
                unit_filter = "AND unit IS NULL"
            else:
                unit_filter = "AND unit = ? "
                data += (unit,)

        sql_query = f"""
        SELECT
            {STAT_TO_SQLITE_AGGREGATION_FUNC[stat]},
            SUM(count)
        FROM (
            SELECT
            value, 1 as count,
            account_id, region, metric_name, namespace, timestamp, dimensions, unit, storage_resolution
            FROM {self.TABLE_SINGLE_METRICS}
            UNION ALL
            SELECT
            {STAT_TO_SQLITE_COL_NAME_HELPER[stat]} as value, sample_count as count,
            account_id, region, metric_name, namespace, timestamp, dimensions, unit, storage_resolution
            FROM {self.TABLE_AGGREGATED_METRICS}
        ) AS combined
        WHERE account_id = ? AND region = ?
        AND namespace = ? AND metric_name = ?
        {dimension_filter}
        {unit_filter}
        AND timestamp >= ? AND timestamp < ?
        ORDER BY timestamp ASC
        """

        timestamps = []
        values = []
        query_params = []

        # Prepare all the query parameters
        while start_time_unix < end_time_unix:
            next_start_time = start_time_unix + period
            query_params.append(data + (start_time_unix, next_start_time))
            start_time_unix = next_start_time

        all_results = []
        with self.DATABASE_LOCK, sqlite3.connect(self.METRICS_DB_READ_ONLY, uri=True) as conn:
            cur = conn.cursor()
            batch_size = 500
            for i in range(0, len(query_params), batch_size):
                batch = query_params[i : i + batch_size]
                cur.execute(
                    f"""
                            SELECT * FROM (
                                {" UNION ALL ".join(["SELECT * FROM (" + sql_query + ")"] * len(batch))}
                            )
                        """,
                    sum(batch, ()),  # flatten the list of tuples in batch into a single tuple
                )
                all_results.extend(cur.fetchall())

        # Process results outside the lock
        for i, result_row in enumerate(all_results):
            if result_row[1]:
                calculated_result = (
                    result_row[0] / result_row[1] if stat == "Average" else result_row[0]
                )
                timestamps.append(query_params[i][-2])  # start_time_unix
                values.append(calculated_result)

        # The while loop while always give us the timestamps in ascending order as we start with the start_time
        # and increase it by the period until we reach the end_time
        # If we want the timestamps in descending order we need to reverse the list
        if scan_by is None or scan_by == ScanBy.TimestampDescending:
            timestamps = timestamps[::-1]
            values = values[::-1]

        return {
            "timestamps": timestamps,
            "values": values,
        }

    def list_metrics(
        self,
        account_id: str,
        region: str,
        namespace: str,
        metric_name: str,
        dimensions: list[dict[str, str]],
    ) -> dict:
        data = (account_id, region)

        namespace_filter = ""
        if namespace:
            namespace_filter = " AND namespace = ?"
            data = data + (namespace,)

        metric_name_filter = ""
        if metric_name:
            metric_name_filter = " AND metric_name = ?"
            data = data + (metric_name,)

        dimension_filter = "" if not dimensions else " AND dimensions LIKE ? "
        if dimensions:
            data = data + (
                self._get_ordered_dimensions_with_separator(dimensions, for_search=True),
            )

        query = f"""
            SELECT DISTINCT metric_name, namespace, dimensions
            FROM (
                SELECT metric_name, namespace, dimensions, account_id, region, timestamp
                FROM SINGLE_METRICS
                UNION
                SELECT metric_name, namespace, dimensions, account_id, region, timestamp
                FROM AGGREGATED_METRICS
            ) AS combined
            WHERE account_id = ? AND region = ?
            {namespace_filter}
            {metric_name_filter}
            {dimension_filter}
            ORDER BY timestamp DESC
        """
        with self.DATABASE_LOCK, sqlite3.connect(self.METRICS_DB_READ_ONLY, uri=True) as conn:
            cur = conn.cursor()

            cur.execute(
                query,
                data,
            )
            metrics_result = [
                {
                    "metric_name": r[0],
                    "namespace": r[1],
                    "dimensions": self._restore_dimensions_from_string(r[2]),
                }
                for r in cur.fetchall()
            ]

            return {"metrics": metrics_result}

    def clear_tables(self):
        with self.DATABASE_LOCK, sqlite3.connect(self.METRICS_DB) as conn:
            cur = conn.cursor()
            cur.execute(f"DELETE FROM {self.TABLE_SINGLE_METRICS}")
            cur.execute(f"DELETE FROM {self.TABLE_AGGREGATED_METRICS}")
            conn.commit()
            cur.execute("VACUUM")
            conn.commit()

    def _get_ordered_dimensions_with_separator(self, dims: Optional[List[Dict]], for_search=False):
        """
        Returns a string with the dimensions in the format "Name=Value\tName=Value\tName=Value" in order to store the metric
        with the dimensions in a single column in the database

        :param dims: List of dimensions in the format [{"Name": "name", "Value": "value"}, ...]
        :param for_search: If True, the dimensions will be formatted in a way that can be used in a LIKE query to search. Default is False. Example: " %{Name}={Value}% "
        :return: String with the dimensions in the format "Name=Value\tName=Value\tName=Value"
        """
        if not dims:
            return None
        dims.sort(key=lambda d: d["Name"])
        dimensions = ""
        if not for_search:
            for d in dims:
                dimensions += f"{d['Name']}={d['Value']}\t"  # aws does not allow ascii control characters, we can use it a sa separator
        else:
            for d in dims:
                dimensions += f"%{d.get('Name')}={d.get('Value', '')}%"

        return dimensions

    def _restore_dimensions_from_string(self, dimensions: str):
        if not dimensions:
            return None
        dims = []
        for d in dimensions.split("\t"):
            if not d:
                continue
            name, value = d.split("=")
            dims.append({"Name": name, "Value": value})

        return dims

    def _convert_timestamp_to_unix(
        self, timestamp: datetime
    ):  # TODO verify if this is the standard format, might need to convert
        return int(timestamp.timestamp())

    def get_all_metric_data(self):
        with self.DATABASE_LOCK, sqlite3.connect(self.METRICS_DB_READ_ONLY, uri=True) as conn:
            cur = conn.cursor()
            """ shape for each data entry:
                    {
                        "ns": r.namespace,
                        "n": r.name,
                        "v": r.value,
                        "t": r.timestamp,
                        "d": [{"n": d.name, "v": d.value} for d in r.dimensions],
                        "account": account-id, # new for v2
                        "region": region_name, # new for v2
                    }
                    """
            query = f"SELECT namespace, metric_name, value, timestamp, dimensions, account_id, region from {self.TABLE_SINGLE_METRICS}"
            cur.execute(query)
            metrics_result = [
                {
                    "ns": r[0],
                    "n": r[1],
                    "v": r[2],
                    "t": r[3],
                    "d": r[4],
                    "account": r[5],
                    "region": r[6],
                }
                for r in cur.fetchall()
            ]
            # TODO add aggregated metrics (was not handled by v1 either)
            return metrics_result
