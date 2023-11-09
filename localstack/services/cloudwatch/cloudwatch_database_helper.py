import logging
import os
import sqlite3
from datetime import datetime, timezone
from typing import Dict, List, Optional

from localstack import config
from localstack.aws.api.cloudwatch import MetricData, MetricStat, ScanBy
from localstack.utils.files import mkdir

LOG = logging.getLogger(__name__)

STAT_TO_SQLITE_FUNC = {
    "Sum": "SUM(value)",
    "Average": "AVG(value)",
    "Minimum": "MIN(value)",
    "Maximum": "MAX(value)",
    "SampleCount": "COUNT(value)",
}

STAT_TO_SQLITE_COLUMNS = {
    "Sum": "sum",
    "Average": "sum, sample_count",
    "Minimum": "min",
    "Maximum": "max",
    "SampleCount": "sample_count",
}


class CloudwatchDatabase:
    DB_NAME = "metrics.db"
    CLOUDWATCH_DATA_ROOT: str = os.path.join(config.dirs.data, "cloudwatch")
    METRICS_DB: str = os.path.join(CLOUDWATCH_DATA_ROOT, DB_NAME)
    TABLE_SINGLE_METRICS = "SINGLE_METRICS"
    TABLE_AGGREGATED_METRICS = "AGGREGATED_METRICS"

    def __init__(self):
        if os.path.exists(self.METRICS_DB):
            LOG.debug(f"database for metrics already exists ({self.METRICS_DB})")
            return

        mkdir(self.CLOUDWATCH_DATA_ROOT)
        with sqlite3.connect(self.METRICS_DB, isolation_level="EXCLUSIVE") as conn:
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
        # TODO consider using thread-lock here instead of increasing busy-timeout
        with sqlite3.connect(self.METRICS_DB, isolation_level="EXCLUSIVE") as conn:
            conn.execute(
                "PRAGMA busy_timeout = 20000"
            )  # TODO check if we need to set timeout higher, testing with 20 seconds
            cur = conn.cursor()

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
                if metric.get("Value"):
                    inserts.append({"Value": metric.get("Value"), "TimesToInsert": 1})
                elif metric.get("Values"):
                    inserts = [
                        {"Value": value, "TimesToInsert": int(metric.get("Counts")[indexValue])}
                        for indexValue, value in enumerate(metric.get("Values"))
                    ]

                for insert in inserts:
                    for _ in range(insert.get("TimesToInsert")):
                        cur.execute(
                            self._get_insert_single_metric_query(),
                            (
                                account_id,
                                region,
                                metric.get("MetricName"),
                                namespace,
                                unix_timestamp,
                                self._get_ordered_dimensions_with_separator(
                                    metric.get("Dimensions")
                                ),
                                metric.get("Unit"),
                                metric.get("StorageResolution"),
                                insert.get("Value"),
                            ),
                        )

                if statistic_values := metric.get("StatisticValues"):
                    cur.execute(
                        self._get_insert_aggregated_metric_query(),
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

    def get_metric_data_stat(
        self,
        account_id: str,
        region: str,
        query: MetricStat,
        start_time: datetime,
        end_time: datetime,
        scan_by: str,
    ):
        # TODO exclude null values, check if dimensions must be null though if missing
        # TODO test default order
        # TODO add filters for dimensions
        # TODO add filters for unit

        with sqlite3.connect(self.METRICS_DB) as conn:
            cur = conn.cursor()
            metric_stat = query.get("MetricStat")
            metric = metric_stat.get("Metric")
            period = metric_stat.get("Period")
            stat = metric_stat.get("Stat")
            # unit = metric_stat.get("Unit")

            order_by = (
                "timestamp DESC"
                if scan_by and scan_by == ScanBy.TimestampDescending
                else "timestamp ASC"
            )

            start_time_unix = self._convert_timestamp_to_unix(start_time)
            end_time_unix = self._convert_timestamp_to_unix(end_time)

            data = (
                account_id,
                region,
                metric.get("Namespace"),
                metric.get("MetricName"),
            )

            query_single_metric = f"""
            SELECT {STAT_TO_SQLITE_FUNC[stat]} FROM {self.TABLE_SINGLE_METRICS}
            WHERE account_id = ? AND region = ?
            AND namespace = ? AND metric_name = ?
            AND timestamp >= ? AND timestamp < ?
            ORDER BY {order_by}
            """

            query_agg_metric = f"""
            SELECT {STAT_TO_SQLITE_COLUMNS[stat]} FROM {self.TABLE_AGGREGATED_METRICS}
            WHERE account_id = ? AND region = ?
            AND namespace = ? AND metric_name = ?
            AND timestamp >= ? AND timestamp < ?
            ORDER BY {order_by}
            """

            datapoints = {}
            while start_time_unix < end_time_unix:
                next_start_time = start_time_unix + period
                datapoints[str(start_time_unix)] = {"values": []}
                cur.execute(
                    query_single_metric,
                    data
                    + (
                        start_time_unix,
                        next_start_time,
                    ),
                )
                datapoints[str(start_time_unix)]["values"].append(cur.fetchall()[0][0])

                cur.execute(
                    query_agg_metric,
                    data
                    + (
                        start_time_unix,
                        next_start_time,
                    ),
                )
                agg_result = cur.fetchall()
                if agg_result:
                    datapoints[str(start_time_unix)]["values"] += [
                        (
                            (
                                r[0],
                                r[1],
                            )
                            if stat == "Average"
                            else r[0]
                        )
                        for r in agg_result
                    ]

                start_time_unix = next_start_time

            cleaned_datapoints = {}
            for timestamp, timestamp_values in datapoints.items():
                cleaned_values = [v for v in timestamp_values["values"] if v is not None]
                if not cleaned_values:
                    continue

                if stat == "Sum":
                    cleaned_datapoints[timestamp] = sum(cleaned_values)

            return {"id": query.get("Id"), "datapoints": cleaned_datapoints}

    def list_metrics(self, account_id, region, namespace, metric_name, dimensions) -> dict:
        with sqlite3.connect(self.METRICS_DB) as conn:
            cur = conn.cursor()

            data = (account_id, region)

            namespace_filter = ""
            if namespace:
                namespace_filter = "AND namespace = ?"
                data = data + (namespace,)

            metric_name_filter = ""
            if metric_name:
                metric_name_filter = "AND metric_name = ?"
                data = data + (metric_name,)

            dimension_filter = ""
            for dimension in dimensions:
                dimension_filter += "AND dimensions LIKE ? "
                data = data + (f"%{dimension.get('Name')}={dimension.get('Value','')}%",)

            query = f"""
                SELECT DISTINCT metric_name, namespace, dimensions
                FROM {self.TABLE_SINGLE_METRICS}
                WHERE account_id = ? AND region = ? {namespace_filter} {metric_name_filter} {dimension_filter}
                ORDER BY timestamp DESC
            """

            cur.execute(
                query,
                data,
            )
            single_metrics_result = [
                {
                    "metric_name": r[0],
                    "namespace": r[1],
                    "dimensions": self._restore_dimensions_from_string(r[2]),
                }
                for r in cur.fetchall()
            ]

            query = f"""
                SELECT DISTINCT metric_name, namespace ,dimensions FROM {self.TABLE_AGGREGATED_METRICS}
                WHERE account_id = ? AND region = ?
                {namespace_filter}
                {metric_name_filter}
                {dimension_filter}
                ORDER BY timestamp DESC
            """

            cur.execute(
                query,
                data,
            )
            aggregated_metrics_result = [
                {
                    "metric_name": r[0],
                    "namespace": r[1],
                    "dimensions": self._restore_dimensions_from_string(r[2]),
                }
                for r in cur.fetchall()
            ]

            return {"metrics": (single_metrics_result + aggregated_metrics_result)}

    def clear_tables(self):
        # TODO clear tables for reset calls on cloudwatch
        pass

    def shutdown(self):
        # TODO delete tmpdir/database if we do not have persistence enabled?
        # anything else we should consider?
        ...

    def _get_ordered_dimensions_with_separator(self, dims: Optional[List[Dict]]):
        if not dims:
            return None
        dims.sort(key=lambda d: d["Name"])
        dimensions = ""
        for d in dims:
            dimensions += f"{d['Name']}={d['Value']}\t"  # aws does not allow ascii control characters, we can use it a sa separator

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

    def _get_insert_single_metric_query(self) -> str:
        return f"""INSERT INTO {self.TABLE_SINGLE_METRICS}
                    ("account_id", "region", "metric_name", "namespace", "timestamp", "dimensions", "unit", "storage_resolution", "value")
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"""

    def _get_insert_aggregated_metric_query(self) -> str:
        return f"""INSERT INTO {self.TABLE_AGGREGATED_METRICS}
                    ("account_id", "region", "metric_name", "namespace", "timestamp", "dimensions", "unit", "storage_resolution", "sample_count", "sum", "min", "max")
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
