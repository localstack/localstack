import logging
import os
import sqlite3
from datetime import datetime, timezone
from typing import Dict, List, Optional

from localstack import config
from localstack.aws.api.cloudwatch import MetricData, MetricStat, ScanBy
from localstack.utils.files import mkdir

LOG = logging.getLogger(__name__)


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

            def _get_current_timestamp_utc():  # TODO verify if this is the standard format, might need to convert
                now = datetime.utcnow().replace(tzinfo=timezone.utc)
                return int(now.timestamp())

            for metric in metric_data:
                if metric.get("Value"):
                    # TODO convert timestamp
                    # TODO convert dimensions
                    timestamp = (
                        self._convert_timestamp_to_unix(metric.get("Timestamp"))
                        if metric.get("Timestamp")
                        else _get_current_timestamp_utc()
                    )
                    cur.execute(
                        f"""INSERT INTO {self.TABLE_SINGLE_METRICS}
                        ("account_id", "region", "metric_name", "namespace", "timestamp", "dimensions", "unit", "storage_resolution", "value")
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            account_id,
                            region,
                            metric.get("MetricName"),
                            namespace,
                            timestamp,
                            self._get_ordered_dimensions_with_separator(metric.get("Dimensions")),
                            metric.get("Unit"),
                            metric.get("StorageResolution"),
                            metric["Value"],
                        ),
                    )
                elif metric.get("Values"):
                    pass
                elif metric.get("StatisticValues"):
                    pass

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
        with sqlite3.connect(self.METRICS_DB) as conn:
            cur = conn.cursor()
            metric_stat = query.get("MetricStat")
            metric = metric_stat.get("Metric")
            # period = metric_stat.get("Period")
            stat = metric_stat.get("Stat")
            # unit = metric_stat.get("Unit")

            # TODO test default order
            order_by = (
                "timestamp DESC"
                if scan_by and scan_by == ScanBy.TimestampDescending
                else "timestamp ASC"
            )
            data = (
                account_id,
                region,
                metric.get("Namespace"),
                metric.get("MetricName"),
                self._convert_timestamp_to_unix(start_time),
                self._convert_timestamp_to_unix(end_time),
            )
            fun = ""
            if stat == "Sum":
                fun = "SUM(value)"
            if stat == "Average":
                fun = "AVG(value)"
            if stat == "Minimum":
                fun = "MIN(value)"
            if stat == "Maximum":
                fun = "MAX(value)"
            if stat == "SampleCount":
                fun = "COUNT(value)"

            # TODO select by period
            # TODO exclude null values, check if dimensions must be null though if missing
            cur.execute(
                f"""SELECT {fun} FROM {self.TABLE_SINGLE_METRICS}
                                    WHERE account_id = ? AND region = ?
                                        AND namespace = ? AND metric_name = ?
                                        AND timestamp BETWEEN ? AND ?
                                    ORDER BY {order_by}""",
                data,
            )
            # cur.execute(
            #     f"""SELECT {fun} FROM {self.TABLE_SINGLE_METRICS}
            #             WHERE account_id = ? AND region = ?
            #                 AND namespace = ? AND metric_name = ? AND dimensions = ?
            #                 AND unit = ?
            #                 AND timestamp BETWEEN ? AND ?
            #             ORDER BY {order_by}""",
            #     data,
            # )
            results = cur.fetchall()
            # TODO return datapoints, create results, join with aggregated data
            return {"id": query.get("Id"), "result": results}

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

    def _convert_timestamp_to_unix(
        self, timestamp: datetime
    ):  # TODO verify if this is the standard format, might need to convert
        return int(timestamp.timestamp())
