import os
from typing import Optional

import mysql.connector
import pytest
import requests
from python_terraform import IsNotFlagged, Terraform

from localstack.utils.strings import get_random_hex
from localstack.utils.sync import retry


@pytest.fixture
def deploy_terraform():
    terraform_client = Terraform()

    def _apply(terraform_dir: Optional[str] = None, variables: Optional[dict] = None):
        terraform_client.variables = variables
        terraform_client.working_dir = os.path.realpath(terraform_dir)
        terraform_client.init(capture_output="yes", no_color=IsNotFlagged)
        terraform_client.apply(capture_output="yes", no_color=IsNotFlagged, skip_plan=True)
        return terraform_client.output()

    yield _apply

    terraform_client.destroy(
        capture_output="yes", no_color=IsNotFlagged, force=IsNotFlagged, auto_approve=True
    )


@pytest.mark.aws_validated
@pytest.skip("DMS not yet implemented in localstack")
def test_dms_rds_kinesis(dms_client, kinesis_client, deploy_terraform):

    db_name = "test"
    db_pass = get_random_hex(18)
    db_user = "admin"
    db_table = "test"
    client_ip = requests.get("https://ifconfig.me").text

    variables = {
        "region_name": "us-east-1",
        "db_name": db_name,
        "db_pass": db_pass,
        "db_user": db_user,
        "client_ip": f"{client_ip}/32",
    }

    output = deploy_terraform(terraform_dir="./dms_rds_kinesis", variables=variables)
    kinesis_stream_arn = output["kinesis_stream_arn"]["value"]
    rds_endpoint = output["rds_endpoint"]["value"]
    replication_task_arn = output["replication_task_arn"]["value"]

    config = {
        "user": db_user,
        "password": db_pass,
        "host": rds_endpoint,
        "database": db_name,
    }

    cnx = mysql.connector.connect(**config)
    cursor = cnx.cursor()

    try:
        cursor.execute(f"USE {db_name}")
    except mysql.connector.Error as err:
        print("Failed creating database: {}".format(err))
        exit(1)

    try:
        cursor.execute(
            f"CREATE TABLE {db_table} (id INT NOT NULL AUTO_INCREMENT, name VARCHAR(255), PRIMARY KEY (id))"
        )
    except mysql.connector.Error as err:
        print("Failed creating table: {}".format(err))
        exit(1)

    try:
        for i in range(2):
            cursor.execute(f"INSERT INTO {db_table} (name) VALUES ('value{i}')")
        cnx.commit()
    except mysql.connector.Error as err:
        print("Failed inserting data: {}".format(err))
        exit(1)

    cursor.close()
    cnx.close()

    def _dms_replication_task_status(status: str):
        response = dms_client.describe_replication_tasks(
            Filters=[
                {
                    "Name": "replication-task-arn",
                    "Values": [replication_task_arn],
                }
            ],
            WithoutSettings=True,
        )
        assert len(response["ReplicationTasks"]) == 1
        assert response["ReplicationTasks"][0]["Status"] == status

    retry(_dms_replication_task_status, retries=100, sleep=5, status="ready")
    dms_client.start_replication_task(
        ReplicationTaskArn=replication_task_arn, StartReplicationTaskType="start-replication"
    )
    retry(_dms_replication_task_status, retries=100, sleep=5, status="stopped")

    def _describe_table_statistics():
        response = dms_client.describe_table_statistics(
            ReplicationTaskArn=replication_task_arn,
        )
        assert len(response["TableStatistics"]) == 1
        assert response["TableStatistics"][0]["FullLoadRows"] == 2

    retry(_describe_table_statistics, retries=100, sleep=5)

    shard_id = kinesis_client.describe_stream(StreamARN=kinesis_stream_arn)["StreamDescription"][
        "Shards"
    ][0]["ShardId"]
    shard_iterator = kinesis_client.get_shard_iterator(
        StreamARN=kinesis_stream_arn,
        ShardId=shard_id,
        ShardIteratorType="TRIM_HORIZON",
    )["ShardIterator"]

    def _get_records():
        records = kinesis_client.get_records(ShardIterator=shard_iterator)
        assert len(records["Records"]) == 4

    retry(_get_records, retries=100, sleep=5)
