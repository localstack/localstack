import json
from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON37

from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_PYTHON_ECHO
from tests.integration.awslambda.test_lambda_integration import _await_dynamodb_table_active, _await_event_source_mapping_enabled


class TestLambdaEventFiltering:
    def test_dynamo_db_insert_event(
        self, create_lambda_function, lambda_client, dynamodb_client, dynamodb_create_table, check_lambda_logs
    ):
        def check_logs():
            expected = [
                r'.*"Records":.*',
                r'.*"dynamodb": {(.*)}.*',
                r'.*"eventSource": ("aws:dynamodb").*',
                r'.*"eventName": ("INSERT").*',
                r'.*"Keys": {0}.*'.format(json.dumps(db_item)),
            ]
            check_lambda_logs(function_name, expected_lines=expected)

        function_name = f"lambda_func-{short_uid()}"
        table_name = f"test-table-{short_uid()}"
        partition_key = "id"
        db_item = {partition_key: {"S": "test123"}}

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON37,
        )
        dynamodb_create_table(table_name=table_name, partition_key=partition_key)
        _await_dynamodb_table_active(dynamodb_client, table_name)
        stream_arn = dynamodb_client.update_table(
            TableName=table_name,
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        )["TableDescription"]["LatestStreamArn"]
        event_source_uuid = lambda_client.create_event_source_mapping(
            FunctionName=function_name,
            BatchSize=1,
            StartingPosition="LATEST",
            EventSourceArn=stream_arn,
            MaximumBatchingWindowInSeconds=1,
            MaximumRetryAttempts=1,
            FilterCriteria={
                'Filters': [
                    {
                        'Pattern': json.dumps({ "eventName": ['INSERT']})
                    },
                ]
            }
        )["UUID"]
        _await_event_source_mapping_enabled(lambda_client, event_source_uuid)
        dynamodb_client.put_item(TableName=table_name, Item=db_item)
        retry(check_logs, retries=50, sleep=2)
        
        dynamodb_client.put_item(TableName=table_name, Item=db_item)
        retry(check_logs, retries=50, sleep=2)
