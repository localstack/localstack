import json

from localstack_snapshot.snapshots import JsonpathTransformer, RegexTransformer

from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.templates.scenarios.scenarios_templates import (
    ScenariosTemplate as ST,
)
from tests.aws.services.stepfunctions.utils import await_execution_terminated, create


@markers.snapshot.skip_snapshot_verify(paths=["$..loggingConfiguration", "$..tracingConfiguration"])
class TestSnfApiMapRun:
    @markers.aws.validated
    def test_list_map_runs_and_describe_map_run(
        self,
        aws_client,
        s3_create_bucket,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..stopDate", replacement="stop-date", replace_reference=False
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..startDate", replacement="start-date", replace_reference=False
            )
        )

        bucket_name = s3_create_bucket()
        sfn_snapshot.add_transformer(RegexTransformer(bucket_name, "bucket_name"))

        key = "file.csv"
        csv_file = "Col1,Col2,Col3\nValue1,Value2,Value3\nValue4,Value5,Value6"
        aws_client.s3.put_object(Bucket=bucket_name, Key=key, Body=csv_file)

        template = ST.load_sfn_template(ST.MAP_ITEM_READER_BASE_CSV_HEADERS_FIRST_LINE)
        definition = json.dumps(template)

        exec_input = json.dumps({"Bucket": bucket_name, "Key": key})

        state_machine_arn = create(
            create_iam_role_for_sfn, create_state_machine, sfn_snapshot, definition
        )

        exec_resp = aws_client.stepfunctions.start_execution(
            stateMachineArn=state_machine_arn, input=exec_input
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(exec_resp, 0))
        execution_arn = exec_resp["executionArn"]

        await_execution_terminated(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )

        list_map_runs = aws_client.stepfunctions.list_map_runs(executionArn=execution_arn)

        for i, map_run in enumerate(list_map_runs["mapRuns"]):
            sfn_snapshot.add_transformer(
                sfn_snapshot.transform.sfn_map_run_arn(map_run["mapRunArn"], 0)
            )

        sfn_snapshot.match("list_map_runs", list_map_runs)

        map_run_arn = list_map_runs["mapRuns"][0]["mapRunArn"]
        describe_map_run = aws_client.stepfunctions.describe_map_run(mapRunArn=map_run_arn)
        sfn_snapshot.match("describe_map_run", describe_map_run)
