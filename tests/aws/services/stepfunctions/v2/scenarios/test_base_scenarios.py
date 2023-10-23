import json
from collections import OrderedDict

import pytest

from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils
from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer import RegexTransformer
from tests.aws.services.stepfunctions.conftest import SfnNoneRecursiveParallelTransformer
from tests.aws.services.stepfunctions.templates.scenarios.scenarios_templates import (
    ScenariosTemplate as ST,
)
from tests.aws.services.stepfunctions.utils import (
    await_execution_terminated,
    create,
    create_and_record_execution,
    is_old_provider,
)

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


@markers.snapshot.skip_snapshot_verify(paths=["$..loggingConfiguration", "$..tracingConfiguration"])
class TestBaseScenarios:
    @markers.aws.validated
    def test_parallel_state(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(SfnNoneRecursiveParallelTransformer())
        template = ST.load_sfn_template(ST.PARALLEL_STATE)
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_state(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE)
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_state_legacy(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_LEGACY)
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_state_item_selector(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_ITEM_SELECTOR)
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_state_parameters_legacy(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_PARAMETERS_LEGACY)
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_state_item_selector_singleton(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_ITEM_SELECTOR_SINGLETON)
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_state_parameters_singleton_legacy(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_PARAMETERS_SINGLETON_LEGACY)
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_state_catch(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_CATCH)
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_state_catch_empty_fail(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_CATCH_EMPTY_FAIL)
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_state_catch_legacy(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_CATCH_LEGACY)
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_state_retry(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_RETRY)
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_state_retry_multiple_retriers(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_RETRY_MULTIPLE_RETRIERS)
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_state_retry_legacy(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_RETRY_LEGACY)
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_state_break_condition(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_BREAK_CONDITION)
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_state_break_condition_legacy(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_BREAK_CONDITION_LEGACY)
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    @pytest.mark.parametrize(
        "exec_input",
        [json.dumps({"result": {"done": True}}), json.dumps({"result": {"done": False}})],
    )
    def test_choice_unsorted_parameters(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        exec_input,
    ):
        template = ST.load_sfn_template(ST.CHOICE_STATE_UNSORTED_CHOICE_PARAMETERS)
        definition = json.dumps(template)

        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_choice_aws_docs_scenario(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.CHOICE_STATE_AWS_SCENARIO)
        definition = json.dumps(template)
        exec_input = json.dumps({"type": "Private", "value": 22})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_item_reader_base_list_objects_v2(
        self,
        aws_client,
        s3_create_bucket,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        bucket_name = s3_create_bucket()
        sfn_snapshot.add_transformer(RegexTransformer(bucket_name, "bucket_name"))
        for i in range(3):
            aws_client.s3.put_object(
                Bucket=bucket_name, Key=f"file_{i}.txt", Body=f"{i}HelloWorld!"
            )

        template = ST.load_sfn_template(ST.MAP_ITEM_READER_BASE_LIST_OBJECTS_V2)
        definition = json.dumps(template)

        exec_input = json.dumps({"Bucket": bucket_name})

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

        execution_history = aws_client.stepfunctions.get_execution_history(
            executionArn=execution_arn
        )
        map_run_arn = JSONPathUtils.extract_json(
            "$..mapRunStartedEventDetails.mapRunArn", execution_history
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_map_run_arn(map_run_arn, 0))

        # Normalise s3 ListObjectV2 response in the execution events output to ensure variable fields such as
        # Etag and LastModified are mapped to repeatable static values. Such normalisation is only necessary in
        # ItemReader calls invoking s3:ListObjectV2, of which result is directly mapped to the output of the iteration.
        output_str = execution_history["events"][-1]["executionSucceededEventDetails"]["output"]
        output_json = json.loads(output_str)
        output_norm = []
        for output_value in output_json:
            norm_output_value = OrderedDict()
            norm_output_value["Etag"] = f"<Etag-{output_value['Key']}>"
            norm_output_value["LastModified"] = "<date>"
            norm_output_value["Key"] = output_value["Key"]
            norm_output_value["Size"] = output_value["Size"]
            norm_output_value["StorageClass"] = output_value["StorageClass"]
            output_norm.append(norm_output_value)
        output_norm.sort(key=lambda value: value["Key"])
        output_norm_str = json.dumps(output_norm)
        execution_history["events"][-2]["stateExitedEventDetails"]["output"] = output_norm_str
        execution_history["events"][-1]["executionSucceededEventDetails"][
            "output"
        ] = output_norm_str

        sfn_snapshot.match("get_execution_history", execution_history)

    @markers.aws.validated
    def test_map_item_reader_base_csv_headers_first_line(
        self,
        aws_client,
        s3_create_bucket,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        bucket_name = s3_create_bucket()
        sfn_snapshot.add_transformer(RegexTransformer(bucket_name, "bucket-name"))

        key = "file.csv"
        csv_file = (
            "Col1,Col2,Col3\n"
            "Value1,Value2,Value3\n"
            "Value4,Value5,Value6\n"
            ",,,\n"
            "true,1,'HelloWorld'\n"
            "Null,None,\n"
            "   \n"
        )
        aws_client.s3.put_object(Bucket=bucket_name, Key=key, Body=csv_file)

        template = ST.load_sfn_template(ST.MAP_ITEM_READER_BASE_CSV_HEADERS_FIRST_LINE)
        definition = json.dumps(template)

        exec_input = json.dumps({"Bucket": bucket_name, "Key": key})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_item_reader_base_csv_headers_decl(
        self,
        aws_client,
        s3_create_bucket,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        bucket_name = s3_create_bucket()
        sfn_snapshot.add_transformer(RegexTransformer(bucket_name, "bucket-name"))

        key = "file.csv"
        csv_headers = ["H1", "H2", "H3"]
        csv_file = (
            "Value1,Value2,Value3\n"
            "Value4,Value5,Value6\n"
            ",,,\n"
            "true,1,'HelloWorld'\n"
            "Null,None,\n"
            "   \n"
        )
        aws_client.s3.put_object(Bucket=bucket_name, Key=key, Body=csv_file)

        template = ST.load_sfn_template(ST.MAP_ITEM_READER_BASE_CSV_HEADERS_DECL)
        template["States"]["MapState"]["ItemReader"]["ReaderConfig"]["CSVHeaders"] = csv_headers
        definition = json.dumps(template)

        exec_input = json.dumps({"Bucket": bucket_name, "Key": key})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_item_reader_csv_headers_decl_duplicate_headers(
        self,
        aws_client,
        s3_create_bucket,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        bucket_name = s3_create_bucket()
        sfn_snapshot.add_transformer(RegexTransformer(bucket_name, "bucket-name"))

        key = "file.csv"
        csv_headers = ["H1", "H1", "H3"]
        csv_file = (
            "Value1,Value2,Value3\n"
            "Value4,Value5,Value6\n"
            ",,,\n"
            "true,1,'HelloWorld'\n"
            "Null,None,\n"
            "   \n"
        )
        aws_client.s3.put_object(Bucket=bucket_name, Key=key, Body=csv_file)

        template = ST.load_sfn_template(ST.MAP_ITEM_READER_BASE_CSV_HEADERS_DECL)
        template["States"]["MapState"]["ItemReader"]["ReaderConfig"]["CSVHeaders"] = csv_headers
        definition = json.dumps(template)

        exec_input = json.dumps({"Bucket": bucket_name, "Key": key})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_item_reader_csv_headers_first_row_typed_headers(
        self,
        aws_client,
        s3_create_bucket,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        bucket_name = s3_create_bucket()
        sfn_snapshot.add_transformer(RegexTransformer(bucket_name, "bucket-name"))

        key = "file.csv"
        csv_file = (
            "0,True,{}\n"
            "Value4,Value5,Value6\n"
            ",,,\n"
            "true,1,'HelloWorld'\n"
            "Null,None,\n"
            "   \n"
        )
        aws_client.s3.put_object(Bucket=bucket_name, Key=key, Body=csv_file)

        template = ST.load_sfn_template(ST.MAP_ITEM_READER_BASE_CSV_HEADERS_FIRST_LINE)
        definition = json.dumps(template)

        exec_input = json.dumps({"Bucket": bucket_name, "Key": key})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_item_reader_csv_headers_decl_extra_fields(
        self,
        aws_client,
        s3_create_bucket,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        bucket_name = s3_create_bucket()
        sfn_snapshot.add_transformer(RegexTransformer(bucket_name, "bucket-name"))

        key = "file.csv"
        csv_headers = ["H1"]
        csv_file = (
            "Value1,Value2,Value3\n"
            "Value4,Value5,Value6\n"
            ",,,\n"
            "true,1,'HelloWorld'\n"
            "Null,None,\n"
            "   \n"
        )
        aws_client.s3.put_object(Bucket=bucket_name, Key=key, Body=csv_file)

        template = ST.load_sfn_template(ST.MAP_ITEM_READER_BASE_CSV_HEADERS_DECL)
        template["States"]["MapState"]["ItemReader"]["ReaderConfig"]["CSVHeaders"] = csv_headers
        definition = json.dumps(template)

        exec_input = json.dumps({"Bucket": bucket_name, "Key": key})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_item_reader_csv_first_row_extra_fields(
        self,
        aws_client,
        s3_create_bucket,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        bucket_name = s3_create_bucket()
        sfn_snapshot.add_transformer(RegexTransformer(bucket_name, "bucket-name"))

        key = "file.csv"
        csv_file = (
            "H1,\n" "Value4,Value5,Value6\n" ",,,\n" "true,1,'HelloWorld'\n" "Null,None,\n" "   \n"
        )
        aws_client.s3.put_object(Bucket=bucket_name, Key=key, Body=csv_file)

        template = ST.load_sfn_template(ST.MAP_ITEM_READER_BASE_CSV_HEADERS_FIRST_LINE)
        definition = json.dumps(template)

        exec_input = json.dumps({"Bucket": bucket_name, "Key": key})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_item_reader_base_json(
        self,
        aws_client,
        s3_create_bucket,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        bucket_name = s3_create_bucket()
        sfn_snapshot.add_transformer(RegexTransformer(bucket_name, "bucket-name"))

        key = "file.json"
        json_file = json.dumps(
            [
                {"verdict": "true", "statement_date": "6/11/2008", "statement_source": "speech"},
                {
                    "verdict": "false",
                    "statement_date": "6/7/2022",
                    "statement_source": "television",
                },
                {
                    "verdict": "mostly-true",
                    "statement_date": "5/18/2016",
                    "statement_source": "news",
                },
            ]
        )
        aws_client.s3.put_object(Bucket=bucket_name, Key=key, Body=json_file)

        template = ST.load_sfn_template(ST.MAP_ITEM_READER_BASE_JSON)
        definition = json.dumps(template)

        exec_input = json.dumps({"Bucket": bucket_name, "Key": key})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_item_reader_json_no_json_list_object(
        self,
        aws_client,
        s3_create_bucket,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        bucket_name = s3_create_bucket()
        sfn_snapshot.add_transformer(RegexTransformer(bucket_name, "bucket-name"))

        key = "file.json"
        json_file = json.dumps({"Hello": "world"})
        aws_client.s3.put_object(Bucket=bucket_name, Key=key, Body=json_file)

        template = ST.load_sfn_template(ST.MAP_ITEM_READER_BASE_JSON)
        definition = json.dumps(template)

        exec_input = json.dumps({"Bucket": bucket_name, "Key": key})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
