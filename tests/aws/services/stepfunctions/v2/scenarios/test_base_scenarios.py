import json
import time

import pytest

from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer import RegexTransformer
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.conftest import SfnNoneRecursiveParallelTransformer
from tests.aws.services.stepfunctions.templates.scenarios.scenarios_templates import (
    ScenariosTemplate as ST,
)
from tests.aws.services.stepfunctions.utils import create_and_record_execution, is_old_provider

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


@markers.snapshot.skip_snapshot_verify(
    paths=["$..loggingConfiguration", "$..tracingConfiguration", "$..previousEventId"]
)
class TestBaseScenarios:
    @markers.aws.unknown
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

    @markers.aws.unknown
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

    @markers.aws.unknown
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

    @markers.aws.unknown
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

    @markers.aws.unknown
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

    @markers.aws.unknown
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

    @markers.aws.unknown
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

    @markers.aws.unknown
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

    @markers.aws.unknown
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

    @markers.aws.unknown
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

    @markers.aws.unknown
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

    @markers.aws.unknown
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

    @markers.aws.unknown
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

    @markers.aws.unknown
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

    @markers.aws.unknown
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
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.unknown
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

    @markers.aws.unknown
    def test_map_item_reader_base_csv_headers_decl(
        self,
        aws_client,
        s3_create_bucket,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        bucket_name = s3_create_bucket()
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
