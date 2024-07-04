import json
from collections import OrderedDict

import pytest
from localstack_snapshot.snapshots.transformer import JsonpathTransformer, RegexTransformer

from localstack.aws.api.lambda_ import Runtime
from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    SfnNoneRecursiveParallelTransformer,
    await_execution_terminated,
    create,
    create_and_record_execution,
)
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.errorhandling.error_handling_templates import (
    ErrorHandlingTemplate as EHT,
)
from tests.aws.services.stepfunctions.templates.scenarios.scenarios_templates import (
    ScenariosTemplate as ST,
)
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as SerT,
)


@markers.snapshot.skip_snapshot_verify(paths=["$..tracingConfiguration"])
class TestBaseScenarios:
    @markers.snapshot.skip_snapshot_verify(paths=["$..cause"])
    @markers.aws.validated
    def test_catch_states_runtime(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_name = f"lambda_func_{short_uid()}"
        create_res = create_lambda_function(
            func_name=function_name,
            handler_file=SerT.LAMBDA_ID_FUNCTION,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))
        function_arn = create_res["CreateFunctionResponse"]["FunctionArn"]

        template = ST.load_sfn_template(ST.CATCH_STATES_RUNTIME)
        template["States"]["RaiseRuntime"]["Resource"] = function_arn
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
    def test_catch_empty(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_name = f"lambda_func_{short_uid()}"
        create_res = create_lambda_function(
            func_name=function_name,
            handler_file=SerT.LAMBDA_ID_FUNCTION,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))
        function_arn = create_res["CreateFunctionResponse"]["FunctionArn"]

        template = ST.load_sfn_template(ST.CATCH_EMPTY)
        template["States"]["StartTask"]["Resource"] = function_arn
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
    @pytest.mark.parametrize("max_concurrency_value", [dict(), "NoNumber", 0, 1])
    def test_max_concurrency_path(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        max_concurrency_value,
    ):
        # TODO: Investigate AWS's behaviour with stringified integer values such as "1", as when passed as
        #  execution inputs these are casted to integers. Future efforts should record more snapshot tests to assert
        #  the behaviour of such stringification on execution inputs
        template = ST.load_sfn_template(ST.MAX_CONCURRENCY)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {"MaxConcurrencyValue": max_concurrency_value, "Values": ["HelloWorld"]}
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: AWS consistently appears to stall after startup when a negative MaxConcurrency value is given.
            #  Instead, the Provider V2 raises a State.Runtime exception and terminates. In the future we should
            #  reevaluate AWS's behaviour in these circumstances and choose whether too also 'hang'.
            "$..events"
        ]
    )
    def test_max_concurrency_path_negative(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAX_CONCURRENCY)
        definition = json.dumps(template)

        exec_input = json.dumps({"MaxConcurrencyValue": -1, "Values": ["HelloWorld"]})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_parallel_state_order(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(SfnNoneRecursiveParallelTransformer())
        template = ST.load_sfn_template(ST.PARALLEL_STATE_ORDER)
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
    def test_parallel_state_fail(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.PARALLEL_STATE_FAIL)
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
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: AWS appears to have changed json encoding to include spaces after separators,
            #  other v2 test suite snapshots need to be re-recorded
            "$..events..stateEnteredEventDetails.input",
            "$..events..stateExitedEventDetails.output",
            "$..events..executionSucceededEventDetails.output",
        ]
    )
    def test_parallel_state_nested(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(SfnNoneRecursiveParallelTransformer())
        template = ST.load_sfn_template(ST.PARALLEL_NESTED_NESTED)
        definition = json.dumps(template)

        exec_input = json.dumps([[1, 2, 3], [4, 5, 6]])
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_parallel_state_catch(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.PARALLEL_STATE_CATCH)
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
    def test_parallel_state_retry(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.PARALLEL_STATE_RETRY)
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
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: AWS appears to have changed json encoding to include spaces after separators,
            #  other v2 test suite snapshots need to be re-recorded
            "$..events..stateEnteredEventDetails.input"
        ]
    )
    def test_map_state_nested(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_NESTED)
        definition = json.dumps(template)

        exec_input = json.dumps(
            [
                [1, 2, 3],
                [4, 5, 6],
            ]
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_state_no_processor_config(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_NO_PROCESSOR_CONFIG)
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
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: AWS appears to have changed json encoding to include spaces after separators,
            #  other v2 test suite snapshots need to be re-recorded
            "$..events..stateEnteredEventDetails.input"
        ]
    )
    def test_map_state_legacy_config_inline(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_LEGACY_CONFIG_INLINE)
        definition = json.dumps(template)

        exec_input = json.dumps(["Hello", "World"])
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: AWS appears to have changed json encoding to include spaces after separators,
            #  other v2 test suite snapshots need to be re-recorded
            "$..events..stateEnteredEventDetails.input"
        ]
    )
    def test_map_state_legacy_config_distributed(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_LEGACY_CONFIG_DISTRIBUTED)
        definition = json.dumps(template)

        exec_input = json.dumps(["Hello", "World"])
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: AWS appears to have changed json encoding to include spaces after separators,
            #  other v2 test suite snapshots need to be re-recorded
            "$..events..stateEnteredEventDetails.input"
        ]
    )
    def test_map_state_legacy_config_distributed_parameters(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_LEGACY_CONFIG_DISTRIBUTED_PARAMETERS)
        definition = json.dumps(template)

        exec_input = json.dumps(["Hello", "World"])
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: AWS appears to have changed json encoding to include spaces after separators,
            #  other v2 test suite snapshots need to be re-recorded
            "$..events..stateEnteredEventDetails.input"
        ]
    )
    def test_map_state_legacy_config_distributed_item_selector(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_LEGACY_CONFIG_DISTRIBUTED_ITEM_SELECTOR)
        definition = json.dumps(template)

        exec_input = json.dumps(["Hello", "World"])
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: AWS appears to have changed json encoding to include spaces after separators,
            #  other v2 test suite snapshots need to be re-recorded
            "$..events..stateEnteredEventDetails.input"
        ]
    )
    def test_map_state_legacy_config_inline_parameters(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_LEGACY_CONFIG_INLINE_PARAMETERS)
        definition = json.dumps(template)

        exec_input = json.dumps(["Hello", "World"])
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: AWS appears to have changed json encoding to include spaces after separators,
            #  other v2 test suite snapshots need to be re-recorded
            "$..events..stateEnteredEventDetails.input"
        ]
    )
    def test_map_state_legacy_config_inline_item_selector(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_LEGACY_CONFIG_INLINE_ITEM_SELECTOR)
        definition = json.dumps(template)

        exec_input = json.dumps(["Hello", "World"])
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: AWS appears to have changed json encoding to include spaces after separators,
            #  other v2 test suite snapshots need to be re-recorded
            "$..events..stateEnteredEventDetails.input"
        ]
    )
    def test_map_state_config_distributed_item_selector(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_CONFIG_DISTRIBUTED_ITEM_SELECTOR)
        definition = json.dumps(template)

        exec_input = json.dumps(["Hello", "World"])
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_map_state_legacy_reentrant(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_LEGACY_REENTRANT)
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
    def test_map_state_config_distributed_reentrant(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        # Replace MapRunArns with fixed values to circumvent random ordering issues.
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..mapRunArn", replacement="map_run_arn", replace_reference=False
            )
        )

        template = ST.load_sfn_template(ST.MAP_STATE_CONFIG_DISTRIBUTED_REENTRANT)
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
    def test_map_state_config_distributed_reentrant_lambda(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        # Replace MapRunArns with fixed values to circumvent random ordering issues.
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..mapRunArn", replacement="map_run_arn", replace_reference=False
            )
        )

        function_name = f"sfn_lambda_{short_uid()}"
        create_res = create_lambda_function(
            func_name=function_name,
            handler_file=SerT.LAMBDA_ID_FUNCTION,
            runtime=Runtime.python3_12,
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "lambda_function_name"))
        function_arn = create_res["CreateFunctionResponse"]["FunctionArn"]

        template = ST.load_sfn_template(ST.MAP_STATE_CONFIG_DISTRIBUTED_REENTRANT_LAMBDA)
        definition = json.dumps(template)
        definition = definition.replace("_tbd_", function_arn)

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
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: AWS appears to have changed json encoding to include spaces after separators,
            #  other v2 test suite snapshots need to be re-recorded
            "$..events..stateEnteredEventDetails.input"
        ]
    )
    def test_map_state_config_distributed_parameters(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_CONFIG_DISTRIBUTED_PARAMETERS)
        definition = json.dumps(template)

        exec_input = json.dumps(["Hello", "World"])
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: AWS appears to have changed json encoding to include spaces after separators,
            #  other v2 test suite snapshots need to be re-recorded
            "$..events..stateEnteredEventDetails.input"
        ]
    )
    def test_map_state_config_inline_item_selector(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_CONFIG_DISTRIBUTED_ITEM_SELECTOR)
        definition = json.dumps(template)

        exec_input = json.dumps(["Hello", "World"])
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: AWS appears to have changed json encoding to include spaces after separators,
            #  other v2 test suite snapshots need to be re-recorded
            "$..events..stateEnteredEventDetails.input"
        ]
    )
    def test_map_state_config_inline_parameters(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_CONFIG_INLINE_PARAMETERS)
        definition = json.dumps(template)

        exec_input = json.dumps(["Hello", "World"])
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
        "tolerance_template",
        [ST.MAP_STATE_TOLERATED_FAILURE_COUNT, ST.MAP_STATE_TOLERATED_FAILURE_PERCENTAGE],
        ids=["count_literal", "percentage_literal"],
    )
    def test_map_state_tolerated_failure_values(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        tolerance_template,
    ):
        template = ST.load_sfn_template(tolerance_template)
        definition = json.dumps(template)

        exec_input = json.dumps([0])
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    @pytest.mark.parametrize("tolerated_failure_count_value", [dict(), "NoNumber", -1, 0, 1])
    def test_map_state_tolerated_failure_count_path(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        tolerated_failure_count_value,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_TOLERATED_FAILURE_COUNT_PATH)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {"Items": [0], "ToleratedFailureCount": tolerated_failure_count_value}
        )
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
        "tolerated_failure_percentage_value", [dict(), "NoNumber", -1.1, -1, 0, 1, 1.1, 100, 100.1]
    )
    def test_map_state_tolerated_failure_percentage_path(
        self,
        aws_client,
        s3_create_bucket,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        tolerated_failure_percentage_value,
    ):
        template = ST.load_sfn_template(ST.MAP_STATE_TOLERATED_FAILURE_PERCENTAGE_PATH)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {"Items": [0], "ToleratedFailurePercentage": tolerated_failure_percentage_value}
        )
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
    def test_choice_singleton_composite(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.CHOICE_STATE_SINGLETON_COMPOSITE)
        definition = json.dumps(template)
        exec_input = json.dumps({"type": "Public", "value": 22})
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
        execution_history["events"][-1]["executionSucceededEventDetails"]["output"] = (
            output_norm_str
        )

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
    @pytest.mark.parametrize(
        "max_items_value",
        [0, 2, 100_000_000],  # Linter on creation filters for valid input integers (0 - 100000000).
    )
    def test_map_item_reader_csv_max_items(
        self,
        aws_client,
        s3_create_bucket,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        max_items_value,
    ):
        bucket_name = s3_create_bucket()
        sfn_snapshot.add_transformer(RegexTransformer(bucket_name, "bucket-name"))

        key = "file.csv"
        csv_file = (
            "Col1,Col2\n" "Value1,Value2\n" "Value3,Value4\n" "Value5,Value6\n" "Value7,Value8\n"
        )
        aws_client.s3.put_object(Bucket=bucket_name, Key=key, Body=csv_file)

        template = ST.load_sfn_template(ST.MAP_ITEM_READER_BASE_CSV_MAX_ITEMS)
        template["States"]["MapState"]["ItemReader"]["ReaderConfig"]["MaxItems"] = max_items_value
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
    @pytest.mark.parametrize(
        "max_items_value", [-1, 0, 1.5, 2, 100_000_000, 100_000_001]
    )  # The Distributed Map state stops reading items beyond 100_000_000.
    def test_map_item_reader_csv_max_items_paths(
        self,
        aws_client,
        s3_create_bucket,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        max_items_value,
    ):
        if max_items_value == 1.5:
            pytest.skip(
                "Validation of non integer max items value is performed at a higher depth than that of negative "
                "values in AWS StepFunctions. The SFN v2 interpreter runs this check at the same depth."
            )

        bucket_name = s3_create_bucket()
        sfn_snapshot.add_transformer(RegexTransformer(bucket_name, "bucket-name"))

        key = "file.csv"
        csv_file = (
            "Col1,Col2\n" "Value1,Value2\n" "Value3,Value4\n" "Value5,Value6\n" "Value7,Value8\n"
        )
        aws_client.s3.put_object(Bucket=bucket_name, Key=key, Body=csv_file)

        template = ST.load_sfn_template(ST.MAP_ITEM_READER_BASE_CSV_MAX_ITEMS_PATH)
        definition = json.dumps(template)

        exec_input = json.dumps({"Bucket": bucket_name, "Key": key, "MaxItems": max_items_value})
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

    @markers.aws.validated
    def test_map_item_reader_base_json_max_items(
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
            ]
            * 3
        )
        aws_client.s3.put_object(Bucket=bucket_name, Key=key, Body=json_file)

        template = ST.load_sfn_template(ST.MAP_ITEM_READER_BASE_JSON_MAX_ITEMS)
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

    @markers.snapshot.skip_snapshot_verify(paths=["$..Cause"])
    @markers.aws.validated
    def test_lambda_empty_retry(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_name = f"lambda_func_{short_uid()}"
        create_res = create_lambda_function(
            func_name=function_name,
            handler_file=EHT.LAMBDA_FUNC_RAISE_EXCEPTION,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))
        function_arn = create_res["CreateFunctionResponse"]["FunctionArn"]

        template = ST.load_sfn_template(ST.LAMBDA_EMPTY_RETRY)
        template["States"]["LambdaTask"]["Resource"] = function_arn
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

    @markers.snapshot.skip_snapshot_verify(paths=["$..Cause"])
    @markers.aws.validated
    def test_lambda_invoke_with_retry_base(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_1_name = f"lambda_1_func_{short_uid()}"
        create_1_res = create_lambda_function(
            func_name=function_1_name,
            handler_file=EHT.LAMBDA_FUNC_RAISE_EXCEPTION,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_1_name, "<lambda_function_1_name>"))

        template = ST.load_sfn_template(ST.LAMBDA_INVOKE_WITH_RETRY_BASE)
        template["States"]["InvokeLambdaWithRetry"]["Resource"] = create_1_res[
            "CreateFunctionResponse"
        ]["FunctionArn"]
        definition = json.dumps(template)

        exec_input = json.dumps({"Value1": "HelloWorld!", "Value2": None})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.snapshot.skip_snapshot_verify(paths=["$..Cause"])
    @markers.aws.validated
    def test_lambda_invoke_with_retry_extended_input(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..StartTime", replacement="<start-time>", replace_reference=False
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..EnteredTime", replacement="<entered-time>", replace_reference=False
            )
        )

        function_1_name = f"lambda_1_func_{short_uid()}"
        create_1_res = create_lambda_function(
            func_name=function_1_name,
            handler_file=EHT.LAMBDA_FUNC_RAISE_EXCEPTION,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_1_name, "<lambda_function_1_name>"))

        template = ST.load_sfn_template(ST.LAMBDA_INVOKE_WITH_RETRY_BASE_EXTENDED_INPUT)
        template["States"]["InvokeLambdaWithRetry"]["Resource"] = create_1_res[
            "CreateFunctionResponse"
        ]["FunctionArn"]
        definition = json.dumps(template)

        exec_input = json.dumps({"Value1": "HelloWorld!", "Value2": None})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.snapshot.skip_snapshot_verify(paths=["$..Cause"])
    @markers.aws.validated
    def test_lambda_service_invoke_with_retry_extended_input(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..StartTime", replacement="<start-time>", replace_reference=False
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..EnteredTime", replacement="<entered-time>", replace_reference=False
            )
        )

        function_1_name = f"lambda_1_func_{short_uid()}"
        create_lambda_function(
            func_name=function_1_name,
            handler_file=EHT.LAMBDA_FUNC_RAISE_EXCEPTION,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_1_name, "<lambda_function_1_name>"))

        template = ST.load_sfn_template(ST.LAMBDA_SERVICE_INVOKE_WITH_RETRY_BASE_EXTENDED_INPUT)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {"FunctionName": function_1_name, "Value1": "HelloWorld!", "Value2": None}
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_retry_interval_features(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_name = f"lambda_func_{short_uid()}"
        create_res = create_lambda_function(
            func_name=function_name,
            handler_file=EHT.LAMBDA_FUNC_RAISE_EXCEPTION,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))
        function_arn = create_res["CreateFunctionResponse"]["FunctionArn"]

        template = ST.load_sfn_template(ST.RETRY_INTERVAL_FEATURES)
        template["States"]["LambdaTask"]["Resource"] = function_arn
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
    def test_retry_interval_features_jitter_none(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_name = f"lambda_func_{short_uid()}"
        create_res = create_lambda_function(
            func_name=function_name,
            handler_file=EHT.LAMBDA_FUNC_RAISE_EXCEPTION,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))
        function_arn = create_res["CreateFunctionResponse"]["FunctionArn"]

        template = ST.load_sfn_template(ST.RETRY_INTERVAL_FEATURES_JITTER_NONE)
        template["States"]["LambdaTask"]["Resource"] = function_arn
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
    def test_retry_interval_features_max_attempts_zero(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_name = f"lambda_func_{short_uid()}"
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "lambda_function_name"))
        create_lambda_function(
            func_name=function_name,
            handler_file=EHT.LAMBDA_FUNC_RAISE_EXCEPTION,
            runtime=Runtime.python3_12,
        )

        template = ST.load_sfn_template(ST.RETRY_INTERVAL_FEATURES_MAX_ATTEMPTS_ZERO)
        definition = json.dumps(template)

        exec_input = json.dumps({"FunctionName": function_name})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_wait_timestamp(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.WAIT_TIMESTAMP)
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
    def test_wait_timestamp_path(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.WAIT_TIMESTAMP_PATH)
        definition = json.dumps(template)

        exec_input = json.dumps({"TimestampValue": "2016-03-14T01:59:00Z"})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
