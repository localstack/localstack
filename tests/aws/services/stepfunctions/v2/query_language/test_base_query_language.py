import json

import pytest

from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import create_and_record_execution
from tests.aws.services.stepfunctions.templates.querylanguage.query_language_templates import (
    QueryLanguageTemplate as QLT,
)

QUERY_LANGUAGE_JSON_PATH_TYPE = "JSONPath"
QUERY_LANGUAGE_JSONATA_TYPE = "JSONata"


class TestBaseQueryLanguage:
    @pytest.mark.parametrize(
        "template",
        [
            QLT.load_sfn_template(QLT.BASE_PASS_JSONPATH),
            QLT.load_sfn_template(QLT.BASE_PASS_JSONATA),
        ],
        ids=["JSON_PATH", "JSONATA"],
    )
    @markers.aws.validated
    def test_base_query_language_field(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        template,
    ):
        definition = json.dumps(template)
        exec_input = json.dumps({})
        create_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            create_iam_role_for_sfn=create_iam_role_for_sfn,
            create_state_machine=create_state_machine,
            sfn_snapshot=sfn_snapshot,
            definition=definition,
            execution_input=exec_input,
        )

    @pytest.mark.parametrize(
        "template",
        [
            QLT.load_sfn_template(QLT.BASE_PASS_JSONATA_OVERRIDE),
            QLT.load_sfn_template(QLT.BASE_PASS_JSONATA_OVERRIDE_DEFAULT),
        ],
        ids=["JSONATA_OVERRIDE", "JSONATA_OVERRIDE_DEFAULT"],
    )
    @markers.aws.validated
    def test_query_language_field_override(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        template,
    ):
        definition = json.dumps(template)
        exec_input = json.dumps({})
        create_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            create_iam_role_for_sfn=create_iam_role_for_sfn,
            create_state_machine=create_state_machine,
            sfn_snapshot=sfn_snapshot,
            definition=definition,
            execution_input=exec_input,
        )

    @pytest.mark.skip(reason="Skipped until we have more context on more handling error cases")
    @markers.aws.unknown
    def test_jsonata_query_language_field_downgrade_exception(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = QLT.load_sfn_template(QLT.BASE_PASS_JSONATA)

        # Cannot set a state-level Query Language to 'JSONPath' when the top-level field is 'JSONata'
        template["States"]["StartState"]["QueryLanguage"] = QUERY_LANGUAGE_JSON_PATH_TYPE
        definition = json.dumps(template)
        exec_input = json.dumps({})

        try:
            create_and_record_execution(
                stepfunctions_client=aws_client.stepfunctions,
                create_iam_role_for_sfn=create_iam_role_for_sfn,
                create_state_machine=create_state_machine,
                sfn_snapshot=sfn_snapshot,
                definition=definition,
                execution_input=exec_input,
            )
        except Exception as e:
            # Will this raise an exception since downgrades to JSONPath are not supported?
            sfn_snapshot.snapshot("incompatible_state_level_query_language_field", e)
