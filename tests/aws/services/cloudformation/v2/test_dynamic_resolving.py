from tests.aws.services.cloudformation.conftest import skip_if_legacy_engine

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

pytestmark = skip_if_legacy_engine(reason="Only valid for the V2 provider")


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "delete-describe..*",
        #
        # Before/After Context
        "$..Capabilities",
        "$..IncludeNestedStacks",
        "$..Scope",
        "$..Details",
        "$..Parameters",
        "$..Replacement",
        "$..PolicyAction",
    ]
)
class TestSSMParameterValues:
    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: parity of the events
            "$..MyParameter..PhysicalResourceId"
        ]
    )
    def test_update_parameter_between_deployments(
        self, aws_client, snapshot, create_parameter, capture_update_process
    ):
        param_name = f"param-{short_uid()}"
        param_value_1 = f"param-value-1-{short_uid()}"
        param_value_2 = f"param-value-2-{short_uid()}"

        snapshot.add_transformers_list(
            [
                snapshot.transform.regex(param_name, "<param-name>"),
                snapshot.transform.regex(param_value_1, "<param-value-1>"),
                snapshot.transform.regex(param_value_2, "<param-value-2>"),
                snapshot.transform.key_value("PhysicalResourceId"),
            ]
        )

        create_parameter(Name=param_name, Value=param_value_1, Type="String")

        template1 = {
            "Parameters": {
                "MyValue": {
                    "Type": "AWS::SSM::Parameter::Value<String>",
                },
            },
            "Resources": {
                "MyParameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {"Ref": "MyValue"},
                    },
                },
            },
        }

        def update_parameter_value():
            aws_client.ssm.put_parameter(
                Name=param_name, Value=param_value_2, Type="String", Overwrite=True
            )

        capture_update_process(
            snapshot=snapshot,
            t1=template1,
            t2=template1,
            p1={"MyValue": param_name},
            p2={"MyValue": param_name},
            custom_update_step=update_parameter_value,
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: parity of the events
            "$..MyParameter..PhysicalResourceId"
        ]
    )
    def test_change_parameter_type(
        self, aws_client, snapshot, create_parameter, capture_update_process
    ):
        param_name = f"param-{short_uid()}"
        param_value = f"param-value-{short_uid()}"

        snapshot.add_transformers_list(
            [
                snapshot.transform.regex(param_name, "<param-name>"),
                snapshot.transform.regex(param_value, "<param-value>"),
                snapshot.transform.key_value("PhysicalResourceId"),
            ]
        )

        create_parameter(Name=param_name, Value=param_value, Type="String")

        template1 = {
            "Parameters": {
                "MyValue": {
                    "Type": "String",
                },
            },
            "Resources": {
                "MyParameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {"Ref": "MyValue"},
                    },
                },
            },
        }
        template2 = {
            "Parameters": {
                "MyValue": {
                    "Type": "AWS::SSM::Parameter::Value<String>",
                },
            },
            "Resources": {
                "MyParameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {"Ref": "MyValue"},
                    },
                },
            },
        }

        capture_update_process(
            snapshot=snapshot,
            t1=template1,
            t2=template2,
            p1={"MyValue": param_name},
            p2={"MyValue": param_name},
        )
