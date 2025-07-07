import copy
import json

import pytest
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.aws.connect import ServiceLevelClientFactory
from localstack.services.cloudformation.v2.utils import is_v2_engine
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

pytestmark = pytest.mark.skipif(
    condition=not is_v2_engine() and not is_aws_cloud(),
    reason="Only targeting the new engine",
)


@pytest.mark.skipif(
    condition=not is_v2_engine() and not is_aws_cloud(), reason="Requires the V2 engine"
)
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "delete-describe..*",
        #
        # Before/After Context
        "$..Capabilities",
        "$..NotificationARNs",
        "$..IncludeNestedStacks",
        "$..Scope",
        "$..Details",
        "$..Parameters",
        "$..Replacement",
        "$..PolicyAction",
        "$..PhysicalResourceId",
    ]
)
class TestCaptureUpdateProcess:
    @markers.aws.validated
    def test_direct_update(
        self,
        snapshot,
        capture_update_process,
    ):
        """
        Update a stack with a static change (i.e. in the text of the template).

        Conclusions:
        - A static change in the template that's not invoking an intrinsic function
            (`Ref`, `Fn::GetAtt` etc.) is resolved by the deployment engine synchronously
            during the `create_change_set` invocation
        """
        name1 = f"topic-1-{short_uid()}"
        name2 = f"topic-2-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-2"))
        t1 = {
            "Resources": {
                "Foo": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                    },
                },
            },
        }
        t2 = {
            "Resources": {
                "Foo": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                    },
                },
            },
        }
        capture_update_process(snapshot, t1, t2)

    @markers.aws.validated
    def test_dynamic_update(
        self,
        snapshot,
        capture_update_process,
    ):
        """
        Update a stack with two resources:
        - A is changed statically
        - B refers to the changed value of A via an intrinsic function

        Conclusions:
        - The value of B on creation is "known after apply" even though the resolved
          property value is known statically
        - The nature of the change to B is "known after apply"
        - The CloudFormation engine does not resolve intrinsic function calls when determining the
            nature of the update
        """
        name1 = f"topic-1-{short_uid()}"
        name2 = f"topic-2-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-2"))
        t1 = {
            "Resources": {
                "Foo": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                    },
                },
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {
                            "Fn::GetAtt": ["Foo", "TopicName"],
                        },
                    },
                },
            },
        }
        t2 = {
            "Resources": {
                "Foo": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                    },
                },
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {
                            "Fn::GetAtt": ["Foo", "TopicName"],
                        },
                    },
                },
            },
        }
        capture_update_process(snapshot, t1, t2)

    @markers.aws.validated
    def test_parameter_changes(
        self,
        snapshot,
        capture_update_process,
    ):
        """
        Update a stack with two resources:
        - A is changed via a template parameter
        - B refers to the changed value of A via an intrinsic function

        Conclusions:
        - The value of B on creation is "known after apply" even though the resolved
          property value is known statically
        - The nature of the change to B is "known after apply"
        - The CloudFormation engine does not resolve intrinsic function calls when determining the
            nature of the update
        """
        name1 = f"topic-1-{short_uid()}"
        name2 = f"topic-2-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-2"))
        t1 = {
            "Parameters": {
                "TopicName": {
                    "Type": "String",
                },
            },
            "Resources": {
                "Foo": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": {"Ref": "TopicName"},
                    },
                },
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {
                            "Fn::GetAtt": ["Foo", "TopicName"],
                        },
                    },
                },
            },
        }
        capture_update_process(snapshot, t1, t1, p1={"TopicName": name1}, p2={"TopicName": name2})

    @markers.aws.validated
    def test_mappings_with_static_fields(
        self,
        snapshot,
        capture_update_process,
    ):
        """
        Update a stack with two resources:
        - A is changed via looking up a static value in a mapping
        - B refers to the changed value of A via an intrinsic function

        Conclusions:
        - On first deploy the contents of the map is resolved completely
        - The nature of the change to B is "known after apply"
        - The CloudFormation engine does not resolve intrinsic function calls when determining the
            nature of the update
        """
        name1 = f"topic-1-{short_uid()}"
        name2 = f"topic-2-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        t1 = {
            "Mappings": {
                "MyMap": {
                    "MyKey": {"key1": name1, "key2": name2},
                },
            },
            "Resources": {
                "Foo": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": {
                            "Fn::FindInMap": [
                                "MyMap",
                                "MyKey",
                                "key1",
                            ],
                        },
                    },
                },
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {
                            "Fn::GetAtt": ["Foo", "TopicName"],
                        },
                    },
                },
            },
        }
        t2 = {
            "Mappings": {
                "MyMap": {
                    "MyKey": {
                        "key1": name1,
                        "key2": name2,
                    },
                },
            },
            "Resources": {
                "Foo": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": {
                            "Fn::FindInMap": [
                                "MyMap",
                                "MyKey",
                                "key2",
                            ],
                        },
                    },
                },
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {
                            "Fn::GetAtt": ["Foo", "TopicName"],
                        },
                    },
                },
            },
        }
        capture_update_process(snapshot, t1, t2)

    @markers.aws.validated
    def test_mappings_with_parameter_lookup(
        self,
        snapshot,
        capture_update_process,
    ):
        """
        Update a stack with two resources:
        - A is changed via looking up a static value in a mapping but the key comes from
          a template parameter
        - B refers to the changed value of A via an intrinsic function

        Conclusions:
        - The same conclusions as `test_mappings_with_static_fields`
        """
        name1 = f"topic-1-{short_uid()}"
        name2 = f"topic-2-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        t1 = {
            "Parameters": {
                "TopicName": {
                    "Type": "String",
                },
            },
            "Mappings": {
                "MyMap": {
                    "MyKey": {"key1": name1, "key2": name2},
                },
            },
            "Resources": {
                "Foo": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": {
                            "Fn::FindInMap": [
                                "MyMap",
                                "MyKey",
                                {
                                    "Ref": "TopicName",
                                },
                            ],
                        },
                    },
                },
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {
                            "Fn::GetAtt": ["Foo", "TopicName"],
                        },
                    },
                },
            },
        }
        capture_update_process(snapshot, t1, t1, p1={"TopicName": "key1"}, p2={"TopicName": "key2"})

    @markers.aws.validated
    def test_conditions(
        self,
        snapshot,
        capture_update_process,
    ):
        """
        Toggle a resource from present to not present via a condition

        Conclusions:
        - Adding the second resource creates an `Add` resource change
        """
        t1 = {
            "Parameters": {
                "EnvironmentType": {
                    "Type": "String",
                }
            },
            "Conditions": {
                "IsProduction": {
                    "Fn::Equals": [
                        {"Ref": "EnvironmentType"},
                        "prod",
                    ],
                }
            },
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                },
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": "test",
                    },
                    "Condition": "IsProduction",
                },
            },
        }

        capture_update_process(
            snapshot, t1, t1, p1={"EnvironmentType": "not-prod"}, p2={"EnvironmentType": "prod"}
        )

    @markers.aws.validated
    @pytest.mark.skip(
        "Unlike AWS CFN, the update graph understands the dependent resource does not "
        "need modification also when the IncludePropertyValues flag is off."
        # TODO: we may achieve the same limitation by pruning the resolution of traversals.
    )
    def test_unrelated_changes_update_propagation(
        self,
        snapshot,
        capture_update_process,
    ):
        """
        - Resource B depends on resource A which is updated, but the referenced parameter does not
          change

        Conclusions:
        - No update to resource B
        """
        topic_name = f"MyTopic{short_uid()}"
        snapshot.add_transformer(RegexTransformer(topic_name, "topic-name"))
        t1 = {
            "Resources": {
                "Parameter1": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": topic_name,
                        "Description": "original",
                    },
                },
                "Parameter2": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {"Fn::GetAtt": ["Parameter1", "Value"]},
                    },
                },
            },
        }
        t2 = {
            "Resources": {
                "Parameter1": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": topic_name,
                        "Description": "changed",
                    },
                },
                "Parameter2": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {"Fn::GetAtt": ["Parameter1", "Value"]},
                    },
                },
            },
        }
        capture_update_process(snapshot, t1, t2)

    @markers.aws.validated
    @pytest.mark.skip(
        "Deployment now succeeds but our describer incorrectly does not assign a change for Parameter2"
    )
    def test_unrelated_changes_requires_replacement(
        self,
        snapshot,
        capture_update_process,
    ):
        """
        - Resource B depends on resource A which is updated, but the referenced parameter does not
          change, however resource A requires replacement

        Conclusions:
        - Resource B is updated
        """
        parameter_name_1 = f"MyParameter{short_uid()}"
        parameter_name_2 = f"MyParameter{short_uid()}"
        snapshot.add_transformer(RegexTransformer(parameter_name_1, "parameter-1-name"))
        snapshot.add_transformer(RegexTransformer(parameter_name_2, "parameter-2-name"))
        t1 = {
            "Resources": {
                "Parameter1": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Name": parameter_name_1,
                        "Type": "String",
                        "Value": "value",
                    },
                },
                "Parameter2": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {"Fn::GetAtt": ["Parameter1", "Value"]},
                    },
                },
            },
        }
        t2 = {
            "Resources": {
                "Parameter1": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Name": parameter_name_2,
                        "Type": "String",
                        "Value": "value",
                    },
                },
                "Parameter2": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {"Fn::GetAtt": ["Parameter1", "Value"]},
                    },
                },
            },
        }
        capture_update_process(snapshot, t1, t2)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "template",
        [
            pytest.param(
                {
                    "Parameters": {
                        "ParameterValue": {
                            "Type": "String",
                        },
                    },
                    "Resources": {
                        "Parameter": {
                            "Type": "AWS::SSM::Parameter",
                            "Properties": {
                                "Type": "String",
                                "Value": {"Ref": "ParameterValue"},
                            },
                        }
                    },
                },
                id="change_dynamic",
            ),
            pytest.param(
                {
                    "Parameters": {
                        "ParameterValue": {
                            "Type": "String",
                        },
                    },
                    "Resources": {
                        "Parameter1": {
                            "Type": "AWS::SSM::Parameter",
                            "Properties": {
                                "Name": "param-name",
                                "Type": "String",
                                "Value": {"Ref": "ParameterValue"},
                            },
                        },
                        "Parameter2": {
                            "Type": "AWS::SSM::Parameter",
                            "Properties": {
                                "Type": "String",
                                "Value": {"Fn::GetAtt": ["Parameter1", "Name"]},
                            },
                        },
                    },
                },
                id="change_unrelated_property",
            ),
            pytest.param(
                {
                    "Parameters": {
                        "ParameterValue": {
                            "Type": "String",
                        },
                    },
                    "Resources": {
                        "Parameter1": {
                            "Type": "AWS::SSM::Parameter",
                            "Properties": {
                                "Type": "String",
                                "Value": {"Ref": "ParameterValue"},
                            },
                        },
                        "Parameter2": {
                            "Type": "AWS::SSM::Parameter",
                            "Properties": {
                                "Type": "String",
                                "Value": {"Fn::GetAtt": ["Parameter1", "Type"]},
                            },
                        },
                    },
                },
                id="change_unrelated_property_not_create_only",
            ),
            pytest.param(
                {
                    "Parameters": {
                        "ParameterValue": {
                            "Type": "String",
                            "Default": "value-1",
                            "AllowedValues": ["value-1", "value-2"],
                        }
                    },
                    "Conditions": {
                        "ShouldCreateParameter": {
                            "Fn::Equals": [{"Ref": "ParameterValue"}, "value-2"]
                        }
                    },
                    "Resources": {
                        "SSMParameter1": {
                            "Type": "AWS::SSM::Parameter",
                            "Properties": {
                                "Type": "String",
                                "Value": "first",
                            },
                        },
                        "SSMParameter2": {
                            "Type": "AWS::SSM::Parameter",
                            "Condition": "ShouldCreateParameter",
                            "Properties": {
                                "Type": "String",
                                "Value": "first",
                            },
                        },
                    },
                },
                id="change_parameter_for_condition_create_resource",
            ),
        ],
    )
    def test_base_dynamic_parameter_scenarios(
        self, snapshot, capture_update_process, template, request
    ):
        if request.node.callspec.id in {
            "change_unrelated_property",
            "change_unrelated_property_not_create_only",
        }:
            pytest.skip(
                reason="AWS appears to incorrectly mark the dependent resource as needing update when describe "
                "changeset is invoked without the inclusion of property values."
            )
        capture_update_process(
            snapshot,
            template,
            template,
            {"ParameterValue": "value-1"},
            {"ParameterValue": "value-2"},
        )

    @markers.aws.validated
    def test_execute_with_ref(self, snapshot, aws_client, deploy_cfn_template):
        name1 = f"param-1-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(name1, "<name-1>"))
        name2 = f"param-2-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(name2, "<name-2>"))
        value = "my-value"
        param2_name = f"output-param-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(param2_name, "<output-parameter>"))

        t1 = {
            "Resources": {
                "Parameter1": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Name": name1,
                        "Type": "String",
                        "Value": value,
                    },
                },
                "Parameter2": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Name": param2_name,
                        "Type": "String",
                        "Value": {"Ref": "Parameter1"},
                    },
                },
            }
        }
        t2 = copy.deepcopy(t1)
        t2["Resources"]["Parameter1"]["Properties"]["Name"] = name2

        stack = deploy_cfn_template(template=json.dumps(t1))
        stack_id = stack.stack_id

        before_value = aws_client.ssm.get_parameter(Name=param2_name)["Parameter"]["Value"]
        snapshot.match("before-value", before_value)

        deploy_cfn_template(stack_name=stack_id, template=json.dumps(t2), is_update=True)

        after_value = aws_client.ssm.get_parameter(Name=param2_name)["Parameter"]["Value"]
        snapshot.match("after-value", after_value)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "template_1, template_2",
        [
            (
                {
                    "Mappings": {"GenericMapping": {"EnvironmentA": {"ParameterValue": "value-1"}}},
                    "Resources": {
                        "MySSMParameter": {
                            "Type": "AWS::SSM::Parameter",
                            "Properties": {
                                "Type": "String",
                                "Value": {
                                    "Fn::FindInMap": [
                                        "GenericMapping",
                                        "EnvironmentA",
                                        "ParameterValue",
                                    ]
                                },
                            },
                        }
                    },
                },
                {
                    "Mappings": {"GenericMapping": {"EnvironmentA": {"ParameterValue": "value-2"}}},
                    "Resources": {
                        "MySSMParameter": {
                            "Type": "AWS::SSM::Parameter",
                            "Properties": {
                                "Type": "String",
                                "Value": {
                                    "Fn::FindInMap": [
                                        "GenericMapping",
                                        "EnvironmentA",
                                        "ParameterValue",
                                    ]
                                },
                            },
                        }
                    },
                },
            )
        ],
        ids=["update_string_referencing_resource"],
    )
    def test_base_mapping_scenarios(
        self,
        snapshot,
        capture_update_process,
        template_1,
        template_2,
    ):
        capture_update_process(snapshot, template_1, template_2)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..Capabilities",
        "$..IncludeNestedStacks",
        "$..NotificationARNs",
        "$..Parameters",
        "$..Changes..ResourceChange.Details",
        "$..Changes..ResourceChange.Scope",
        "$..Changes..ResourceChange.PhysicalResourceId",
        "$..Changes..ResourceChange.Replacement",
    ]
)
def test_single_resource_static_update(aws_client: ServiceLevelClientFactory, snapshot, cleanups):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    parameter_name = f"parameter-{short_uid()}"
    value1 = "foo"
    value2 = "bar"

    t1 = {
        "Resources": {
            "MyParameter": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name": parameter_name,
                    "Type": "String",
                    "Value": value1,
                },
            },
        },
    }

    stack_name = f"stack-{short_uid()}"
    change_set_name = f"cs-{short_uid()}"
    cs_result = aws_client.cloudformation.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=json.dumps(t1),
        ChangeSetType="CREATE",
    )
    cs_id = cs_result["Id"]
    stack_id = cs_result["StackId"]
    aws_client.cloudformation.get_waiter("change_set_create_complete").wait(ChangeSetName=cs_id)
    cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_id))

    describe_result = aws_client.cloudformation.describe_change_set(ChangeSetName=cs_id)
    snapshot.match("describe-1", describe_result)

    aws_client.cloudformation.execute_change_set(ChangeSetName=cs_id)
    aws_client.cloudformation.get_waiter("stack_create_complete").wait(StackName=stack_id)

    parameter = aws_client.ssm.get_parameter(Name=parameter_name)["Parameter"]
    snapshot.match("parameter-1", parameter)

    t2 = copy.deepcopy(t1)
    t2["Resources"]["MyParameter"]["Properties"]["Value"] = value2

    change_set_name = f"cs-{short_uid()}"
    cs_result = aws_client.cloudformation.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=json.dumps(t2),
    )
    cs_id = cs_result["Id"]
    aws_client.cloudformation.get_waiter("change_set_create_complete").wait(ChangeSetName=cs_id)

    describe_result = aws_client.cloudformation.describe_change_set(ChangeSetName=cs_id)
    snapshot.match("describe-2", describe_result)

    aws_client.cloudformation.execute_change_set(ChangeSetName=cs_id)
    aws_client.cloudformation.get_waiter("stack_update_complete").wait(StackName=stack_id)

    parameter = aws_client.ssm.get_parameter(Name=parameter_name)["Parameter"]
    snapshot.match("parameter-2", parameter)
