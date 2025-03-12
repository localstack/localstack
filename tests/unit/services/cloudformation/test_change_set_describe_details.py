import json

from localstack.aws.api.cloudformation import ResourceChange
from localstack.services.cloudformation.engine.v2.change_set_model import (
    ChangeSetModel,
    NodeTemplate,
)
from localstack.services.cloudformation.engine.v2.change_set_model_describer import (
    ChangeSetModelDescriber,
)


# TODO: this is a temporary test suite for the v2 CFN update engine change set description logic.
#  should be replaced in favour of v2 integration tests.
class TestChangeSetDescribeDetails:
    @staticmethod
    def eval_change_set(before_template: dict, after_template: dict) -> list[ResourceChange]:
        change_set_model = ChangeSetModel(
            before_template=before_template, after_template=after_template
        )
        update_model: NodeTemplate = change_set_model.get_update_model()
        change_set_describer = ChangeSetModelDescriber(node_template=update_model)
        resource_changes = change_set_describer.get_resource_changes()
        # TODO
        json_str = json.dumps(resource_changes)
        return json.loads(json_str)

    def test_direct_update(self):
        t1 = {
            "Resources": {
                "Foo": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": "topic-1",
                    },
                },
            },
        }
        t2 = {
            "Resources": {
                "Foo": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": "topic-2",
                    },
                },
            },
        }
        resource_changes = self.eval_change_set(t1, t2)
        target = [
            {
                "Action": "Modify",
                "AfterContext": {"Properties": {"TopicName": "topic-2"}},
                "BeforeContext": {"Properties": {"TopicName": "topic-1"}},
                "LogicalResourceId": "Foo",
                "ResourceType": "AWS::SNS::Topic",
            },
        ]
        assert resource_changes == target

    def test_dynamic_update(self):
        t1 = {
            "Resources": {
                "Foo": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": "topic-1",
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
                        "TopicName": "topic-2",
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
        resource_changes = self.eval_change_set(t1, t2)
        target = [
            {
                "Action": "Modify",
                "AfterContext": {"Properties": {"TopicName": "topic-2"}},
                "BeforeContext": {"Properties": {"TopicName": "topic-1"}},
                "LogicalResourceId": "Foo",
                "ResourceType": "AWS::SNS::Topic",
            },
            {
                "Action": "Modify",
                "AfterContext": {
                    "Properties": {"Value": "{{changeSet:KNOWN_AFTER_APPLY}}", "Type": "String"}
                },
                "BeforeContext": {"Properties": {"Value": "topic-1", "Type": "String"}},
                "LogicalResourceId": "Parameter",
                "ResourceType": "AWS::SSM::Parameter",
            },
        ]
        assert resource_changes == target

    def test_unrelated_changes_update_propagation(self):
        t1 = {
            "Resources": {
                "Parameter1": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": "topic_name",
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
                        "Value": "topic_name",
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
        resource_changes = self.eval_change_set(t1, t2)
        target = [
            {
                "Action": "Modify",
                "AfterContext": {
                    "Properties": {
                        "Value": "topic_name",
                        "Type": "String",
                        "Description": "changed",
                    }
                },
                "BeforeContext": {
                    "Properties": {
                        "Value": "topic_name",
                        "Type": "String",
                        "Description": "original",
                    }
                },
                "LogicalResourceId": "Parameter1",
                "ResourceType": "AWS::SSM::Parameter",
            }
        ]
        assert resource_changes == target

    def test_unrelated_changes_requires_replacement(self):
        t1 = {
            "Resources": {
                "Parameter1": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Name": "MyParameter-1",
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
                        "Name": "MyParameter-2",
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
        resource_changes = self.eval_change_set(t1, t2)
        target = [
            {
                "Action": "Modify",
                "AfterContext": {
                    "Properties": {"Value": "value", "Type": "String", "Name": "MyParameter-2"}
                },
                "BeforeContext": {
                    "Properties": {"Value": "value", "Type": "String", "Name": "MyParameter-1"}
                },
                "LogicalResourceId": "Parameter1",
                "ResourceType": "AWS::SSM::Parameter",
            },
            {
                "Action": "Modify",
                "AfterContext": {
                    "Properties": {"Value": "{{changeSet:KNOWN_AFTER_APPLY}}", "Type": "String"}
                },
                "BeforeContext": {"Properties": {"Value": "value", "Type": "String"}},
                "LogicalResourceId": "Parameter2",
                "Replacement": "False",
                "ResourceType": "AWS::SSM::Parameter",
            },
        ]
        assert resource_changes == target
