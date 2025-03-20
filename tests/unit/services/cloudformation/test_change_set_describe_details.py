import json
from typing import Optional

import pytest

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
    def eval_change_set(
        before_template: dict,
        after_template: dict,
        before_parameters: Optional[dict] = None,
        after_parameters: Optional[dict] = None,
    ) -> list[ResourceChange]:
        change_set_model = ChangeSetModel(
            before_template=before_template,
            after_template=after_template,
            before_parameters=before_parameters,
            after_parameters=after_parameters,
        )
        update_model: NodeTemplate = change_set_model.get_update_model()
        change_set_describer = ChangeSetModelDescriber(node_template=update_model)
        changes = change_set_describer.get_resource_changes()
        # TODO
        json_str = json.dumps(changes)
        return json.loads(json_str)

    @staticmethod
    def compare_changes(computed: list, target: list) -> None:
        def sort_criteria(resource_change):
            return resource_change["ResourceChange"]["LogicalResourceId"]

        assert sorted(computed, key=sort_criteria) == sorted(target, key=sort_criteria)

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
        changes = self.eval_change_set(t1, t2)
        target = [
            {
                "ResourceChange": {
                    "Action": "Modify",
                    "AfterContext": {"Properties": {"TopicName": "topic-2"}},
                    "BeforeContext": {"Properties": {"TopicName": "topic-1"}},
                    # "Details": [
                    #     {
                    #         "ChangeSource": "DirectModification",
                    #         "Evaluation": "Static",
                    #         "Target": {
                    #             "AfterValue": "topic-2-fdd551f7",
                    #             "Attribute": "Properties",
                    #             "AttributeChangeType": "Modify",
                    #             "BeforeValue": "topic-1-eaed84b9",
                    #             "Name": "TopicName",
                    #             "Path": "/Properties/TopicName",
                    #             "RequiresRecreation": "Always"
                    #         }
                    #     }
                    # ],
                    "LogicalResourceId": "Foo",
                    # "PhysicalResourceId": "arn:<partition>:sns:<region>:111111111111:topic-1",
                    # "PolicyAction": "ReplaceAndDelete",
                    # "Replacement": "True",
                    "ResourceType": "AWS::SNS::Topic",
                    # "Scope": [
                    #     "Properties"
                    # ]
                },
                "Type": "Resource",
            }
        ]
        self.compare_changes(changes, target)

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
        changes = self.eval_change_set(t1, t2)
        target = [
            {
                "ResourceChange": {
                    "Action": "Modify",
                    "AfterContext": {"Properties": {"TopicName": "topic-2"}},
                    "BeforeContext": {"Properties": {"TopicName": "topic-1"}},
                    # "Details": [
                    #     {
                    #         "ChangeSource": "DirectModification",
                    #         "Evaluation": "Static",
                    #         "Target": {
                    #             "AfterValue": "topic-2-6da2c5b0",
                    #             "Attribute": "Properties",
                    #             "AttributeChangeType": "Modify",
                    #             "BeforeValue": "topic-1-1601f61d",
                    #             "Name": "TopicName",
                    #             "Path": "/Properties/TopicName",
                    #             "RequiresRecreation": "Always"
                    #         }
                    #     }
                    # ],
                    "LogicalResourceId": "Foo",
                    # "PhysicalResourceId": "arn:<partition>:sns:<region>:111111111111:topic-1",
                    # "PolicyAction": "ReplaceAndDelete",
                    # "Replacement": "True",
                    "ResourceType": "AWS::SNS::Topic",
                    # "Scope": [
                    #     "Properties"
                    # ]
                },
                "Type": "Resource",
            },
            {
                "ResourceChange": {
                    "Action": "Modify",
                    "AfterContext": {
                        "Properties": {"Value": "{{changeSet:KNOWN_AFTER_APPLY}}", "Type": "String"}
                    },
                    "BeforeContext": {"Properties": {"Value": "topic-1", "Type": "String"}},
                    # "Details": [
                    #     {
                    #         "ChangeSource": "DirectModification",
                    #         "Evaluation": "Dynamic",
                    #         "Target": {
                    #             "AfterValue": "{{changeSet:KNOWN_AFTER_APPLY}}",
                    #             "Attribute": "Properties",
                    #             "AttributeChangeType": "Modify",
                    #             "BeforeValue": "topic-1-1601f61d",
                    #             "Name": "Value",
                    #             "Path": "/Properties/Value",
                    #             "RequiresRecreation": "Never"
                    #         }
                    #     },
                    #     {
                    #         "CausingEntity": "Foo.TopicName",
                    #         "ChangeSource": "ResourceAttribute",
                    #         "Evaluation": "Static",
                    #         "Target": {
                    #             "AfterValue": "{{changeSet:KNOWN_AFTER_APPLY}}",
                    #             "Attribute": "Properties",
                    #             "AttributeChangeType": "Modify",
                    #             "BeforeValue": "topic-1-1601f61d",
                    #             "Name": "Value",
                    #             "Path": "/Properties/Value",
                    #             "RequiresRecreation": "Never"
                    #         }
                    #     }
                    # ],
                    "LogicalResourceId": "Parameter",
                    # "PhysicalResourceId": "CFN-Parameter",
                    # "Replacement": "False",
                    "ResourceType": "AWS::SSM::Parameter",
                    # "Scope": [
                    #     "Properties"
                    # ]
                },
                "Type": "Resource",
            },
        ]
        self.compare_changes(changes, target)

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
        changes = self.eval_change_set(t1, t2)
        target = [
            {
                "ResourceChange": {
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
                    # "Details": [
                    #     {
                    #         "ChangeSource": "DirectModification",
                    #         "Evaluation": "Static",
                    #         "Target": {
                    #             "AfterValue": "changed",
                    #             "Attribute": "Properties",
                    #             "AttributeChangeType": "Modify",
                    #             "BeforeValue": "original",
                    #             "Name": "Description",
                    #             "Path": "/Properties/Description",
                    #             "RequiresRecreation": "Never"
                    #         }
                    #     }
                    # ],
                    "LogicalResourceId": "Parameter1",
                    # "PhysicalResourceId": "CFN-Parameter1",
                    # "Replacement": "False",
                    "ResourceType": "AWS::SSM::Parameter",
                    # "Scope": [
                    #     "Properties"
                    # ]
                },
                "Type": "Resource",
            }
        ]
        self.compare_changes(changes, target)

    @pytest.mark.skip(
        reason=(
            "Updating an SSN name seems to require replacement of the resource which "
            "means the other resource using Fn::GetAtt is known after apply."
        )
    )
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
        changes = self.eval_change_set(t1, t2)
        target = [
            {
                "ResourceChange": {
                    "Action": "Modify",
                    "AfterContext": {
                        "Properties": {"Value": "value", "Type": "String", "Name": "MyParameter-2"}
                    },
                    "BeforeContext": {
                        "Properties": {"Value": "value", "Type": "String", "Name": "MyParameter-1"}
                    },
                    # "Details": [
                    #     {
                    #         "ChangeSource": "DirectModification",
                    #         "Evaluation": "Static",
                    #         "Target": {
                    #             "AfterValue": "MyParameter846966c8",
                    #             "Attribute": "Properties",
                    #             "AttributeChangeType": "Modify",
                    #             "BeforeValue": "MyParameter676af33a",
                    #             "Name": "Name",
                    #             "Path": "/Properties/Name",
                    #             "RequiresRecreation": "Always"
                    #         }
                    #     }
                    # ],
                    "LogicalResourceId": "Parameter1",
                    # "PhysicalResourceId": "MyParameter676af33a",
                    # "PolicyAction": "ReplaceAndDelete",
                    # "Replacement": "True",
                    "ResourceType": "AWS::SSM::Parameter",
                    # "Scope": [
                    #     "Properties"
                    # ]
                },
                "Type": "Resource",
            },
            {
                "ResourceChange": {
                    "Action": "Modify",
                    "AfterContext": {
                        "Properties": {"Value": "{{changeSet:KNOWN_AFTER_APPLY}}", "Type": "String"}
                    },
                    "BeforeContext": {"Properties": {"Value": "value", "Type": "String"}},
                    # "Details": [
                    #     {
                    #         "ChangeSource": "DirectModification",
                    #         "Evaluation": "Dynamic",
                    #         "Target": {
                    #             "AfterValue": "{{changeSet:KNOWN_AFTER_APPLY}}",
                    #             "Attribute": "Properties",
                    #             "AttributeChangeType": "Modify",
                    #             "BeforeValue": "value",
                    #             "Name": "Value",
                    #             "Path": "/Properties/Value",
                    #             "RequiresRecreation": "Never"
                    #         }
                    #     },
                    #     {
                    #         "CausingEntity": "Parameter1.Value",
                    #         "ChangeSource": "ResourceAttribute",
                    #         "Evaluation": "Static",
                    #         "Target": {
                    #             "AfterValue": "{{changeSet:KNOWN_AFTER_APPLY}}",
                    #             "Attribute": "Properties",
                    #             "AttributeChangeType": "Modify",
                    #             "BeforeValue": "value",
                    #             "Name": "Value",
                    #             "Path": "/Properties/Value",
                    #             "RequiresRecreation": "Never"
                    #         }
                    #     }
                    # ],
                    "LogicalResourceId": "Parameter2",
                    # "PhysicalResourceId": "CFN-Parameter2",
                    # "Replacement": "False",
                    "ResourceType": "AWS::SSM::Parameter",
                    # "Scope": [
                    #     "Properties"
                    # ]
                },
                "Type": "Resource",
            },
        ]
        self.compare_changes(changes, target)

    def test_parameters_dynamic_change(self):
        t1 = {
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
        }
        changes = self.eval_change_set(
            t1, t1, {"ParameterValue": "value-1"}, {"ParameterValue": "value-2"}
        )
        target = [
            {
                "Type": "Resource",
                "ResourceChange": {
                    "Action": "Modify",
                    "LogicalResourceId": "Parameter",
                    # "PhysicalResourceId": "<physical-resource-id:1>",
                    "ResourceType": "AWS::SSM::Parameter",
                    # "Replacement": "False",
                    # "Scope": [
                    #     "Properties"
                    # ],
                    # "Details": [
                    #     {
                    #         "Target": {
                    #             "Attribute": "Properties",
                    #             "Name": "Value",
                    #             "RequiresRecreation": "Never",
                    #             "Path": "/Properties/Value",
                    #             "BeforeValue": "55252c2c",
                    #             "AfterValue": "f8679c0b",
                    #             "AttributeChangeType": "Modify"
                    #         },
                    #         "Evaluation": "Dynamic",
                    #         "ChangeSource": "DirectModification"
                    #     },
                    #     {
                    #         "Target": {
                    #             "Attribute": "Properties",
                    #             "Name": "Value",
                    #             "RequiresRecreation": "Never",
                    #             "Path": "/Properties/Value",
                    #             "BeforeValue": "55252c2c",
                    #             "AfterValue": "f8679c0b",
                    #             "AttributeChangeType": "Modify"
                    #         },
                    #         "Evaluation": "Static",
                    #         "ChangeSource": "ParameterReference",
                    #         "CausingEntity": "ParameterValue"
                    #     }
                    # ],
                    "BeforeContext": {"Properties": {"Value": "value-1", "Type": "String"}},
                    "AfterContext": {"Properties": {"Value": "value-2", "Type": "String"}},
                },
            }
        ]
        self.compare_changes(changes, target)

    def test_parameter_dynamic_change_unrelated_property(self):
        t1 = {
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
                        "Value": {"Fn::GetAtt": ["Parameter1", "Name"]},
                    },
                },
            },
        }
        changes = self.eval_change_set(
            t1, t1, {"ParameterValue": "value-1"}, {"ParameterValue": "value-2"}
        )
        target = [
            {
                "Type": "Resource",
                "ResourceChange": {
                    "Action": "Modify",
                    "LogicalResourceId": "Parameter1",
                    # "PhysicalResourceId": "<physical-resource-id:1>",
                    "ResourceType": "AWS::SSM::Parameter",
                    # "Replacement": "False",
                    # "Scope": [
                    #     "Properties"
                    # ],
                    # "Details": [
                    #     {
                    #         "Target": {
                    #             "Attribute": "Properties",
                    #             "Name": "Value",
                    #             "RequiresRecreation": "Never",
                    #             "Path": "/Properties/Value",
                    #             "BeforeValue": "49f3de25",
                    #             "AfterValue": "0e788b5d",
                    #             "AttributeChangeType": "Modify"
                    #         },
                    #         "Evaluation": "Static",
                    #         "ChangeSource": "ParameterReference",
                    #         "CausingEntity": "ParameterValue"
                    #     },
                    #     {
                    #         "Target": {
                    #             "Attribute": "Properties",
                    #             "Name": "Value",
                    #             "RequiresRecreation": "Never",
                    #             "Path": "/Properties/Value",
                    #             "BeforeValue": "49f3de25",
                    #             "AfterValue": "0e788b5d",
                    #             "AttributeChangeType": "Modify"
                    #         },
                    #         "Evaluation": "Dynamic",
                    #         "ChangeSource": "DirectModification"
                    #     }
                    # ],
                    "BeforeContext": {"Properties": {"Value": "value-1", "Type": "String"}},
                    "AfterContext": {"Properties": {"Value": "value-2", "Type": "String"}},
                },
            }
        ]
        self.compare_changes(changes, target)

    def test_parameter_dynamic_change_unrelated_property_not_create_only(self):
        t1 = {
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
        }
        changes = self.eval_change_set(
            t1, t1, {"ParameterValue": "value-1"}, {"ParameterValue": "value-2"}
        )
        target = [
            {
                "Type": "Resource",
                "ResourceChange": {
                    "Action": "Modify",
                    "LogicalResourceId": "Parameter1",
                    # "PhysicalResourceId": "<physical-resource-id:1>",
                    "ResourceType": "AWS::SSM::Parameter",
                    # "Replacement": "False",
                    # "Scope": [
                    #     "Properties"
                    # ],
                    # "Details": [
                    #     {
                    #         "Target": {
                    #             "Attribute": "Properties",
                    #             "Name": "Value",
                    #             "RequiresRecreation": "Never",
                    #             "Path": "/Properties/Value",
                    #             "BeforeValue": "d45ab5ec",
                    #             "AfterValue": "c77f207c",
                    #             "AttributeChangeType": "Modify"
                    #         },
                    #         "Evaluation": "Dynamic",
                    #         "ChangeSource": "DirectModification"
                    #     },
                    #     {
                    #         "Target": {
                    #             "Attribute": "Properties",
                    #             "Name": "Value",
                    #             "RequiresRecreation": "Never",
                    #             "Path": "/Properties/Value",
                    #             "BeforeValue": "d45ab5ec",
                    #             "AfterValue": "c77f207c",
                    #             "AttributeChangeType": "Modify"
                    #         },
                    #         "Evaluation": "Static",
                    #         "ChangeSource": "ParameterReference",
                    #         "CausingEntity": "ParameterValue"
                    #     }
                    # ],
                    "BeforeContext": {"Properties": {"Value": "value-1", "Type": "String"}},
                    "AfterContext": {"Properties": {"Value": "value-2", "Type": "String"}},
                },
            }
        ]
        self.compare_changes(changes, target)

    def test_parameter_root_change(self):
        t1 = {
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
        }
        changes = self.eval_change_set(
            t1, t1, {"ParameterValue": "value-1"}, {"ParameterValue": "value-2"}
        )
        target = [
            {
                "Type": "Resource",
                "ResourceChange": {
                    "Action": "Modify",
                    "LogicalResourceId": "Parameter1",
                    # "PhysicalResourceId": "<physical-resource-id:1>",
                    "ResourceType": "AWS::SSM::Parameter",
                    # "Replacement": "False",
                    # "Scope": [
                    #     "Properties"
                    # ],
                    # "Details": [
                    #     {
                    #         "Target": {
                    #             "Attribute": "Properties",
                    #             "Name": "Value",
                    #             "RequiresRecreation": "Never",
                    #             "Path": "/Properties/Value",
                    #             "BeforeValue": "d45ab5ec",
                    #             "AfterValue": "c77f207c",
                    #             "AttributeChangeType": "Modify"
                    #         },
                    #         "Evaluation": "Dynamic",
                    #         "ChangeSource": "DirectModification"
                    #     },
                    #     {
                    #         "Target": {
                    #             "Attribute": "Properties",
                    #             "Name": "Value",
                    #             "RequiresRecreation": "Never",
                    #             "Path": "/Properties/Value",
                    #             "BeforeValue": "d45ab5ec",
                    #             "AfterValue": "c77f207c",
                    #             "AttributeChangeType": "Modify"
                    #         },
                    #         "Evaluation": "Static",
                    #         "ChangeSource": "ParameterReference",
                    #         "CausingEntity": "ParameterValue"
                    #     }
                    # ],
                    "BeforeContext": {"Properties": {"Value": "value-1", "Type": "String"}},
                    "AfterContext": {"Properties": {"Value": "value-2", "Type": "String"}},
                },
            }
        ]
        self.compare_changes(changes, target)
