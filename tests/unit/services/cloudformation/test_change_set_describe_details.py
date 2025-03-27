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
from localstack.services.cloudformation.engine.v2.change_set_model_processor import (
    ResolvedEntityDelta,
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
        changes = change_set_describer.get_changes()
        # TODO
        json_str = json.dumps(changes)
        return json.loads(json_str)

    @staticmethod
    def debug_outputs(
        before_template: Optional[dict],
        after_template: Optional[dict],
        before_parameters: Optional[dict] = None,
        after_parameters: Optional[dict] = None,
    ) -> ResolvedEntityDelta:
        change_set_model = ChangeSetModel(
            before_template=before_template,
            after_template=after_template,
            before_parameters=before_parameters,
            after_parameters=after_parameters,
        )
        update_model: NodeTemplate = change_set_model.get_update_model()
        outputs_unit = ChangeSetModelDescriber(update_model).visit(update_model.outputs)
        return outputs_unit

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
                    "BeforeContext": {
                        "Properties": {"Name": "param-name", "Value": "value-1", "Type": "String"}
                    },
                    "AfterContext": {
                        "Properties": {"Name": "param-name", "Value": "value-2", "Type": "String"}
                    },
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

    def test_condition_parameter_delete_resource(self):
        t1 = {
            "Parameters": {
                "CreateParameter": {
                    "Type": "String",
                    "Default": "value-1",
                    "AllowedValues": ["value-1", "value-2"],
                }
            },
            "Conditions": {
                "ShouldCreateParameter": {"Fn::Equals": [{"Ref": "CreateParameter"}, "value-1"]}
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
        }
        changes = self.eval_change_set(
            t1, t1, {"CreateParameter": "value-1"}, {"CreateParameter": "value-2"}
        )
        target = [
            {
                "Type": "Resource",
                "ResourceChange": {
                    # "PolicyAction": "Delete",
                    "Action": "Remove",
                    "LogicalResourceId": "SSMParameter2",
                    # "PhysicalResourceId": "<physical-resource-id:1>",
                    "ResourceType": "AWS::SSM::Parameter",
                    # "Scope": [],
                    # "Details": [],
                    "BeforeContext": {"Properties": {"Value": "first", "Type": "String"}},
                },
            }
        ]
        self.compare_changes(changes, target)

    def test_condition_parameter_create_resource(self):
        t1 = {
            "Parameters": {
                "CreateParameter": {
                    "Type": "String",
                    "Default": "value-1",
                    "AllowedValues": ["value-1", "value-2"],
                }
            },
            "Conditions": {
                "ShouldCreateParameter": {"Fn::Equals": [{"Ref": "CreateParameter"}, "value-2"]}
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
        }
        changes = self.eval_change_set(
            t1, t1, {"CreateParameter": "value-1"}, {"CreateParameter": "value-2"}
        )
        target = [
            {
                "Type": "Resource",
                "ResourceChange": {
                    "Action": "Add",
                    "LogicalResourceId": "SSMParameter2",
                    "ResourceType": "AWS::SSM::Parameter",
                    # "Replacement": "True",
                    # "Scope": [],
                    # "Details": [],
                    "AfterContext": {"Properties": {"Value": "first", "Type": "String"}},
                },
            }
        ]
        self.compare_changes(changes, target)

    def test_condition_update_create_resource(self):
        t1 = {
            "Parameters": {
                "CreateParameter": {
                    "Type": "String",
                    "AllowedValues": ["value-1", "value-2"],
                }
            },
            "Conditions": {
                "ShouldCreateParameter": {"Fn::Equals": [{"Ref": "CreateParameter"}, "value-2"]}
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
        }
        t2 = {
            "Parameters": {
                "CreateParameter": {
                    "Type": "String",
                    "AllowedValues": ["value-1", "value-2"],
                }
            },
            "Conditions": {
                "ShouldCreateParameter": {"Fn::Equals": [{"Ref": "CreateParameter"}, "value-1"]}
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
        }
        changes = self.eval_change_set(
            t1, t2, {"CreateParameter": "value-1"}, {"CreateParameter": "value-1"}
        )
        target = [
            {
                "Type": "Resource",
                "ResourceChange": {
                    "Action": "Add",
                    "LogicalResourceId": "SSMParameter2",
                    "ResourceType": "AWS::SSM::Parameter",
                    # "Replacement": "True",
                    # "Scope": [],
                    # "Details": [],
                    "AfterContext": {"Properties": {"Value": "first", "Type": "String"}},
                },
            }
        ]
        self.compare_changes(changes, target)

    def test_condition_update_delete_resource(self):
        t1 = {
            "Parameters": {
                "CreateParameter": {
                    "Type": "String",
                    "AllowedValues": ["value-1", "value-2"],
                }
            },
            "Conditions": {
                "ShouldCreateParameter": {"Fn::Equals": [{"Ref": "CreateParameter"}, "value-1"]}
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
        }
        t2 = {
            "Parameters": {
                "CreateParameter": {
                    "Type": "String",
                    "AllowedValues": ["value-1", "value-2"],
                }
            },
            "Conditions": {
                "ShouldCreateParameter": {"Fn::Equals": [{"Ref": "CreateParameter"}, "value-2"]}
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
        }
        changes = self.eval_change_set(
            t1, t2, {"CreateParameter": "value-1"}, {"CreateParameter": "value-1"}
        )
        target = [
            {
                "Type": "Resource",
                "ResourceChange": {
                    # "PolicyAction": "Delete",
                    "Action": "Remove",
                    "LogicalResourceId": "SSMParameter2",
                    # "PhysicalResourceId": "<physical-resource-id:1>",
                    "ResourceType": "AWS::SSM::Parameter",
                    # "Scope": [],
                    # "Details": [],
                    "BeforeContext": {"Properties": {"Value": "first", "Type": "String"}},
                },
            }
        ]
        self.compare_changes(changes, target)

    def test_condition_bound_property_assignment_parameter_modified(self):
        t1 = {
            "Parameters": {
                "UseProductionValue": {
                    "Type": "String",
                    "AllowedValues": ["true", "false"],
                    "Default": "false",
                }
            },
            "Conditions": {"IsProduction": {"Fn::Equals": [{"Ref": "UseProductionValue"}, "true"]}},
            "Resources": {
                "MySSMParameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {
                            "Fn::If": [
                                "IsProduction",
                                "ProductionParameterValue",
                                "StagingParameterValue",
                            ]
                        },
                    },
                }
            },
        }
        changes = self.eval_change_set(
            t1, t1, {"UseProductionValue": "false"}, {"UseProductionValue": "true"}
        )
        target = [
            {
                "Type": "Resource",
                "ResourceChange": {
                    "Action": "Modify",
                    "LogicalResourceId": "MySSMParameter",
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
                    #             "BeforeValue": "StagingParameterValue",
                    #             "AfterValue": "ProductionParameterValue",
                    #             "AttributeChangeType": "Modify"
                    #         },
                    #         "Evaluation": "Static",
                    #         "ChangeSource": "DirectModification"
                    #     }
                    # ],
                    "BeforeContext": {
                        "Properties": {"Value": "StagingParameterValue", "Type": "String"}
                    },
                    "AfterContext": {
                        "Properties": {"Value": "ProductionParameterValue", "Type": "String"}
                    },
                },
            }
        ]
        self.compare_changes(changes, target)

    def test_condition_bound_property_assignment_modified(self):
        t1 = {
            "Parameters": {
                "UseProductionValue": {
                    "Type": "String",
                    "AllowedValues": ["true", "false"],
                    "Default": "false",
                }
            },
            "Conditions": {"IsProduction": {"Fn::Equals": [{"Ref": "UseProductionValue"}, "true"]}},
            "Resources": {
                "MySSMParameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {
                            "Fn::If": [
                                "IsProduction",
                                "ProductionParameterValue",
                                "StagingParameterValue",
                            ]
                        },
                    },
                }
            },
        }
        t2 = {
            "Parameters": {
                "UseProductionValue": {
                    "Type": "String",
                    "AllowedValues": ["true", "false"],
                    "Default": "false",
                }
            },
            "Conditions": {
                "IsProduction": {"Fn::Equals": [{"Ref": "UseProductionValue"}, "false"]}
            },
            "Resources": {
                "MySSMParameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {
                            "Fn::If": [
                                "IsProduction",
                                "ProductionParameterValue",
                                "StagingParameterValue",
                            ]
                        },
                    },
                }
            },
        }
        changes = self.eval_change_set(
            t1, t2, {"UseProductionValue": "false"}, {"UseProductionValue": "false"}
        )
        target = [
            {
                "Type": "Resource",
                "ResourceChange": {
                    "Action": "Modify",
                    "LogicalResourceId": "MySSMParameter",
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
                    #             "BeforeValue": "StagingParameterValue",
                    #             "AfterValue": "ProductionParameterValue",
                    #             "AttributeChangeType": "Modify"
                    #         },
                    #         "Evaluation": "Static",
                    #         "ChangeSource": "DirectModification"
                    #     }
                    # ],
                    "BeforeContext": {
                        "Properties": {"Value": "StagingParameterValue", "Type": "String"}
                    },
                    "AfterContext": {
                        "Properties": {"Value": "ProductionParameterValue", "Type": "String"}
                    },
                },
            }
        ]
        self.compare_changes(changes, target)

    def test_condition_update_production_remove_resource(self):
        t1 = {
            "Parameters": {
                "CreateParameter": {
                    "Type": "String",
                    "AllowedValues": ["value-1", "value-2"],
                }
            },
            "Conditions": {
                "ShouldCreateParameter": {"Fn::Equals": [{"Ref": "CreateParameter"}, "value-1"]}
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
        }
        t2 = {
            "Parameters": {
                "CreateParameter": {
                    "Type": "String",
                    "AllowedValues": ["value-1", "value-2"],
                }
            },
            "Conditions": {
                "ShouldCreateParameter": {
                    "Fn::Not": [{"Fn::Equals": [{"Ref": "CreateParameter"}, "value-1"]}]
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
        }
        changes = self.eval_change_set(
            t1, t2, {"CreateParameter": "value-1"}, {"CreateParameter": "value-1"}
        )
        target = [
            {
                "Type": "Resource",
                "ResourceChange": {
                    # "PolicyAction": "Delete",
                    "Action": "Remove",
                    "LogicalResourceId": "SSMParameter2",
                    # "PhysicalResourceId": "<physical-resource-id:1>",
                    "ResourceType": "AWS::SSM::Parameter",
                    # "Scope": [],
                    # "Details": [],
                    "BeforeContext": {"Properties": {"Value": "first", "Type": "String"}},
                },
            }
        ]
        self.compare_changes(changes, target)

    def test_output_new_resource_and_output(self):
        t1 = {
            "Resources": {
                "UnrelatedParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "unrelated-param", "Type": "String", "Value": "foo"},
                }
            }
        }
        t2 = {
            "Resources": {
                "UnrelatedParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "unrelated-param", "Type": "String", "Value": "foo"},
                },
                "NewParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "param-name", "Type": "String", "Value": "value-1"},
                },
            },
            "Outputs": {"NewParamName": {"Value": {"Ref": "NewParam"}}},
        }
        outputs_unit = self.debug_outputs(t1, t2)
        assert not outputs_unit.before
        assert outputs_unit.after == [{"Name": "NewParamName", "Value": "NewParam"}]

    def test_output_and_resource_removed(self):
        t1 = {
            "Resources": {
                "FeatureToggle": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Name": "app-feature-toggle",
                        "Type": "String",
                        "Value": "enabled",
                    },
                },
                "UnrelatedParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "unrelated-param", "Type": "String", "Value": "foo"},
                },
            },
            "Outputs": {"FeatureToggleName": {"Value": {"Ref": "FeatureToggle"}}},
        }
        t2 = {
            "Resources": {
                "UnrelatedParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "unrelated-param", "Type": "String", "Value": "foo"},
                }
            }
        }
        outputs_unit = self.debug_outputs(t1, t2)
        assert outputs_unit.before == [{"Name": "FeatureToggleName", "Value": "FeatureToggle"}]
        assert outputs_unit.after == []

    def test_output_resource_changed(self):
        t1 = {
            "Resources": {
                "LogLevelParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "app-log-level", "Type": "String", "Value": "info"},
                },
                "UnrelatedParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "unrelated-param", "Type": "String", "Value": "foo"},
                },
            },
            "Outputs": {"LogLevelOutput": {"Value": {"Ref": "LogLevelParam"}}},
        }
        t2 = {
            "Resources": {
                "LogLevelParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "app-log-level", "Type": "String", "Value": "debug"},
                },
                "UnrelatedParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "unrelated-param", "Type": "String", "Value": "foo"},
                },
            },
            "Outputs": {"LogLevelOutput": {"Value": {"Ref": "LogLevelParam"}}},
        }
        outputs_unit = self.debug_outputs(t1, t2)
        assert outputs_unit.before == [{"Name": "LogLevelOutput", "Value": "LogLevelParam"}]
        assert outputs_unit.after == [{"Name": "LogLevelOutput", "Value": "LogLevelParam"}]

    def test_output_update(self):
        t1 = {
            "Resources": {
                "EnvParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "app-env", "Type": "String", "Value": "prod"},
                },
                "UnrelatedParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "unrelated-param", "Type": "String", "Value": "foo"},
                },
            },
            "Outputs": {"EnvParamRef": {"Value": {"Ref": "EnvParam"}}},
        }

        t2 = {
            "Resources": {
                "EnvParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "app-env", "Type": "String", "Value": "prod"},
                },
                "UnrelatedParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "unrelated-param", "Type": "String", "Value": "foo"},
                },
            },
            "Outputs": {"EnvParamRef": {"Value": {"Fn::GetAtt": ["EnvParam", "Name"]}}},
        }
        outputs_unit = self.debug_outputs(t1, t2)
        assert outputs_unit.before == [{"Name": "EnvParamRef", "Value": "EnvParam"}]
        assert outputs_unit.after == [
            {"Name": "EnvParamRef", "Value": "{{changeSet:KNOWN_AFTER_APPLY}}"}
        ]

    def test_output_renamed(self):
        t1 = {
            "Resources": {
                "SSMParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "some-param", "Type": "String", "Value": "value"},
                },
                "UnrelatedParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "unrelated-param", "Type": "String", "Value": "foo"},
                },
            },
            "Outputs": {"OldSSMOutput": {"Value": {"Ref": "SSMParam"}}},
        }
        t2 = {
            "Resources": {
                "SSMParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "some-param", "Type": "String", "Value": "value"},
                },
                "UnrelatedParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "unrelated-param", "Type": "String", "Value": "foo"},
                },
            },
            "Outputs": {"NewSSMOutput": {"Value": {"Ref": "SSMParam"}}},
        }
        outputs_unit = self.debug_outputs(t1, t2)
        assert outputs_unit.before == [{"Name": "OldSSMOutput", "Value": "SSMParam"}]
        assert outputs_unit.after == [{"Name": "NewSSMOutput", "Value": "SSMParam"}]

    def test_output_and_resource_renamed(self):
        t1 = {
            "Resources": {
                "DBPasswordParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "db-password", "Type": "String", "Value": "secret"},
                },
                "UnrelatedParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "unrelated-param", "Type": "String", "Value": "foo"},
                },
            },
            "Outputs": {"DBPasswordOutput": {"Value": {"Ref": "DBPasswordParam"}}},
        }
        t2 = {
            "Resources": {
                "DatabaseSecretParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "db-password", "Type": "String", "Value": "secret"},
                },
                "UnrelatedParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "unrelated-param", "Type": "String", "Value": "foo"},
                },
            },
            "Outputs": {"DatabaseSecretOutput": {"Value": {"Ref": "DatabaseSecretParam"}}},
        }
        outputs_unit = self.debug_outputs(t1, t2)
        assert outputs_unit.before == [{"Name": "DBPasswordOutput", "Value": "DBPasswordParam"}]
        assert outputs_unit.after == [
            {"Name": "DatabaseSecretOutput", "Value": "DatabaseSecretParam"}
        ]

    def test_mappings_update_string_referencing_resource(self):
        t1 = {
            "Mappings": {"GenericMapping": {"EnvironmentA": {"ParameterValue": "value-1"}}},
            "Resources": {
                "MySSMParameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {
                            "Fn::FindInMap": ["GenericMapping", "EnvironmentA", "ParameterValue"]
                        },
                    },
                }
            },
        }
        t2 = {
            "Mappings": {"GenericMapping": {"EnvironmentA": {"ParameterValue": "value-2"}}},
            "Resources": {
                "MySSMParameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {
                            "Fn::FindInMap": ["GenericMapping", "EnvironmentA", "ParameterValue"]
                        },
                    },
                }
            },
        }
        changes = self.eval_change_set(t1, t2)
        target = [
            {
                "Type": "Resource",
                "ResourceChange": {
                    "Action": "Modify",
                    "LogicalResourceId": "MySSMParameter",
                    # "PhysicalResourceId": "<physical-resource-id:1>",
                    "ResourceType": "AWS::SSM::Parameter",
                    # "Replacement": "False",
                    # "Scope": [
                    #   "Properties"
                    # ],
                    # "Details": [
                    #   {
                    #     "Target": {
                    #       "Attribute": "Properties",
                    #       "Name": "Value",
                    #       "RequiresRecreation": "Never",
                    #       "Path": "/Properties/Value",
                    #       "BeforeValue": "value-1",
                    #       "AfterValue": "value-2",
                    #       "AttributeChangeType": "Modify"
                    #     },
                    #     "Evaluation": "Static",
                    #     "ChangeSource": "DirectModification"
                    #   }
                    # ],
                    "BeforeContext": {"Properties": {"Value": "value-1", "Type": "String"}},
                    "AfterContext": {"Properties": {"Value": "value-2", "Type": "String"}},
                },
            }
        ]
        self.compare_changes(changes, target)

    def test_mappings_update_type_referencing_resource(self):
        t1 = {
            "Mappings": {"GenericMapping": {"EnvironmentA": {"ParameterValue": "value-1"}}},
            "Resources": {
                "MySSMParameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {
                            "Fn::FindInMap": ["GenericMapping", "EnvironmentA", "ParameterValue"]
                        },
                    },
                }
            },
        }
        t2 = {
            "Mappings": {
                "GenericMapping": {"EnvironmentA": {"ParameterValue": ["value-1", "value-2"]}}
            },
            "Resources": {
                "MySSMParameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {
                            "Fn::FindInMap": ["GenericMapping", "EnvironmentA", "ParameterValue"]
                        },
                    },
                }
            },
        }
        changes = self.eval_change_set(t1, t2)
        target = [
            {
                "Type": "Resource",
                "ResourceChange": {
                    "Action": "Modify",
                    "LogicalResourceId": "MySSMParameter",
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
                    #             "BeforeValue": "value-1",
                    #             "AfterValue": "[value-1, value-2]",
                    #             "AttributeChangeType": "Modify"
                    #         },
                    #         "Evaluation": "Static",
                    #         "ChangeSource": "DirectModification"
                    #     }
                    # ],
                    "BeforeContext": {"Properties": {"Value": "value-1", "Type": "String"}},
                    "AfterContext": {
                        "Properties": {"Value": ["value-1", "value-2"], "Type": "String"}
                    },
                },
            }
        ]
        self.compare_changes(changes, target)

    @pytest.mark.skip(reason="Add support for nested intrinsic functions")
    def test_mappings_update_referencing_resource_through_parameter(self):
        t1 = {
            "Parameters": {
                "Environment": {
                    "Type": "String",
                    "AllowedValues": [
                        "EnvironmentA",
                    ],
                }
            },
            "Mappings": {
                "GenericMapping": {
                    "EnvironmentA": {"ParameterValue": "value-1"},
                    "EnvironmentB": {"ParameterValue": "value-2"},
                }
            },
            "Resources": {
                "MySSMParameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {
                            "Fn::FindInMap": [
                                "GenericMapping",
                                {"Ref": "Environment"},
                                "ParameterValue",
                            ]
                        },
                    },
                }
            },
        }
        t2 = {
            "Parameters": {
                "Environment": {
                    "Type": "String",
                    "AllowedValues": ["EnvironmentA", "EnvironmentB"],
                    "Default": "EnvironmentA",
                }
            },
            "Mappings": {
                "GenericMapping": {
                    "EnvironmentA": {"ParameterValue": "value-1-2"},
                    "EnvironmentB": {"ParameterValue": "value-2"},
                }
            },
            "Resources": {
                "MySSMParameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {
                            "Fn::FindInMap": [
                                "GenericMapping",
                                {"Ref": "Environment"},
                                "ParameterValue",
                            ]
                        },
                    },
                }
            },
        }
        changes = self.eval_change_set(
            t1, t2, {"Environment": "EnvironmentA"}, {"Environment": "EnvironmentA"}
        )
        target = [
            {
                "Type": "Resource",
                "ResourceChange": {
                    "Action": "Modify",
                    "LogicalResourceId": "MySSMParameter",
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
                    #             "BeforeValue": "value-1",
                    #             "AfterValue": "value-1-2",
                    #             "AttributeChangeType": "Modify"
                    #         },
                    #         "Evaluation": "Static",
                    #         "ChangeSource": "DirectModification"
                    #     }
                    # ],
                    "BeforeContext": {"Properties": {"Value": "value-1", "Type": "String"}},
                    "AfterContext": {"Properties": {"Value": "value-1-2", "Type": "String"}},
                },
            }
        ]
        self.compare_changes(changes, target)
