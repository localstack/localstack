import json

from localstack.services.cloudformation.engine.v2.change_set_model import (
    ChangeSetModel,
    NodeTemplate,
)
from localstack.services.cloudformation.engine.v2.change_set_model_describer import (
    ChangeSetModelDescriber,
)


class TestCFNUpdatePlayground:
    def test_ssm_parameter_string_value_literal_change(self):
        t1 = {
            "Resources": {
                "Parameter1": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Name": "Parameter1",
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
                        "Name": "Parameter1",
                        "Type": "String",
                        "Value": "this is the new value",  # update value
                    },
                },
                "Parameter2": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Name": "Added parameter 2 name",  # added value
                        "Value": {
                            "Fn::GetAtt": ["Parameter3", "Value"]  # updated value in array args
                        },
                    },
                },
                "Parameter3": {  # added (resource)
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {"Fn::GetAtt": ["Parameter1", "Value"]},
                    },
                },
            },
        }

        change_set_model = ChangeSetModel(before_template=t1, after_template=t2)
        update_model: NodeTemplate = change_set_model.get_update_model()

        print(update_model)

        change_set_describer = ChangeSetModelDescriber()
        change_set_describer.visit(update_model)
        resource_changes = change_set_describer.resource_changes
        print(json.dumps(resource_changes, indent=4))
