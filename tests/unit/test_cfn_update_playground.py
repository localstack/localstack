import json

from localstack.services.cloudformation.engine.playground_update import (
    ChangeSetDescribeVisitor,
    ChangeSetModeler,
    NodeTemplate,
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
                            "Fn::GetAtt": ["I changed this to Parameter3", "Value"]
                        },  # added value in array args
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

        node_template: NodeTemplate = ChangeSetModeler().model(
            before_template=t1, after_template=t2
        )
        print(node_template)

        change_set_describer = ChangeSetDescribeVisitor()
        change_set_describer.visit(node_template)
        print(json.dumps(change_set_describer.changes, indent=4))
