import boto3

import localstack.services.cloudformation.provider_utils as utils


class TestDictUtils:
    def test_convert_values_to_numbers(self):
        original = {"Parameter": "1", "SecondParameter": ["2", "2"], "ThirdParameter": "3"}
        transformed = utils.convert_values_to_numbers(original, ["ThirdParameter"])

        assert transformed == {"Parameter": 1, "SecondParameter": [2, 2], "ThirdParameter": "3"}

    def test_drop_unknown(self):
        svc_name = "events"
        operation_name = "PutTargets"
        operation = boto3.client(svc_name).meta.service_model.operation_model(operation_name)
        input_shape = operation.input_shape
        original_dict = {
            "EventBusName": "my-event-bus",
            "UnknownKey": "somevalue",
        }
        transformed_dict = utils.fix_casing_for_boto_request_parameters(original_dict, input_shape)

        assert transformed_dict == {
            "EventBusName": "my-event-bus",
        }

    def test_transform_casing(self):
        svc_name = "events"
        operation_name = "PutTargets"
        operation = boto3.client(svc_name).meta.service_model.operation_model(operation_name)
        input_shape = operation.input_shape
        original_dict = {
            "EventBusName": "my-event-bus",
            "Targets": [
                {
                    "Id": "an-id",
                    "EcsParameters": {
                        "NetworkConfiguration": {
                            "AwsVpcConfiguration": {  # wrong casing!
                                "AssignPublicIp": "ENABLED",
                            }
                        }
                    },
                }
            ],
        }
        transformed_dict = utils.fix_casing_for_boto_request_parameters(original_dict, input_shape)

        assert transformed_dict == {
            "EventBusName": "my-event-bus",
            "Targets": [
                {
                    "Id": "an-id",
                    "EcsParameters": {
                        "NetworkConfiguration": {
                            "awsvpcConfiguration": {  # fixed casing
                                "AssignPublicIp": "ENABLED",
                            }
                        }
                    },
                }
            ],
        }
