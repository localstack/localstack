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
        transformed_dict = utils.convert_request_kwargs(original_dict, input_shape)

        assert transformed_dict == {
            "EventBusName": "my-event-bus",
        }

    def test_convert_type_integers(self):
        svc_name = "efs"
        operation_name = "CreateAccessPoint"
        operation = boto3.client(svc_name).meta.service_model.operation_model(operation_name)
        input_shape = operation.input_shape
        original_dict = {
            "FileSystemId": "fs-29d6b02c",
            "PosixUser": {"Gid": "1322", "SecondaryGids": ["1344", "1452"], "Uid": "13234"},
            "RootDirectory": {
                "CreationInfo": {
                    "OwnerGid": "708798",
                    "OwnerUid": "7987987",
                    "Permissions": "0755",
                },
                "Path": "/testcfn/abc",
            },
        }
        transformed_dict = utils.convert_request_kwargs(original_dict, input_shape)
        assert transformed_dict == {
            "FileSystemId": "fs-29d6b02c",
            "PosixUser": {"Gid": 1322, "SecondaryGids": [1344, 1452], "Uid": 13234},
            "RootDirectory": {
                "CreationInfo": {"OwnerGid": 708798, "OwnerUid": 7987987, "Permissions": "0755"},
                "Path": "/testcfn/abc",
            },
        }

    def test_convert_type_boolean(self):
        svc_name = "events"
        operation_name = "PutTargets"
        operation = boto3.client(svc_name).meta.service_model.operation_model(operation_name)
        input_shape = operation.input_shape
        original_dict = {
            "EventBusName": "my-event-bus",
            "Targets": [
                {
                    "Id": "an-id",
                    "EcsParameters": {"EnableECSManagedTags": "false"},
                }
            ],
        }
        transformed_dict = utils.convert_request_kwargs(original_dict, input_shape)

        assert transformed_dict == {
            "EventBusName": "my-event-bus",
            "Targets": [
                {
                    "Id": "an-id",
                    "EcsParameters": {"EnableECSManagedTags": False},
                }
            ],
        }

    def test_convert_key_casing(self):
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
        transformed_dict = utils.convert_request_kwargs(original_dict, input_shape)

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
