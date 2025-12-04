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

    def test_lower_camelcase_to_pascalcase(self):
        original_dict = {
            "eventBusName": "my-event-bus",
            "targets": [
                {
                    "id": "an-id",
                }
            ],
        }

        converted_dict = utils.keys_lower_camelcase_to_pascalcase(original_dict)
        assert converted_dict == {
            "EventBusName": "my-event-bus",
            "Targets": [
                {
                    "Id": "an-id",
                }
            ],
        }

    def test_lower_camelcase_to_pascalcase_skip_keys(self):
        original_dict = {
            "Stages": [
                {
                    "Actions": [
                        {
                            "Actiontypeid": {
                                "Category": "Source",
                                "Owner": "AWS",
                                "Provider": "S3",
                                "Version": "1",
                            },
                            "Configuration": {
                                "S3bucket": "localstack-codepipeline-source-86a13a88",
                                "S3objectkey": "source-key",
                                "Subconfig": {"Subconfig1": "Foo", "Subconfig2": "bar"},
                            },
                            "Inputartifacts": [],
                            "Name": "S3Source",
                            "Namespace": "S3SourceVariables",
                            "Outputartifacts": [{"Name": "Artifact_Source_S3Source"}],
                            "Rolearn": "arn:aws:iam::096845016391:role/EcrPipelineStack-MyPipelineSourceS3SourceCodePipeli-YOoRQUZQe6WU",
                            "Runorder": 1,
                        }
                    ],
                    "Name": "Source",
                }
            ]
        }
        target_dict = {
            "stages": [
                {
                    "actions": [
                        {
                            "actiontypeid": {
                                "category": "Source",
                                "owner": "AWS",
                                "provider": "S3",
                                "version": "1",
                            },
                            # The excluded key itself is transformed
                            # Its values are not
                            # Recursion stops, items at lower levels are not transformed as well
                            "configuration": {
                                "S3bucket": "localstack-codepipeline-source-86a13a88",
                                "S3objectkey": "source-key",
                                "Subconfig": {"Subconfig1": "Foo", "Subconfig2": "bar"},
                            },
                            "inputartifacts": [],
                            "name": "S3Source",
                            "namespace": "S3SourceVariables",
                            "outputartifacts": [{"name": "Artifact_Source_S3Source"}],
                            "rolearn": "arn:aws:iam::096845016391:role/EcrPipelineStack-MyPipelineSourceS3SourceCodePipeli-YOoRQUZQe6WU",
                            "runorder": 1,
                        }
                    ],
                    "name": "Source",
                }
            ]
        }
        converted_dict = utils.keys_pascalcase_to_lower_camelcase(
            original_dict, skip_keys={"Configuration"}
        )
        assert converted_dict == target_dict

    def test_resource_tags_to_remove_or_update(self):
        previous = [
            {"Key": "k1", "Value": "v1"},
            {"Key": "k2", "Value": "v2"},
            {"Key": "k3", "Value": "v3"},
            {"Key": "k4", "Value": "v4"},
        ]
        desired = [{"Key": "k2", "Value": "v2-updated"}, {"Key": "k3", "Value": "v3"}]

        to_remove, to_update = utils.resource_tags_to_remove_or_update(previous, desired)

        assert sorted(to_remove) == ["k1", "k4"]
        assert to_update == {"k2": "v2-updated", "k3": "v3"}
