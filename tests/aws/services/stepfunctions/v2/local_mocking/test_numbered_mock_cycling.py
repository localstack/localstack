"""
Test for cycling through numbered mock responses in Step Functions Local.
Fixes GitHub issue #13107: Step Functions Mock Responses Not Cycling Through Numbered Responses
"""

import json

from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack import config
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    create_and_record_mocked_execution,
)
from localstack.utils.strings import short_uid


@markers.snapshot.skip_snapshot_verify(
    paths=["$..SdkHttpMetadata", "$..SdkResponseMetadata"]
)
@markers.requires_in_process
class TestNumberedMockCycling:
    @markers.aws.only_localstack
    def test_numbered_mock_responses_cycle_correctly(
        self,
        aws_client,
        create_state_machine_iam_role,
        create_state_machine,
        sfn_snapshot,
        monkeypatch,
        mock_config_file,
    ):
        """
        Test that numbered mock responses ("0", "1", "2", etc.) cycle correctly
        through multiple invocations of the same state, not based on retry count.
        
        This test verifies the fix for issue #13107 where mock responses were incorrectly
        using RetryCount instead of an invocation counter, causing all calls to return
        the same response ("0") instead of cycling through the sequence.
        """
        state_machine_name = f"mock_cycling_test_{short_uid()}"
        test_name = "NumberedResponseCyclingTest"
        
        sfn_snapshot.add_transformer(RegexTransformer(state_machine_name, "state_machine_name"))
        
        # Define a state machine with a Choice state that loops until the instance is running
        definition = {
            "Comment": "Test numbered mock response cycling",
            "StartAt": "DescribeInstance",
            "States": {
                "DescribeInstance": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::aws-sdk:ec2:describeInstances",
                    "Parameters": {
                        "InstanceIds": ["i-1234567890abcdef0"]
                    },
                    "ResultPath": "$.DescribeResult",
                    "Next": "CheckInstanceState"
                },
                "CheckInstanceState": {
                    "Type": "Choice",
                    "Choices": [
                        {
                            "Variable": "$.DescribeResult.Reservations[0].Instances[0].State.Code",
                            "NumericEquals": 16,
                            "Next": "InstanceRunning"
                        }
                    ],
                    "Default": "DescribeInstance"
                },
                "InstanceRunning": {
                    "Type": "Succeed"
                }
            }
        }
        
        # Mock configuration with numbered responses
        # Response "0": Instance in pending state (Code: 0)
        # Response "1": Instance in running state (Code: 16)
        mock_config = {
            "StateMachines": {
                state_machine_name: {
                    "TestCases": {
                        test_name: {
                            "DescribeInstance": "MockDescribeInstancesProgression"
                        }
                    }
                }
            },
            "MockedResponses": {
                "MockDescribeInstancesProgression": {
                    "0": {
                        "Return": {
                            "Reservations": [
                                {
                                    "Instances": [
                                        {
                                            "InstanceId": "i-1234567890abcdef0",
                                            "InstanceType": "t2.micro",
                                            "LaunchTime": "2023-01-01T00:00:00.000Z",
                                            "State": {
                                                "Code": 0,
                                                "Name": "pending"
                                            }
                                        }
                                    ]
                                }
                            ]
                        }
                    },
                    "1": {
                        "Return": {
                            "Reservations": [
                                {
                                    "Instances": [
                                        {
                                            "InstanceId": "i-1234567890abcdef0",
                                            "InstanceType": "t2.micro",
                                            "LaunchTime": "2023-01-01T00:00:00.000Z",
                                            "State": {
                                                "Code": 16,
                                                "Name": "running"
                                            }
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                }
            }
        }
        
        mock_config_file_path = mock_config_file(mock_config)
        monkeypatch.setattr(config, "SFN_MOCK_CONFIG", mock_config_file_path)
        
        exec_input = json.dumps({})
        definition_str = json.dumps(definition)
        
        create_and_record_mocked_execution(
            aws_client,
            create_state_machine_iam_role,
            create_state_machine,
            sfn_snapshot,
            definition_str,
            exec_input,
            state_machine_name,
            test_name,
        )

    @markers.aws.only_localstack
    def test_multiple_numbered_responses_in_sequence(
        self,
        aws_client,
        create_state_machine_iam_role,
        create_state_machine,
        sfn_snapshot,
        monkeypatch,
        mock_config_file,
    ):
        """
        Test that multiple numbered responses (3+) cycle correctly through invocations.
        """
        state_machine_name = f"multi_mock_cycling_test_{short_uid()}"
        test_name = "MultipleNumberedResponsesTest"
        
        sfn_snapshot.add_transformer(RegexTransformer(state_machine_name, "state_machine_name"))
        
        # State machine that will call GetQueueUrl multiple times
        definition = {
            "Comment": "Test multiple numbered mock responses",
            "StartAt": "GetQueueUrl1",
            "States": {
                "GetQueueUrl1": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::aws-sdk:sqs:getQueueUrl",
                    "Parameters": {
                        "QueueName": "test-queue"
                    },
                    "ResultPath": "$.QueueUrl1",
                    "Next": "GetQueueUrl2"
                },
                "GetQueueUrl2": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::aws-sdk:sqs:getQueueUrl",
                    "Parameters": {
                        "QueueName": "test-queue"
                    },
                    "ResultPath": "$.QueueUrl2",
                    "Next": "GetQueueUrl3"
                },
                "GetQueueUrl3": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::aws-sdk:sqs:getQueueUrl",
                    "Parameters": {
                        "QueueName": "test-queue"
                    },
                    "ResultPath": "$.QueueUrl3",
                    "Next": "Success"
                },
                "Success": {
                    "Type": "Succeed"
                }
            }
        }
        
        # Mock config with 3 different responses
        mock_config = {
            "StateMachines": {
                state_machine_name: {
                    "TestCases": {
                        test_name: {
                            "GetQueueUrl1": "MockQueueUrlResponses",
                            "GetQueueUrl2": "MockQueueUrlResponses",
                            "GetQueueUrl3": "MockQueueUrlResponses"
                        }
                    }
                }
            },
            "MockedResponses": {
                "MockQueueUrlResponses": {
                    "0": {
                        "Return": {
                            "QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/queue-0"
                        }
                    },
                    "1": {
                        "Return": {
                            "QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/queue-1"
                        }
                    },
                    "2": {
                        "Return": {
                            "QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/queue-2"
                        }
                    }
                }
            }
        }
        
        mock_config_file_path = mock_config_file(mock_config)
        monkeypatch.setattr(config, "SFN_MOCK_CONFIG", mock_config_file_path)
        
        exec_input = json.dumps({})
        definition_str = json.dumps(definition)
        
        create_and_record_mocked_execution(
            aws_client,
            create_state_machine_iam_role,
            create_state_machine,
            sfn_snapshot,
            definition_str,
            exec_input,
            state_machine_name,
            test_name,
        )
