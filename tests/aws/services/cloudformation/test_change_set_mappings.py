from localstack_snapshot.snapshots.transformer import RegexTransformer
from tests.aws.services.cloudformation.conftest import skip_if_legacy_engine

from localstack.testing.pytest import markers
from localstack.utils.strings import long_uid


@skip_if_legacy_engine()
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "per-resource-events..*",
        "delete-describe..*",
        #
        # Before/After Context
        "$..Capabilities",
        "$..IncludeNestedStacks",
        "$..Scope",
        "$..Details",
        "$..Parameters",
        "$..Replacement",
        "$..PolicyAction",
    ]
)
class TestChangeSetMappings:
    @markers.aws.validated
    def test_mapping_leaf_update(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        template_1 = {
            "Mappings": {"SNSMapping": {"Key1": {"Val": "display-value-1"}}},
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                }
            },
        }
        template_2 = {
            "Mappings": {"SNSMapping": {"Key1": {"Val": "display-value-2"}}},
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                }
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_mapping_key_update(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        template_1 = {
            "Mappings": {"SNSMapping": {"Key1": {"Val": "display-value-1"}}},
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                }
            },
        }
        template_2 = {
            "Mappings": {"SNSMapping": {"KeyNew": {"Val": "display-value-2"}}},
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "KeyNew", "Val"]},
                    },
                }
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_mapping_addition_with_resource(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        template_1 = {
            "Mappings": {"SNSMapping": {"Key1": {"Val": "display-value-1"}}},
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                }
            },
        }
        template_2 = {
            "Mappings": {
                "SNSMapping": {"Key1": {"Val": "display-value-1", "ValNew": "display-value-new"}}
            },
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "ValNew"]},
                    },
                },
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_mapping_key_addition_with_resource(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        template_1 = {
            "Mappings": {"SNSMapping": {"Key1": {"Val": "display-value-1"}}},
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                }
            },
        }
        template_2 = {
            "Mappings": {
                "SNSMapping": {
                    "Key1": {
                        "Val": "display-value-1",
                    },
                    "Key2": {
                        "Val": "display-value-1",
                        "ValNew": "display-value-new",
                    },
                }
            },
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key2", "Val"]},
                    },
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key2", "ValNew"]},
                    },
                },
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_mapping_deletion_with_resource_remap(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        template_1 = {
            "Mappings": {
                "SNSMapping": {"Key1": {"Val": "display-value-1", "ValNew": "display-value-new"}}
            },
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "ValNew"]},
                    },
                },
            },
        }
        template_2 = {
            "Mappings": {"SNSMapping": {"Key1": {"Val": "display-value-1"}}},
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                },
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_mapping_key_deletion_with_resource_remap(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        template_1 = {
            "Mappings": {
                "SNSMapping": {
                    "Key1": {
                        "Val": "display-value-1",
                    },
                    "Key2": {"Val": "display-value-2"},
                }
            },
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key2", "Val"]},
                    },
                },
            },
        }
        template_2 = {
            "Mappings": {"SNSMapping": {"Key1": {"Val": "display-value-1"}}},
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                },
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.snapshot.skip_snapshot_verify(paths=["$..LastOperations"])
    @markers.aws.validated
    def test_fn_find_in_map_with_nested_ref(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))

        # Template mimicking the CloudFront/Route53 pattern from the bug report
        # This is the common CDK pattern for alias target hosted zone IDs
        template_1 = {
            "Mappings": {
                "AWSCloudFrontPartitionHostedZoneIdMap": {
                    "aws": {"zoneId": "Z2FDTNDATAQYW2"},
                    "aws-cn": {"zoneId": "Z3RFFRIM2A3IF5"},
                }
            },
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        # Using nested Ref - the problematic pattern
                        "DisplayName": {
                            "Fn::FindInMap": [
                                "AWSCloudFrontPartitionHostedZoneIdMap",
                                {"Ref": "AWS::Partition"},  # Nested Ref
                                "zoneId",
                            ]
                        },
                    },
                }
            },
        }

        # Change the TopicName to create an actual update
        # The key is that the FindInMap with nested Ref is processed without error
        template_2 = {
            "Mappings": {
                "AWSCloudFrontPartitionHostedZoneIdMap": {
                    "aws": {"zoneId": "Z2FDTNDATAQYW2"},
                    "aws-cn": {"zoneId": "Z3RFFRIM2A3IF5"},
                }
            },
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": f"{name1}-updated",  # Changed to trigger update
                        "DisplayName": {
                            "Fn::FindInMap": [
                                "AWSCloudFrontPartitionHostedZoneIdMap",
                                {"Ref": "AWS::Partition"},  # Still has nested Ref
                                "zoneId",
                            ]
                        },
                    },
                }
            },
        }

        # Before the fix, this would raise NotImplementedError when processing the changeset
        # After the fix, it successfully processes the changeset and detects the change
        capture_update_process(snapshot, template_1, template_2)

    @markers.snapshot.skip_snapshot_verify(paths=["$..LastOperations"])
    @markers.aws.validated
    def test_fn_find_in_map_with_nested_ref_change_mapping(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))

        template_1 = {
            "Mappings": {
                "RegionMap": {
                    "us-east-1": {"value": "east-value-1"},
                    "us-west-2": {"value": "west-value-1"},
                }
            },
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {
                            "Fn::FindInMap": [
                                "RegionMap",
                                {"Ref": "AWS::Region"},  # Nested Ref
                                "value",
                            ]
                        },
                    },
                }
            },
        }

        # Change the mapping values
        template_2 = {
            "Mappings": {
                "RegionMap": {
                    "us-east-1": {"value": "east-value-2"},  # Changed
                    "us-west-2": {"value": "west-value-2"},  # Changed
                }
            },
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {
                            "Fn::FindInMap": [
                                "RegionMap",
                                {"Ref": "AWS::Region"},
                                "value",
                            ]
                        },
                    },
                }
            },
        }

        # Should detect the mapping change and mark resource as modified
        capture_update_process(snapshot, template_1, template_2)

    @markers.snapshot.skip_snapshot_verify(paths=["$..LastOperations"])
    @markers.aws.validated
    def test_fn_find_in_map_with_multiple_nested_functions(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))

        template = {
            "Parameters": {
                "Environment": {
                    "Type": "String",
                }
            },
            "Mappings": {
                "ComplexMap": {
                    "prod": {"aws": "prod-aws-value"},
                    "dev": {"aws": "dev-aws-value"},
                }
            },
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {
                            "Fn::FindInMap": [
                                "ComplexMap",
                                {"Ref": "Environment"},  # Nested Ref to parameter
                                {"Ref": "AWS::Partition"},  # Another nested Ref
                            ]
                        },
                    },
                }
            },
        }

        # Change the parameter value to trigger an update
        # The nested Refs in FindInMap should still work without error
        capture_update_process(
            snapshot, template, template, p1={"Environment": "prod"}, p2={"Environment": "dev"}
        )
