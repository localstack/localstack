"""
Test-driven development for CloudFormation deployment timing fix.

This module tests the fix for the bug where CloudFormation fails to deploy
complex API Gateway templates due to circular dependency resolution loops
when trying to resolve immediately available attributes like RootResourceId.
"""

import pytest

from localstack.testing.pytest import markers


class TestImmediatelyAvailableAttributes:
    """Test that immediately available attributes can be resolved during deployment."""

    @markers.aws.validated
    def test_api_gateway_root_resource_id_dependency(self, deploy_cfn_template, aws_client):
        """
        Test that RootResourceId can be accessed immediately after RestApi creation.

        This reproduces the bug described in localstack_fix.md where complex API Gateway
        templates fail with "Resource deployment loop completed" errors.
        """
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "MyApi": {"Type": "AWS::ApiGateway::RestApi", "Properties": {"Name": "TestApi"}},
                "MyResource": {
                    "Type": "AWS::ApiGateway::Resource",
                    "Properties": {
                        "RestApiId": {"Ref": "MyApi"},
                        "ParentId": {"Fn::GetAtt": ["MyApi", "RootResourceId"]},
                        "PathPart": "test",
                    },
                },
            },
            "Outputs": {
                "ApiId": {"Value": {"Ref": "MyApi"}},
                "RootResourceId": {"Value": {"Fn::GetAtt": ["MyApi", "RootResourceId"]}},
                "ResourceId": {"Value": {"Ref": "MyResource"}},
            },
        }

        # This should not raise DependencyNotYetSatisfied exceptions
        stack = deploy_cfn_template(template=template)

        # Verify the stack deployed successfully
        assert stack.outputs["ApiId"]
        assert stack.outputs["RootResourceId"]
        assert stack.outputs["ResourceId"]

        # Verify the API Gateway resources were created correctly
        api_id = stack.outputs["ApiId"]
        root_resource_id = stack.outputs["RootResourceId"]

        # Verify the API exists
        api = aws_client.apigateway.get_rest_api(restApiId=api_id)
        assert api["name"] == "TestApi"

        # Verify the root resource ID matches
        resources = aws_client.apigateway.get_resources(restApiId=api_id)
        root_resources = [
            r for r in resources["items"] if r["path"] == "/" and not r.get("parentId")
        ]
        assert len(root_resources) == 1
        assert root_resources[0]["id"] == root_resource_id

        # Verify the child resource was created with correct parent
        child_resources = [r for r in resources["items"] if r["path"] == "/test"]
        assert len(child_resources) == 1
        assert child_resources[0]["parentId"] == root_resource_id

    @markers.aws.validated
    def test_s3_bucket_immediate_attributes_dependency(self, deploy_cfn_template, aws_client):
        """
        Test that S3 bucket attributes like Arn, DomainName can be accessed immediately.

        This tests the broader class of immediately available attributes beyond just API Gateway.
        """
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "MyBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"BucketName": "test-bucket-immediate-attrs"},
                },
                "MyBucketPolicy": {
                    "Type": "AWS::S3::BucketPolicy",
                    "Properties": {
                        "Bucket": {"Ref": "MyBucket"},
                        "PolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": "*",
                                    "Action": "s3:GetObject",
                                    "Resource": {
                                        "Fn::Sub": [
                                            "${BucketArn}/*",
                                            {"BucketArn": {"Fn::GetAtt": ["MyBucket", "Arn"]}},
                                        ]
                                    },
                                }
                            ]
                        },
                    },
                },
            },
            "Outputs": {
                "BucketArn": {"Value": {"Fn::GetAtt": ["MyBucket", "Arn"]}},
                "BucketDomainName": {"Value": {"Fn::GetAtt": ["MyBucket", "DomainName"]}},
                "BucketWebsiteURL": {"Value": {"Fn::GetAtt": ["MyBucket", "WebsiteURL"]}},
            },
        }

        # This should not raise DependencyNotYetSatisfied exceptions
        stack = deploy_cfn_template(template=template)

        # Verify outputs are available
        assert stack.outputs["BucketArn"].startswith("arn:aws:s3:::test-bucket-immediate-attrs")
        assert "test-bucket-immediate-attrs" in stack.outputs["BucketDomainName"]
        assert "test-bucket-immediate-attrs" in stack.outputs["BucketWebsiteURL"]

    @markers.aws.validated
    def test_lambda_function_arn_immediate_access(self, deploy_cfn_template, aws_client):
        """
        Test that Lambda function Arn can be accessed immediately after creation.
        """
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "LambdaRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "lambda.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        }
                    },
                },
                "MyFunction": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "FunctionName": "test-immediate-arn",
                        "Runtime": "python3.9",
                        "Handler": "index.handler",
                        "Role": {"Fn::GetAtt": ["LambdaRole", "Arn"]},
                        "Code": {"ZipFile": "def handler(event, context): return 'hello'"},
                    },
                },
                "LambdaPermission": {
                    "Type": "AWS::Lambda::Permission",
                    "Properties": {
                        "FunctionName": {"Ref": "MyFunction"},
                        "Action": "lambda:InvokeFunction",
                        "Principal": "apigateway.amazonaws.com",
                        "SourceArn": {
                            "Fn::Sub": [
                                "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:*/*/GET/*",
                                {},
                            ]
                        },
                    },
                },
            },
            "Outputs": {"FunctionArn": {"Value": {"Fn::GetAtt": ["MyFunction", "Arn"]}}},
        }

        # This should not raise DependencyNotYetSatisfied exceptions
        stack = deploy_cfn_template(template=template)

        # Verify the function ARN is available
        function_arn = stack.outputs["FunctionArn"]
        assert "test-immediate-arn" in function_arn
        assert function_arn.startswith("arn:aws:lambda:")

    @markers.aws.validated
    def test_complex_api_gateway_deployment_no_loop(self, deploy_cfn_template, aws_client):
        """
        Test that complex API Gateway deployments don't create resource loops.

        This is the test case suggested in the original markdown file.
        """
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "MyApi": {"Type": "AWS::ApiGateway::RestApi", "Properties": {"Name": "TestApi"}},
                "MyResource": {
                    "Type": "AWS::ApiGateway::Resource",
                    "Properties": {
                        "RestApiId": {"Ref": "MyApi"},
                        "ParentId": {"Fn::GetAtt": ["MyApi", "RootResourceId"]},
                        "PathPart": "test",
                    },
                },
                "MyMethod": {
                    "Type": "AWS::ApiGateway::Method",
                    "Properties": {
                        "RestApiId": {"Ref": "MyApi"},
                        "ResourceId": {"Ref": "MyResource"},
                        "HttpMethod": "GET",
                        "AuthorizationType": "NONE",
                        "Integration": {
                            "Type": "MOCK",
                            "RequestTemplates": {"application/json": '{"statusCode": 200}'},
                            "IntegrationResponses": [
                                {
                                    "StatusCode": "200",
                                    "ResponseTemplates": {
                                        "application/json": '{"message": "success"}'
                                    },
                                }
                            ],
                        },
                        "MethodResponses": [{"StatusCode": "200"}],
                    },
                },
                "MyDeployment": {
                    "Type": "AWS::ApiGateway::Deployment",
                    "DependsOn": ["MyMethod"],
                    "Properties": {"RestApiId": {"Ref": "MyApi"}, "StageName": "test"},
                },
            },
            "Outputs": {
                "ApiEndpoint": {
                    "Value": {
                        "Fn::Sub": [
                            "https://${ApiId}.execute-api.${AWS::Region}.amazonaws.com/test/test",
                            {"ApiId": {"Ref": "MyApi"}},
                        ]
                    }
                }
            },
        }

        # Verify deployment completes without loops
        stack = deploy_cfn_template(template=template)

        # Verify all resources were created
        api_id = stack.outputs["ApiEndpoint"].split(".")[0].split("//")[1]

        # Verify API Gateway structure
        resources = aws_client.apigateway.get_resources(restApiId=api_id)
        test_resources = [r for r in resources["items"] if r.get("pathPart") == "test"]
        assert len(test_resources) == 1

        # Verify method exists
        test_resource_id = test_resources[0]["id"]
        method = aws_client.apigateway.get_method(
            restApiId=api_id, resourceId=test_resource_id, httpMethod="GET"
        )
        assert method["httpMethod"] == "GET"


class TestImmediateAttributeConfiguration:
    """Test that the immediate attribute configuration is working correctly."""

    def test_immediate_attributes_mapping_exists(self):
        """Test that IMMEDIATE_ATTRIBUTES mapping is defined correctly."""
        # This test will pass once we implement the fix
        try:
            from localstack.services.cloudformation.engine.template_deployer import (
                IMMEDIATE_ATTRIBUTES,
            )
        except ImportError:
            pytest.skip("IMMEDIATE_ATTRIBUTES not yet implemented")

        # Verify API Gateway attributes
        assert "AWS::ApiGateway::RestApi" in IMMEDIATE_ATTRIBUTES
        assert "RootResourceId" in IMMEDIATE_ATTRIBUTES["AWS::ApiGateway::RestApi"]

        # Verify S3 attributes
        assert "AWS::S3::Bucket" in IMMEDIATE_ATTRIBUTES
        expected_s3_attrs = {"Arn", "DomainName", "RegionalDomainName", "WebsiteURL"}
        assert expected_s3_attrs.issubset(IMMEDIATE_ATTRIBUTES["AWS::S3::Bucket"])

        # Verify Lambda attributes
        assert "AWS::Lambda::Function" in IMMEDIATE_ATTRIBUTES
        assert "Arn" in IMMEDIATE_ATTRIBUTES["AWS::Lambda::Function"]
