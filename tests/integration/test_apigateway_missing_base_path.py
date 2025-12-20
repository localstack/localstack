import json
from localstack.utils.common import short_uid


class TestApiGatewayBasePathMapping:
    def test_delete_base_path_mapping_missing_base_path(
        self, deploy_cfn_template, aws_client_factory
    ):
        """
        Reproduces Issue #13503:
        CDK constructs often create a BasePathMapping without an explicit 'BasePath' property.
        When deleting this resource, LocalStack's generic provider fails because it calls
        delete_base_path_mapping() without the required 'basePath' argument.
        """
        acm_client = aws_client_factory(region_name="uranus-south-1").acm
        domain_name = f"api-{short_uid()}.localhost.localstack.cloud"
        cert_arn = acm_client.request_certificate(DomainName=domain_name)[
            "CertificateArn"
        ]

        template = json.dumps(
            {
                "Resources": {
                    "MyRestApi": {
                        "Type": "AWS::ApiGateway::RestApi",
                        "Properties": {"Name": "test-api"},
                    },
                    "MyMethod": {
                        "Type": "AWS::ApiGateway::Method",
                        "Properties": {
                            "RestApiId": {"Ref": "MyRestApi"},
                            "ResourceId": {
                                "Fn::GetAtt": ["MyRestApi", "RootResourceId"]
                            },
                            "HttpMethod": "GET",
                            "AuthorizationType": "NONE",
                            "Integration": {
                                "Type": "MOCK",
                                "RequestTemplates": {
                                    "application/json": '{"statusCode": 200}'
                                },
                            },
                            "MethodResponses": [{"StatusCode": 200}],
                        },
                    },
                    "MyDeployment": {
                        "Type": "AWS::ApiGateway::Deployment",
                        "Properties": {"RestApiId": {"Ref": "MyRestApi"}},
                        "DependsOn": ["MyMethod"],
                    },
                    "MyStage": {
                        "Type": "AWS::ApiGateway::Stage",
                        "Properties": {
                            "RestApiId": {"Ref": "MyRestApi"},
                            "DeploymentId": {"Ref": "MyDeployment"},
                            "StageName": "prod",
                        },
                    },
                    "MyDomainName": {
                        "Type": "AWS::ApiGateway::DomainName",
                        "Properties": {
                            "DomainName": domain_name,
                            "CertificateArn": cert_arn,
                        },
                    },
                    "MyBasePathMapping": {
                        "Type": "AWS::ApiGateway::BasePathMapping",
                        "Properties": {
                            "DomainName": {"Ref": "MyDomainName"},
                            "RestApiId": {"Ref": "MyRestApi"},
                            "Stage": {"Ref": "MyStage"},
                        },
                    },
                },
            }
        )
        stack = deploy_cfn_template(template=template)
        stack.destroy()

