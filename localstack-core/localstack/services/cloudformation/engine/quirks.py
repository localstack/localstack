"""
We can't always automatically determine which value serves as the physical resource ID.
=> This needs to be determined manually by testing against AWS (!)

There's also a reason that the mapping is located here instead of closer to the resource providers themselves.
If the resources were compliant with the generic AWS resource provider framework that AWS provides for your own resource types, we wouldn't need this.
For legacy resources (and even some of the ones where they are open-sourced), AWS still has a layer of "secret sauce" that defines what the actual physical resource ID is.
An extension schema only defines the primary identifiers but not directly the physical resource ID that is generated based on those.
Since this is therefore rather part of the cloudformation layer and *not* the resource providers responsibility, we've put the mapping closer to the cloudformation engine.
"""

# note: format here is subject to change (e.g. it might not be a pure str -> str mapping, it could also involve more sophisticated handlers
PHYSICAL_RESOURCE_ID_SPECIAL_CASES = {
    "AWS::ApiGateway::Authorizer": "/properties/AuthorizerId",
    "AWS::ApiGateway::RequestValidator": "/properties/RequestValidatorId",
    "AWS::ApiGatewayV2::Authorizer": "/properties/AuthorizerId",
    "AWS::ApiGatewayV2::Deployment": "/properties/DeploymentId",
    "AWS::ApiGatewayV2::IntegrationResponse": "/properties/IntegrationResponseId",
    "AWS::ApiGatewayV2::Route": "/properties/RouteId",
    "AWS::ApiGateway::BasePathMapping": "/properties/RestApiId",
    "AWS::ApiGateway::Deployment": "/properties/DeploymentId",
    "AWS::ApiGateway::Model": "/properties/Name",
    "AWS::ApiGateway::Resource": "/properties/ResourceId",
    "AWS::ApiGateway::Stage": "/properties/StageName",
    "AWS::Cognito::UserPoolClient": "/properties/ClientId",
    "AWS::ECS::Service": "/properties/ServiceArn",
    "AWS::EKS::FargateProfile": "</properties/ClusterName>|</properties/FargateProfileName>",  # composite
    "AWS::Events::EventBus": "/properties/Name",
    "AWS::Logs::LogStream": "/properties/LogStreamName",
    "AWS::Logs::SubscriptionFilter": "/properties/LogGroupName",
    "AWS::RDS::DBProxyTargetGroup": "/properties/TargetGroupName",
    "AWS::Glue::SchemaVersionMetadata": "</properties/SchemaVersionId>|</properties/Key>|</properties/Value>",  # composite
    "AWS::WAFv2::WebACL": "</properties/Name>|</properties/Id>|</properties/Scope>",
    "AWS::WAFv2::WebACLAssociation": "</properties/ResourceArn>|</properties/WebACLArn>",
    "AWS::WAFv2::IPSet": "</properties/Name>|</properties/Id>|</properties/Scope>",
    # composite
}

# You can usually find the available GetAtt targets in the official resource documentation:
#   https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html
# Use the scaffolded exploration test to verify against AWS which attributes you can access.
# This mapping is not in use yet (!)
VALID_GETATT_PROPERTIES = {
    # Other Examples
    # "AWS::ApiGateway::Resource": ["ResourceId"],
    # "AWS::IAM::User": ["Arn"],  # TODO: not validated yet
    "AWS::SSM::Parameter": ["Type", "Value"],  # TODO: not validated yet
    # "AWS::OpenSearchService::Domain": [
    #     "AdvancedSecurityOptions.AnonymousAuthDisableDate",
    #     "Arn",
    #     "DomainArn",
    #     "DomainEndpoint",
    #     "DomainEndpoints",
    #     "Id",
    #     "ServiceSoftwareOptions",
    #     "ServiceSoftwareOptions.AutomatedUpdateDate",
    #     "ServiceSoftwareOptions.Cancellable",
    #     "ServiceSoftwareOptions.CurrentVersion",
    #     "ServiceSoftwareOptions.Description",
    #     "ServiceSoftwareOptions.NewVersion",
    #     "ServiceSoftwareOptions.OptionalDeployment",
    #     "ServiceSoftwareOptions.UpdateAvailable",
    #     "ServiceSoftwareOptions.UpdateStatus",
    # ],  # TODO: not validated yet
}
