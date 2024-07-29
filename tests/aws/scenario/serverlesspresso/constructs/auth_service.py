import aws_cdk as cdk
import aws_cdk.aws_cognito_identitypool_alpha as identitypool
import constructs


class AuthService(constructs.Construct):
    def __init__(self, scope: constructs.Construct, id: str, *, app_name: str, service: str):
        super().__init__(scope, id)

        # ================================================================================================
        # cognito resources
        # ================================================================================================
        self.user_pool = user_pool = cdk.aws_cognito.UserPool(
            self,
            "UserPool",
            user_pool_name="ServerlesspressoUserPool",
            user_verification=cdk.aws_cognito.UserVerificationConfig(
                email_body="Here is your Serverlesspresso workshop verification code: {####}.",
                email_subject="Serverlesspresso workshop code",
            ),
            auto_verify=cdk.aws_cognito.AutoVerifiedAttrs(email=True),
            password_policy=cdk.aws_cognito.PasswordPolicy(
                min_length=6,
                require_digits=False,
                require_lowercase=False,
                require_symbols=False,
                require_uppercase=False,
            ),
            standard_attributes=cdk.aws_cognito.StandardAttributes(
                email=cdk.aws_cognito.StandardAttribute(
                    required=True,
                    mutable=False,
                )
            ),
            removal_policy=cdk.RemovalPolicy.DESTROY,
            self_sign_up_enabled=True,
        )
        admin_group = cdk.aws_cognito.CfnUserPoolGroup(
            self,
            "AdminGroup",
            user_pool_id=user_pool.user_pool_id,
            group_name="admin"
        )

        user_pool.node.default_child.override_logical_id("UserPool")
        self.user_pool_client = user_pool_client = user_pool.add_client(
            "UserPoolClient", generate_secret=False
        )
        user_pool_parameter = cdk.aws_ssm.StringParameter(
            self,
            "UserPoolParameter",
            parameter_name=f"/{app_name}/{service}/userpool",
            string_value=user_pool.user_pool_id,
        )  # TODO Ref?
        user_pool_client_parameter = cdk.aws_ssm.StringParameter(
            self,
            "UserPoolClientParameter",
            parameter_name=f"/{app_name}/{service}/userpoolclient",
            string_value=user_pool_client.user_pool_client_id,
        )  # TODO Ref?

        self.identity_pool = identitypool.IdentityPool(
            self,
            "IdentityPool",
            identity_pool_name="ServerlesspressoIdentityPool",
            allow_unauthenticated_identities=True,
            authentication_providers=identitypool.IdentityPoolAuthenticationProviders(
                user_pools=[
                    identitypool.UserPoolAuthenticationProvider(
                        user_pool=user_pool,
                        user_pool_client=user_pool_client,
                    )
                ]
            ),
        )

        unauthenticated_role = cdk.aws_iam.Role(
            self,
            "CognitoUnAuthorizedRole",
            assumed_by=cdk.aws_iam.FederatedPrincipal(
                federated="cognito-identity.amazonaws.com",
                assume_role_action="sts:AssumeRoleWithWebIdentity",
                conditions={
                    "StringEquals": {
                        "cognito-identity.amazonaws.com:aud": self.identity_pool.identity_pool_id  # TODO
                    },
                    "ForAnyValue:StringLike": {
                        "cognito-identity.amazonaws.com:amr": "unauthenticated"
                    },
                },
            ),
            inline_policies={
                "CognitoUnauthorizedPolicy": cdk.aws_iam.PolicyDocument(
                    statements=[
                        cdk.aws_iam.PolicyStatement(
                            effect=cdk.aws_iam.Effect.ALLOW,
                            actions=["cognito-sync:*"],
                            resources=[
                                self.identity_pool.identity_pool_arn
                            ],  # TODO: check arn format (should be arn:aws:cognito-sync)
                        ),
                        cdk.aws_iam.PolicyStatement(
                            effect=cdk.aws_iam.Effect.ALLOW,
                            actions=["iot:Connect"],
                            resources=["*"],  # TODO
                        ),
                        cdk.aws_iam.PolicyStatement(
                            effect=cdk.aws_iam.Effect.ALLOW,
                            actions=["iot:Subscribe"],
                            resources=["*"],  # TODO
                        ),
                        cdk.aws_iam.PolicyStatement(
                            effect=cdk.aws_iam.Effect.ALLOW,
                            actions=["iot:Receive"],
                            resources=["*"],  # TODO
                        ),
                    ]
                )
            },
        )
        authenticated_role = cdk.aws_iam.Role(
            self,
            "CognitoAuthorizedRole",
            assumed_by=cdk.aws_iam.FederatedPrincipal(
                federated="cognito-identity.amazonaws.com",
                assume_role_action="sts:AssumeRoleWithWebIdentity",
                conditions={
                    "StringEquals": {
                        "cognito-identity.amazonaws.com:aud": self.identity_pool.identity_pool_id
                    },
                    "ForAnyValue:StringLike": {
                        "cognito-identity.amazonaws.com:amr": "authenticated"
                    },
                },
            ),
            inline_policies={
                "CognitoAuthorizedPolicy": cdk.aws_iam.PolicyDocument(
                    statements=[
                        cdk.aws_iam.PolicyStatement(
                            effect=cdk.aws_iam.Effect.ALLOW,
                            actions=["cognito-sync:*"],
                            resources=[
                                self.identity_pool.identity_pool_arn
                            ],  # TODO: check arn format (should be arn:aws:cognito-sync)
                        ),
                        cdk.aws_iam.PolicyStatement(
                            effect=cdk.aws_iam.Effect.ALLOW,
                            actions=["iot:Connect"],
                            resources=["*"],  # TODO
                        ),
                        cdk.aws_iam.PolicyStatement(
                            effect=cdk.aws_iam.Effect.ALLOW,
                            actions=["iot:Subscribe"],
                            resources=["*"],  # TODO
                        ),
                        cdk.aws_iam.PolicyStatement(
                            effect=cdk.aws_iam.Effect.ALLOW,
                            actions=["iot:Receive"],
                            resources=["*"],  # TODO
                        ),
                    ]
                )
            },
        )

        cdk.custom_resources.AwsCustomResource
        # TODO for some reason this currently fails
        # role_mapping = identitypool.IdentityPoolRoleAttachment(
        #     self,
        #     "IdentityPoolRoleMapping",
        #     identity_pool=identity_pool,
        #     authenticated_role=authenticated_role,
        #     unauthenticated_role=unauthenticated_role,
        #     # role_mappings=[]
        # )
