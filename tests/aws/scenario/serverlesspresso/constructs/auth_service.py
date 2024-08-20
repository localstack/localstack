import aws_cdk as cdk
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
            sign_in_aliases=cdk.aws_cognito.SignInAliases(email=True),
        )
        cdk.aws_cognito.CfnUserPoolGroup(
            self, "AdminGroup", user_pool_id=user_pool.user_pool_id, group_name="admin"
        )

        user_pool.node.default_child.override_logical_id("UserPool")
        self.user_pool_client = user_pool_client = user_pool.add_client(
            "UserPoolClient",
            generate_secret=False,
            auth_flows=cdk.aws_cognito.AuthFlow(
                admin_user_password=True, user_srp=True, user_password=True
            ),
            supported_identity_providers=[cdk.aws_cognito.UserPoolClientIdentityProvider.COGNITO],
        )
        cdk.aws_ssm.StringParameter(
            self,
            "UserPoolParameter",
            parameter_name=f"/{app_name}/{service}/userpool",
            string_value=user_pool.user_pool_id,
        )  # TODO Ref?
        cdk.aws_ssm.StringParameter(
            self,
            "UserPoolClientParameter",
            parameter_name=f"/{app_name}/{service}/userpoolclient",
            string_value=user_pool_client.user_pool_client_id,
        )  # TODO Ref?

        self.identity_pool = cdk.aws_cognito.CfnIdentityPool(
            self,
            "IdentityPool",
            identity_pool_name="ServerlesspressoIdentityPool",
            allow_unauthenticated_identities=True,
            cognito_identity_providers=[
                cdk.aws_cognito.CfnIdentityPool.CognitoIdentityProviderProperty(
                    client_id=user_pool_client.user_pool_client_id,
                    provider_name=user_pool.user_pool_provider_name,
                )
            ],
        )

        self.identity_pool_id = self.identity_pool.ref

        unauthenticated_role = cdk.aws_iam.Role(
            self,
            "CognitoUnAuthorizedRole",
            assumed_by=cdk.aws_iam.FederatedPrincipal(
                federated="cognito-identity.amazonaws.com",
                assume_role_action="sts:AssumeRoleWithWebIdentity",
                conditions={
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": self.identity_pool_id},
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
                                cdk.Fn.join(
                                    "",
                                    [
                                        "arn:aws:cognito-sync:",
                                        cdk.Stack.of(self).region,
                                        ":",
                                        cdk.Stack.of(self).account,
                                        ":identitypool/",
                                        self.identity_pool_id,
                                    ],
                                )
                            ],
                        ),
                        cdk.aws_iam.PolicyStatement(
                            effect=cdk.aws_iam.Effect.ALLOW,
                            actions=["iot:Connect"],
                            resources=[
                                cdk.Fn.join(
                                    "",
                                    [
                                        "arn:aws:iot:",
                                        cdk.Stack.of(self).region,
                                        ":",
                                        cdk.Stack.of(self).account,
                                        ":client/serverlesspresso-*",
                                    ],
                                )
                            ],
                        ),
                        cdk.aws_iam.PolicyStatement(
                            effect=cdk.aws_iam.Effect.ALLOW,
                            actions=["iot:Subscribe"],
                            resources=["*"],
                        ),
                        cdk.aws_iam.PolicyStatement(
                            effect=cdk.aws_iam.Effect.ALLOW,
                            actions=["iot:Receive"],
                            resources=[
                                cdk.Fn.join(
                                    "",
                                    [
                                        "arn:aws:iot:",
                                        cdk.Stack.of(self).region,
                                        ":",
                                        cdk.Stack.of(self).account,
                                        ":topic/*",
                                    ],
                                )
                            ],
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
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": self.identity_pool_id},
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
                                cdk.Fn.join(
                                    "",
                                    [
                                        "arn:aws:cognito-sync:",
                                        cdk.Stack.of(self).region,
                                        ":",
                                        cdk.Stack.of(self).account,
                                        ":identitypool/",
                                        self.identity_pool_id,
                                    ],
                                )
                            ],
                        ),
                        cdk.aws_iam.PolicyStatement(
                            effect=cdk.aws_iam.Effect.ALLOW,
                            actions=["iot:Connect"],
                            resources=[
                                cdk.Fn.join(
                                    "",
                                    [
                                        "arn:aws:iot:",
                                        cdk.Stack.of(self).region,
                                        ":",
                                        cdk.Stack.of(self).account,
                                        ":client/serverlesspresso-*",
                                    ],
                                )
                            ],
                        ),
                        cdk.aws_iam.PolicyStatement(
                            effect=cdk.aws_iam.Effect.ALLOW,
                            actions=["iot:Subscribe"],
                            resources=["*"],
                        ),
                        cdk.aws_iam.PolicyStatement(
                            effect=cdk.aws_iam.Effect.ALLOW,
                            actions=["iot:Receive"],
                            resources=[
                                cdk.Fn.join(
                                    "",
                                    [
                                        "arn:aws:iot:",
                                        cdk.Stack.of(self).region,
                                        ":",
                                        cdk.Stack.of(self).account,
                                        ":topic/*",
                                    ],
                                )
                            ],
                        ),
                    ]
                )
            },
        )

        cdk.aws_cognito.CfnIdentityPoolRoleAttachment(
            self,
            "IdentityPoolRoleMapping",
            identity_pool_id=self.identity_pool_id,
            roles={
                "unauthenticated": unauthenticated_role.role_arn,
                "authenticated": authenticated_role.role_arn,
            },
        )
