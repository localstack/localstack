from localstack.services.generic_proxy import ProxyListener
from localstack.utils.aws.aws_responses import MessageConversion

BOOL_ATTRS = [
    "RequireLowercaseCharacters",
    "RequireUppercaseCharacters",
    "HardExpiry",
    "RequireSymbols",
    "ExpirePasswords",
    "IsTruncated",
]


class ProxyListenerIAM(ProxyListener):
    def forward_request(self, method, path, data, headers):
        # Fixed upstream
        # if method == "POST" and path == "/":
        #     data = MessageConversion._reset_account_id(data)
        #     return Request(data=data, headers=headers, method=method)

        return True

    def return_response(self, method, path, data, headers, response):
        if response.content:
            # fix hardcoded account ID in ARNs returned from this API
            MessageConversion.fix_account_id(response)
            # fix dates returned from this API (fixes issues with Terraform)
            MessageConversion.fix_date_format(response)
            MessageConversion.fix_error_codes(method, data, response)
            MessageConversion.fix_xml_empty_boolean(response, BOOL_ATTRS)
            MessageConversion.booleans_to_lowercase(response, BOOL_ATTRS)

            # fix content-length header
            response.headers["Content-Length"] = str(len(response._content))

            # TODO in this migration. Above fixes TARGET the requests below, but are they still RELEVANT?
            # With CreateDate:
            # AccessKey
            #     CreateAccessKeyResponse
            # AccessKeyMetadata
            #     ListAccessKeysResponse
            # Group
            #     CreateGroupResponse
            #     GetGroupResponse
            # Role
            #     CreateRoleResponse
            #     CreateServiceLinkedRoleResponse
            #     GetRoleResponse
            #     UpdateRoleDescriptionResponse
            # InstanceProfile
            #     CreateInstanceProfileResponse
            #     GetInstanceProfileResponse
            # LoginProfile
            #     CreateLoginProfileResponse
            #     GetLoginProfileResponse
            # Policy
            #     CreatePolicyResponse
            #     GetPolicyResponse
            # PolicyVersion
            #     CreatePolicyVersionResponse
            #     GetPolicyVersionResponse
            # ServiceSpecificCredential
            #     CreateServiceSpecificCredentialResponse
            #     ResetServiceSpecificCredentialResponse
            # User
            #     CreateUserResponse
            #     VirtualMFADevice
            #     GetUserResponse
            # ManagedPolicyDetail
            #     GetAccountAuthorizationDetailsResponse
            # RoleDetail
            #     GetAccountAuthorizationDetailsResponse
            # GroupDetail
            #     GetAccountAuthorizationDetailsResponse
            # UserDetail
            #     GetAccountAuthorizationDetailsResponse
            # SAMLProviderListEntry
            #     ListSAMLProvidersResponse
            # ServiceSpecificCredentialMetadata
            #     ListServiceSpecificCredentialsResponse
            # Other:
            #     GetOpenIDConnectProviderResponse
            #     GetSAMLProviderResponse
            # With Error(s):
            #     GetServiceLastAccessedDetailsResponse
            #     GetServiceLastAccessedDetailsWithEntitiesResponse
            # *nCheck booleans are outputted as missing of with capitals
