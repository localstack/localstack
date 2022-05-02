from abc import ABC
from copy import deepcopy

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.apigateway import (
    Account,
    ApigatewayApi,
    Authorizer,
    Authorizers,
    BasePathMapping,
    BasePathMappings,
    CreateAuthorizerRequest,
    CreateDocumentationPartRequest,
    DocumentationPart,
    DocumentationPartLocation,
    DocumentationParts,
    GetDocumentationPartsRequest,
    ListOfPatchOperation,
    NotFoundException,
    NullableInteger,
    String,
)
from localstack.services.apigateway.helpers import (
    APIGatewayRegion,
    apply_json_patch_safe,
    find_api_subentity_by_id,
)
from localstack.utils.collections import ensure_list
from localstack.utils.strings import short_uid


class ApigatewayProvider(ApigatewayApi, ABC):

    # authorizers

    @handler("CreateAuthorizer", expand=False)
    def create_authorizer(
        self, context: RequestContext, request: CreateAuthorizerRequest
    ) -> Authorizer:
        region_details = APIGatewayRegion.get()

        api_id = request["restApiId"]
        authorizer_id = short_uid()[:6]  # length 6 to make TF tests pass
        result = deepcopy(request)

        result["id"] = authorizer_id
        result = normalize_authorizer(result)
        region_details.authorizers.setdefault(api_id, []).append(result)

        result = to_authorizer_response_json(api_id, result)
        return Authorizer(**result)

    def get_authorizers(
        self,
        context: RequestContext,
        rest_api_id: String,
        position: String = None,
        limit: NullableInteger = None,
    ) -> Authorizers:
        # TODO add paging
        region_details = APIGatewayRegion.get()

        auth_list = region_details.authorizers.get(rest_api_id) or []

        result = [to_authorizer_response_json(rest_api_id, a) for a in auth_list]
        return Authorizers(items=result)

    def get_authorizer(
        self, context: RequestContext, rest_api_id: String, authorizer_id: String
    ) -> Authorizer:
        authorizer = find_api_subentity_by_id(rest_api_id, authorizer_id, "authorizers")
        if authorizer is None:
            raise NotFoundException(f"Authorizer not found: {authorizer_id}")
        return to_authorizer_response_json(rest_api_id, authorizer)

    def delete_authorizer(
        self, context: RequestContext, rest_api_id: String, authorizer_id: String
    ) -> None:
        region_details = APIGatewayRegion.get()

        auth_list = region_details.authorizers.get(rest_api_id, [])
        for i in range(len(auth_list)):
            if auth_list[i]["id"] == authorizer_id:
                del auth_list[i]
                break

    def update_authorizer(
        self,
        context: RequestContext,
        rest_api_id: String,
        authorizer_id: String,
        patch_operations: ListOfPatchOperation = None,
    ) -> Authorizer:
        region_details = APIGatewayRegion.get()

        authorizer = find_api_subentity_by_id(rest_api_id, authorizer_id, "authorizers")
        if authorizer is None:
            raise NotFoundException(f"Authorizer not found: {authorizer_id}")

        result = apply_json_patch_safe(authorizer, patch_operations)
        result = normalize_authorizer(result)

        auth_list = region_details.authorizers[rest_api_id]
        for i in range(len(auth_list)):
            if auth_list[i]["id"] == authorizer_id:
                auth_list[i] = result

        result = to_authorizer_response_json(rest_api_id, result)
        return Authorizer(**result)

    # accounts

    def get_account(
        self,
        context: RequestContext,
    ) -> Account:
        region_details = APIGatewayRegion.get()
        result = to_account_response_json(region_details.account)
        return Account(**result)

    def update_account(
        self, context: RequestContext, patch_operations: ListOfPatchOperation = None
    ) -> Account:
        region_details = APIGatewayRegion.get()
        apply_json_patch_safe(region_details.account, patch_operations, in_place=True)
        result = to_account_response_json(region_details.account)
        return Account(**result)

    # documentation parts

    def get_documentation_parts(
        self, context: RequestContext, request: GetDocumentationPartsRequest
    ) -> DocumentationParts:
        region_details = APIGatewayRegion.get()

        # This function returns either a list or a single entity (depending on the path)
        api_id = request["restApiId"]
        auth_list = region_details.documentation_parts.get(api_id) or []

        result = [to_documentation_part_response_json(api_id, a) for a in auth_list]
        result = {"item": result}
        return result

    def get_documentation_part(
        self, context: RequestContext, rest_api_id: String, documentation_part_id: String
    ) -> DocumentationPart:
        entity = find_api_subentity_by_id(rest_api_id, documentation_part_id, "documentation_parts")
        if entity is None:
            raise NotFoundException(f"Documentation part not found: {documentation_part_id}")
        return to_documentation_part_response_json(rest_api_id, entity)

    def create_documentation_part(
        self,
        context: RequestContext,
        rest_api_id: String,
        location: DocumentationPartLocation,
        properties: String,
    ) -> DocumentationPart:
        region_details = APIGatewayRegion.get()

        entity_id = short_uid()[:6]  # length 6 for AWS parity / Terraform compatibility
        entry = {
            "id": entity_id,
            "restApiId": rest_api_id,
            "location": location,
            "properties": properties,
        }

        region_details.documentation_parts.setdefault(rest_api_id, []).append(entry)

        result = to_documentation_part_response_json(rest_api_id, entry)
        return DocumentationPart(**result)

    def update_documentation_part(
        self,
        context: RequestContext,
        rest_api_id: String,
        documentation_part_id: String,
        patch_operations: ListOfPatchOperation = None,
    ) -> DocumentationPart:
        region_details = APIGatewayRegion.get()

        entity = find_api_subentity_by_id(rest_api_id, documentation_part_id, "documentation_parts")
        if entity is None:
            raise NotFoundException(f"Documentation part not found: {documentation_part_id}")

        result = apply_json_patch_safe(entity, patch_operations)

        auth_list = region_details.documentation_parts[rest_api_id]
        for i in range(len(auth_list)):
            if auth_list[i]["id"] == documentation_part_id:
                auth_list[i] = result

        result = to_documentation_part_response_json(rest_api_id, result)
        return DocumentationPart(**result)

    def delete_documentation_part(
        self, context: RequestContext, rest_api_id: String, documentation_part_id: String
    ) -> None:
        region_details = APIGatewayRegion.get()

        auth_list = region_details.documentation_parts[rest_api_id]
        for i in range(len(auth_list)):
            if auth_list[i]["id"] == documentation_part_id:
                del auth_list[i]
                break

    # base path mappings

    def get_base_path_mappings(
        self,
        context: RequestContext,
        domain_name: String,
        position: String = None,
        limit: NullableInteger = None,
    ) -> BasePathMappings:
        region_details = APIGatewayRegion.get()

        mappings_list = region_details.base_path_mappings.get(domain_name) or []

        result = [
            to_base_mapping_response_json(domain_name, m["basePath"], m) for m in mappings_list
        ]
        return BasePathMappings(items=result)

    def get_base_path_mapping(
        self, context: RequestContext, domain_name: String, base_path: String
    ) -> BasePathMapping:
        region_details = APIGatewayRegion.get()

        mappings_list = region_details.base_path_mappings.get(domain_name) or []
        mapping = ([m for m in mappings_list if m["basePath"] == base_path] or [None])[0]
        if mapping is None:
            raise NotFoundException(f"Base path mapping not found: {domain_name} - {base_path}")

        result = to_base_mapping_response_json(domain_name, base_path, mapping)
        return BasePathMapping(**result)

    def create_base_path_mapping(
        self,
        context: RequestContext,
        domain_name: String,
        rest_api_id: String,
        base_path: String = None,
        stage: String = None,
    ) -> BasePathMapping:
        region_details = APIGatewayRegion.get()

        # Note: "(none)" is a special value in API GW:
        # https://docs.aws.amazon.com/apigateway/api-reference/link-relation/basepathmapping-by-base-path
        base_path = base_path or "(none)"

        entry = {
            "domain_name": domain_name,
            "rest_api_id": rest_api_id,
            "base_path": base_path,
            "stage": stage,
        }
        region_details.base_path_mappings.setdefault(domain_name, []).append(entry)

        result = to_base_mapping_response_json(domain_name, base_path, entry)
        return BasePathMapping(**result)

    def update_base_path_mapping(
        self,
        context: RequestContext,
        domain_name: String,
        base_path: String,
        patch_operations: ListOfPatchOperation = None,
    ) -> BasePathMapping:
        region_details = APIGatewayRegion.get()

        mappings_list = region_details.base_path_mappings.get(domain_name) or []

        mapping = ([m for m in mappings_list if m["basePath"] == base_path] or [None])[0]
        if mapping is None:
            raise NotFoundException(
                f"Not found: mapping for domain name {domain_name}, "
                f"base path {base_path} in list {mappings_list}"
            )

        patch_operations = ensure_list(patch_operations)
        for operation in patch_operations:
            if operation["path"] == "/restapiId":
                operation["path"] = "/restApiId"
        result = apply_json_patch_safe(mapping, patch_operations)

        for i in range(len(mappings_list)):
            if mappings_list[i]["basePath"] == base_path:
                mappings_list[i] = result

        result = to_base_mapping_response_json(domain_name, base_path, result)
        return BasePathMapping(**result)

    def delete_base_path_mapping(
        self, context: RequestContext, domain_name: String, base_path: String
    ) -> None:
        region_details = APIGatewayRegion.get()

        mappings_list = region_details.base_path_mappings.get(domain_name) or []
        for i in range(len(mappings_list)):
            if mappings_list[i]["basePath"] == base_path:
                del mappings_list[i]
                return

        raise NotFoundException(f"Base path mapping {base_path} for domain {domain_name} not found")


# ---------------
# UTIL FUNCTIONS
# ---------------


def normalize_authorizer(data):
    is_list = isinstance(data, list)
    entries = ensure_list(data)
    for i in range(len(entries)):
        entry = deepcopy(entries[i])
        # terraform sends this as a string in patch, so convert to int
        entry["authorizerResultTtlInSeconds"] = int(entry.get("authorizerResultTtlInSeconds", 300))
        entries[i] = entry
    return entries if is_list else entries[0]


def to_authorizer_response_json(api_id, data):
    return to_response_json("authorizer", data, api_id=api_id)


def to_validator_response_json(api_id, data):
    return to_response_json("validator", data, api_id=api_id)


def to_documentation_part_response_json(api_id, data):
    return to_response_json("documentationpart", data, api_id=api_id)


def to_base_mapping_response_json(domain_name, base_path, data):
    self_link = "/domainnames/%s/basepathmappings/%s" % (domain_name, base_path)
    return to_response_json("basepathmapping", data, self_link=self_link)


def to_account_response_json(data):
    return to_response_json("account", data, self_link="/account")


def to_vpc_link_response_json(data):
    return to_response_json("vpclink", data)


def to_client_cert_response_json(data):
    return to_response_json("clientcertificate", data, id_attr="clientCertificateId")


def to_response_json(model_type, data, api_id=None, self_link=None, id_attr=None):
    if isinstance(data, list) and len(data) == 1:
        data = data[0]
    id_attr = id_attr or "id"
    result = deepcopy(data)
    if not self_link:
        self_link = "/%ss/%s" % (model_type, data[id_attr])
        if api_id:
            self_link = "/restapis/%s/%s" % (api_id, self_link)
    if "_links" not in result:
        result["_links"] = {}
    result["_links"]["self"] = {"href": self_link}
    result["_links"]["curies"] = {
        "href": "https://docs.aws.amazon.com/apigateway/latest/developerguide/restapi-authorizer-latest.html",
        "name": model_type,
        "templated": True,
    }
    result["_links"]["%s:delete" % model_type] = {"href": self_link}
    return result
