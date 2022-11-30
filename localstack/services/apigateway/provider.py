import json
import logging
from copy import deepcopy
from typing import IO

from localstack.aws.api import RequestContext, ServiceRequest, handler
from localstack.aws.api.apigateway import (
    Account,
    ApigatewayApi,
    ApiKeys,
    Authorizer,
    Authorizers,
    BasePathMapping,
    BasePathMappings,
    Blob,
    Boolean,
    ClientCertificate,
    ClientCertificates,
    CreateAuthorizerRequest,
    CreateRestApiRequest,
    DocumentationPart,
    DocumentationPartLocation,
    DocumentationParts,
    ExportResponse,
    GetDocumentationPartsRequest,
    ListOfPatchOperation,
    ListOfString,
    MapOfStringToString,
    NotFoundException,
    NullableBoolean,
    NullableInteger,
    PutRestApiRequest,
    RequestValidator,
    RequestValidators,
    RestApi,
    String,
    Tags,
    TestInvokeMethodRequest,
    TestInvokeMethodResponse,
    VpcLink,
    VpcLinks,
)
from localstack.aws.forwarder import create_aws_request_context
from localstack.constants import APPLICATION_JSON
from localstack.services.apigateway.helpers import (
    OpenApiExporter,
    apply_json_patch_safe,
    find_api_subentity_by_id,
    get_apigateway_store,
)
from localstack.services.apigateway.invocations import invoke_rest_api_from_request
from localstack.services.apigateway.patches import apply_patches
from localstack.services.apigateway.router_asf import ApigatewayRouter, to_invocation_context
from localstack.services.edge import ROUTER
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.collections import PaginatedList, ensure_list
from localstack.utils.json import parse_json_or_yaml
from localstack.utils.strings import short_uid, str_to_bool, to_str
from localstack.utils.time import now_utc

LOG = logging.getLogger(__name__)


class ApigatewayProvider(ApigatewayApi, ServiceLifecycleHook):
    router: ApigatewayRouter

    def __init__(self, router: ApigatewayRouter = None):
        self.router = router or ApigatewayRouter(ROUTER)

    def on_after_init(self):
        apply_patches()
        self.router.register_routes()

    @handler("TestInvokeMethod", expand=False)
    def test_invoke_method(
        self, context: RequestContext, request: TestInvokeMethodRequest
    ) -> TestInvokeMethodResponse:

        invocation_context = to_invocation_context(context.request)
        invocation_context.method = request["httpMethod"]

        if data := parse_json_or_yaml(to_str(invocation_context.data or b"")):
            orig_data = data
            if path_with_query_string := orig_data.get("pathWithQueryString"):
                invocation_context.path_with_query_string = path_with_query_string
            invocation_context.data = data.get("body")
            invocation_context.headers = orig_data.get("headers", {})

        result = invoke_rest_api_from_request(invocation_context)

        # TODO: implement the other TestInvokeMethodResponse parameters
        #   * multiValueHeaders: Optional[MapOfStringToList]
        #   * log: Optional[String]
        #   * latency: Optional[Long]

        return TestInvokeMethodResponse(
            status=result.status_code,
            headers=dict(result.headers),
            body=to_str(result.content),
        )

    @handler("CreateRestApi", expand=False)
    def create_rest_api(self, context: RequestContext, request: CreateRestApiRequest) -> RestApi:
        result = call_moto(context)
        if not result.get("binaryMediaTypes"):
            result.pop("binaryMediaTypes")
        if not result.get("tags"):
            result.pop("tags")
        if result.get("version") == "V1":
            result.pop("version")
        return result

    def delete_rest_api(self, context: RequestContext, rest_api_id: String) -> None:
        try:
            call_moto(context)
        except KeyError as e:
            # moto raises a key error if we're trying to delete an API that doesn't exist
            raise NotFoundException(
                f"Invalid API identifier specified {context.account_id}:{rest_api_id}"
            ) from e

    # authorizers

    @handler("CreateAuthorizer", expand=False)
    def create_authorizer(
        self, context: RequestContext, request: CreateAuthorizerRequest
    ) -> Authorizer:
        region_details = get_apigateway_store()

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
        region_details = get_apigateway_store()

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
        region_details = get_apigateway_store()

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
        region_details = get_apigateway_store()

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
        region_details = get_apigateway_store()
        result = to_account_response_json(region_details.account)
        return Account(**result)

    def update_account(
        self, context: RequestContext, patch_operations: ListOfPatchOperation = None
    ) -> Account:
        region_details = get_apigateway_store()
        apply_json_patch_safe(region_details.account, patch_operations, in_place=True)
        result = to_account_response_json(region_details.account)
        return Account(**result)

    # documentation parts

    def get_documentation_parts(
        self, context: RequestContext, request: GetDocumentationPartsRequest
    ) -> DocumentationParts:
        region_details = get_apigateway_store()

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
        region_details = get_apigateway_store()

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
        region_details = get_apigateway_store()

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
        region_details = get_apigateway_store()

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
        region_details = get_apigateway_store()

        mappings_list = region_details.base_path_mappings.get(domain_name) or []

        result = [
            to_base_mapping_response_json(domain_name, m["basePath"], m) for m in mappings_list
        ]
        return BasePathMappings(items=result)

    def get_base_path_mapping(
        self, context: RequestContext, domain_name: String, base_path: String
    ) -> BasePathMapping:
        region_details = get_apigateway_store()

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
        region_details = get_apigateway_store()

        # Note: "(none)" is a special value in API GW:
        # https://docs.aws.amazon.com/apigateway/api-reference/link-relation/basepathmapping-by-base-path
        base_path = base_path or "(none)"

        entry = {
            "domainName": domain_name,
            "restApiId": rest_api_id,
            "basePath": base_path,
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
        region_details = get_apigateway_store()

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
        region_details = get_apigateway_store()

        mappings_list = region_details.base_path_mappings.get(domain_name) or []
        for i in range(len(mappings_list)):
            if mappings_list[i]["basePath"] == base_path:
                del mappings_list[i]
                return

        raise NotFoundException(f"Base path mapping {base_path} for domain {domain_name} not found")

    # client certificates

    def get_client_certificate(
        self, context: RequestContext, client_certificate_id: String
    ) -> ClientCertificate:
        region_details = get_apigateway_store()
        result = region_details.client_certificates.get(client_certificate_id)
        if result is None:
            raise NotFoundException(f"Client certificate ID {client_certificate_id} not found")
        return ClientCertificate(**result)

    def get_client_certificates(
        self, context: RequestContext, position: String = None, limit: NullableInteger = None
    ) -> ClientCertificates:
        region_details = get_apigateway_store()
        result = list(region_details.client_certificates.values())
        return ClientCertificates(items=result)

    def generate_client_certificate(
        self, context: RequestContext, description: String = None, tags: MapOfStringToString = None
    ) -> ClientCertificate:
        region_details = get_apigateway_store()
        cert_id = short_uid()
        creation_time = now_utc()
        entry = {
            "description": description,
            "tags": tags,
            "clientCertificateId": cert_id,
            "createdDate": creation_time,
            "expirationDate": creation_time + 60 * 60 * 24 * 30,  # assume 30 days validity
            "pemEncodedCertificate": "testcert-123",  # TODO return proper certificate!
        }
        region_details.client_certificates[cert_id] = entry
        result = to_client_cert_response_json(entry)
        return ClientCertificate(**result)

    def update_client_certificate(
        self,
        context: RequestContext,
        client_certificate_id: String,
        patch_operations: ListOfPatchOperation = None,
    ) -> ClientCertificate:
        region_details = get_apigateway_store()
        entity = region_details.client_certificates.get(client_certificate_id)
        if entity is None:
            raise NotFoundException(f'Client certificate ID "{client_certificate_id}" not found')
        result = apply_json_patch_safe(entity, patch_operations)
        result = to_client_cert_response_json(result)
        return ClientCertificate(**result)

    def delete_client_certificate(
        self, context: RequestContext, client_certificate_id: String
    ) -> None:
        region_details = get_apigateway_store()
        entity = region_details.client_certificates.pop(client_certificate_id, None)
        if entity is None:
            raise NotFoundException(f'VPC link ID "{client_certificate_id}" not found for deletion')

    # VPC links

    def create_vpc_link(
        self,
        context: RequestContext,
        name: String,
        target_arns: ListOfString,
        description: String = None,
        tags: MapOfStringToString = None,
    ) -> VpcLink:
        region_details = get_apigateway_store()
        link_id = short_uid()
        entry = {"id": link_id, "status": "AVAILABLE"}
        region_details.vpc_links[link_id] = entry
        result = to_vpc_link_response_json(entry)
        return VpcLink(**result)

    def get_vpc_links(
        self, context: RequestContext, position: String = None, limit: NullableInteger = None
    ) -> VpcLinks:
        region_details = get_apigateway_store()
        result = region_details.vpc_links.values()
        result = [to_vpc_link_response_json(r) for r in result]
        result = {"items": result}
        return result

    def get_vpc_link(self, context: RequestContext, vpc_link_id: String) -> VpcLink:
        region_details = get_apigateway_store()
        vpc_link = region_details.vpc_links.get(vpc_link_id)
        if vpc_link is None:
            raise NotFoundException(f'VPC link ID "{vpc_link_id}" not found')
        result = to_vpc_link_response_json(vpc_link)
        return VpcLink(**result)

    def update_vpc_link(
        self,
        context: RequestContext,
        vpc_link_id: String,
        patch_operations: ListOfPatchOperation = None,
    ) -> VpcLink:
        region_details = get_apigateway_store()
        vpc_link = region_details.vpc_links.get(vpc_link_id)
        if vpc_link is None:
            raise NotFoundException(f'VPC link ID "{vpc_link_id}" not found')
        result = apply_json_patch_safe(vpc_link, patch_operations)
        result = to_vpc_link_response_json(result)
        return VpcLink(**result)

    def delete_vpc_link(self, context: RequestContext, vpc_link_id: String) -> None:
        region_details = get_apigateway_store()
        vpc_link = region_details.vpc_links.pop(vpc_link_id, None)
        if vpc_link is None:
            raise NotFoundException(f'VPC link ID "{vpc_link_id}" not found for deletion')

    # request validators

    def get_request_validators(
        self,
        context: RequestContext,
        rest_api_id: String,
        position: String = None,
        limit: NullableInteger = None,
    ) -> RequestValidators:
        region_details = get_apigateway_store()

        auth_list = region_details.validators.get(rest_api_id) or []

        result = [to_validator_response_json(rest_api_id, a) for a in auth_list]
        return RequestValidators(items=result)

    def get_request_validator(
        self, context: RequestContext, rest_api_id: String, request_validator_id: String
    ) -> RequestValidator:
        region_details = get_apigateway_store()

        auth_list = region_details.validators.get(rest_api_id) or []
        validator = ([a for a in auth_list if a["id"] == request_validator_id] or [None])[0]

        if validator is None:
            raise NotFoundException(
                f"Validator {request_validator_id} for API Gateway {rest_api_id} not found"
            )
        result = to_validator_response_json(rest_api_id, validator)
        return RequestValidator(**result)

    def create_request_validator(
        self,
        context: RequestContext,
        rest_api_id: String,
        name: String = None,
        validate_request_body: Boolean = None,
        validate_request_parameters: Boolean = None,
    ) -> RequestValidator:
        region_details = get_apigateway_store()

        # length 6 for AWS parity and TF compatibility
        validator_id = short_uid()[:6]

        entry = {
            "id": validator_id,
            "name": name,
            "restApiId": rest_api_id,
            "validateRequestBody": validate_request_body,
            "validateRequestParameters": validate_request_parameters,
        }
        region_details.validators.setdefault(rest_api_id, []).append(entry)

        return RequestValidator(**entry)

    def update_request_validator(
        self,
        context: RequestContext,
        rest_api_id: String,
        request_validator_id: String,
        patch_operations: ListOfPatchOperation = None,
    ) -> RequestValidator:
        region_details = get_apigateway_store()

        auth_list = region_details.validators.get(rest_api_id) or []
        validator = ([a for a in auth_list if a["id"] == request_validator_id] or [None])[0]

        if validator is None:
            raise NotFoundException(
                f"Validator {request_validator_id} for API Gateway {rest_api_id} not found"
            )

        result = apply_json_patch_safe(validator, patch_operations)

        entry_list = region_details.validators[rest_api_id]
        for i in range(len(entry_list)):
            if entry_list[i]["id"] == request_validator_id:
                entry_list[i] = result

        result = to_validator_response_json(rest_api_id, result)
        return RequestValidator(**result)

    def delete_request_validator(
        self, context: RequestContext, rest_api_id: String, request_validator_id: String
    ) -> None:
        region_details = get_apigateway_store()

        auth_list = region_details.validators.get(rest_api_id, [])
        for i in range(len(auth_list)):
            if auth_list[i]["id"] == request_validator_id:
                del auth_list[i]
                return

        raise NotFoundException(
            f"Validator {request_validator_id} for API Gateway {rest_api_id} not found"
        )

    # tags

    def get_tags(
        self,
        context: RequestContext,
        resource_arn: String,
        position: String = None,
        limit: NullableInteger = None,
    ) -> Tags:
        result = get_apigateway_store().TAGS.get(resource_arn, {})
        return Tags(tags=result)

    def tag_resource(
        self, context: RequestContext, resource_arn: String, tags: MapOfStringToString
    ) -> None:
        resource_tags = get_apigateway_store().TAGS.setdefault(resource_arn, {})
        resource_tags.update(tags)

    def untag_resource(
        self, context: RequestContext, resource_arn: String, tag_keys: ListOfString
    ) -> None:
        resource_tags = get_apigateway_store().TAGS.setdefault(resource_arn, {})
        for key in tag_keys:
            resource_tags.pop(key, None)

    def import_rest_api(
        self,
        context: RequestContext,
        body: IO[Blob],
        fail_on_warnings: Boolean = None,
        parameters: MapOfStringToString = None,
    ) -> RestApi:
        body_data = body.read()

        openapi_spec = parse_json_or_yaml(to_str(body_data))
        response = _call_moto(
            context,
            "CreateRestApi",
            CreateRestApiRequest(name=openapi_spec.get("info").get("title")),
        )

        return _call_moto(
            context,
            "PutRestApi",
            PutRestApiRequest(
                restApiId=response.get("id"),
                failOnWarnings=str_to_bool(fail_on_warnings) or False,
                parameters=parameters or {},
                body=body_data,
            ),
        )

    def delete_integration(
        self, context: RequestContext, rest_api_id: String, resource_id: String, http_method: String
    ) -> None:
        try:
            call_moto(context)
        except Exception as e:
            raise NotFoundException("Invalid Resource identifier specified") from e

    def get_export(
        self,
        context: RequestContext,
        rest_api_id: String,
        stage_name: String,
        export_type: String,
        parameters: MapOfStringToString = None,
        accepts: String = None,
    ) -> ExportResponse:

        openapi_exporter = OpenApiExporter()
        result = openapi_exporter.export_api(
            api_id=rest_api_id, stage=stage_name, export_type=export_type, export_format=accepts
        )

        if accepts == APPLICATION_JSON:
            result = json.dumps(result, indent=2)

        return ExportResponse(contentType=accepts, body=result)

    def get_api_keys(
        self,
        context: RequestContext,
        position: String = None,
        limit: NullableInteger = None,
        name_query: String = None,
        customer_id: String = None,
        include_values: NullableBoolean = None,
    ) -> ApiKeys:
        moto_response: ApiKeys = call_moto(context=context)
        item_list = PaginatedList(moto_response["items"])

        def token_generator(item):
            return item["id"]

        def filter_function(item):
            return item["name"].startswith(name_query)

        paginated_list, next_token = item_list.get_page(
            token_generator=token_generator,
            next_token=position,
            page_size=limit,
            filter_function=filter_function if name_query else None,
        )

        return ApiKeys(
            items=paginated_list, warnings=moto_response.get("warnings"), position=next_token
        )


# ---------------
# UTIL FUNCTIONS
# ---------------


def _call_moto(context: RequestContext, operation_name: str, parameters: ServiceRequest):
    """
    Not necessarily the pattern we want to follow in the future, but this makes possible to nest
    moto call and still be interface compatible.

    Ripped :call_moto_with_request: from moto.py but applicable to any operation (operation_name).
    """
    local_context = create_aws_request_context(
        service_name=context.service.service_name,
        action=operation_name,
        parameters=parameters,
        region=context.region,
    )

    local_context.request.headers.update(context.request.headers)
    return call_moto(local_context)


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
