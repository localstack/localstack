import json
import unittest
import xml
from json import JSONDecodeError
from typing import Any, Dict
from unittest.mock import MagicMock, Mock

import boto3
import pytest
import xmltodict

from localstack.aws.api.apigateway import GatewayResponseType, Model
from localstack.constants import (
    APPLICATION_JSON,
    APPLICATION_XML,
    AWS_REGION_US_EAST_1,
    DEFAULT_AWS_ACCOUNT_ID,
)
from localstack.services.apigateway.helpers import (
    ModelResolver,
    OpenAPISpecificationResolver,
    RequestParametersResolver,
    apply_json_patch_safe,
    extract_path_params,
    extract_query_string_params,
    get_resource_for_path,
)
from localstack.services.apigateway.integration import (
    LambdaProxyIntegration,
    apply_request_parameters,
)
from localstack.services.apigateway.invocations import (
    ApiInvocationContext,
    BadRequestBody,
    RequestValidator,
)
from localstack.services.apigateway.models import ApiGatewayStore, RestApiContainer
from localstack.services.apigateway.next_gen.execute_api.gateway_response import (
    AccessDeniedError,
    BaseGatewayException,
)
from localstack.services.apigateway.templates import (
    RequestTemplates,
    ResponseTemplates,
    VelocityUtilApiGateway,
)
from localstack.testing.config import TEST_AWS_REGION_NAME
from localstack.utils.aws.aws_responses import requests_response
from localstack.utils.common import clone


class TestApiGatewayPaths:
    def test_extract_query_params(self):
        path, query_params = extract_query_string_params("/foo/bar?foo=foo&bar=bar&bar=baz")
        assert path == "/foo/bar"
        assert query_params == {"foo": "foo", "bar": ["bar", "baz"]}

    @pytest.mark.parametrize(
        "path,path_part,expected",
        [
            ("/foo/bar", "/foo/{param1}", {"param1": "bar"}),
            ("/foo/bar1/bar2", "/foo/{param1}/{param2}", {"param1": "bar1", "param2": "bar2"}),
            ("/foo/bar", "/foo/bar", {}),
            ("/foo/bar/baz", "/foo/{proxy+}", {"proxy": "bar/baz"}),
        ],
    )
    def test_extract_path_params(self, path, path_part, expected):
        assert extract_path_params(path, path_part) == expected

    @pytest.mark.parametrize(
        "path,path_parts,expected",
        [
            ("/foo/bar", ["/foo/{param1}"], "/foo/{param1}"),
            ("/foo/bar", ["/foo/bar", "/foo/{param1}"], "/foo/bar"),
            ("/foo/bar", ["/foo/{param1}", "/foo/bar"], "/foo/bar"),
            ("/foo/bar/baz", ["/foo/bar", "/foo/{proxy+}"], "/foo/{proxy+}"),
            ("/foo/bar/baz", ["/{proxy+}", "/foo/{proxy+}"], "/foo/{proxy+}"),
            ("/foo/bar", ["/foo/bar1", "/foo/bar2"], None),
            ("/foo/bar", ["/{param1}/bar1", "/foo/bar2"], None),
            ("/foo/bar", ["/{param1}/{param2}/foo/{param3}", "/{param}/bar"], "/{param}/bar"),
            ("/foo/bar", ["/{param1}/{param2}", "/{param}/bar"], "/{param}/bar"),
            ("/foo/bar", ["/{param}/bar", "/{param1}/{param2}"], "/{param}/bar"),
            ("/foo/bar", ["/foo/bar", "/foo/{param+}"], "/foo/bar"),
            ("/foo/bar", ["/foo/{param+}", "/foo/bar"], "/foo/bar"),
            (
                "/foo/bar/baz",
                ["/{param1}/{param2}/baz", "/{param1}/bar/{param2}"],
                "/{param1}/{param2}/baz",
            ),
            ("/foo/bar/baz", ["/foo123/{param1}/baz"], None),
            ("/foo/bar/baz", ["/foo/{param1}/baz", "/foo/{param1}/{param2}"], "/foo/{param1}/baz"),
            ("/foo/bar/baz", ["/foo/{param1}/{param2}", "/foo/{param1}/baz"], "/foo/{param1}/baz"),
        ],
    )
    def test_path_matches(self, path, path_parts, expected):
        default_resource = {"resourceMethods": {"GET": {}}}

        path_map = {path_part: default_resource for path_part in path_parts}
        matched_path, _ = get_resource_for_path(path, "GET", path_map)
        assert matched_path == expected

    def test_path_routing_with_method(self):
        """Not using parametrization as testing a simple scenario, AWS validated"""
        paths_map = {
            "/{proxy+}": {"resourceMethods": {"OPTIONS": {}}},
            "/foo": {"resourceMethods": {"POST": {}}},
            "/foo/bar": {"resourceMethods": {"ANY": {}}},
        }
        # If there is an exact match on the path but the resource on that path does not match on the method, try
        # greedy path then

        path, _ = get_resource_for_path("/foo", "GET", paths_map)
        # we can see that /foo would match 1:1, but it does not have a "GET" method, so it will try to match {proxy+},
        # but proxy does not have a GET either, so it will not match anything
        assert path is None

        path, _ = get_resource_for_path("/foo", "OPTIONS", paths_map)
        # now OPTIONS matches proxy
        assert path == "/{proxy+}"

        path, _ = get_resource_for_path("/foo", "POST", paths_map)
        # now POST directly matches /foo
        assert path == "/foo"

        path, _ = get_resource_for_path("/foo/bar", "GET", paths_map)
        # with this nested path, it will try to match the exact 1:1, and this one contains ANY, which will properly
        # match before trying {proxy+}
        assert path == "/foo/bar"

        path, _ = get_resource_for_path("/foo/bar", "OPTIONS", paths_map)
        # with this nested path, it will try to match the exact 1:1, and this one contains ANY, which will properly
        # match before trying {proxy+} even if it has the right OPTIONS method
        assert path == "/foo/bar"

    def test_apply_request_parameters(self):
        integration = {
            "type": "HTTP_PROXY",
            "httpMethod": "ANY",
            "uri": "https://httpbin.org/anything/{proxy}",
            "requestParameters": {"integration.request.path.proxy": "method.request.path.proxy"},
            "passthroughBehavior": "WHEN_NO_MATCH",
            "timeoutInMillis": 29000,
            "cacheNamespace": "041fa782",
            "cacheKeyParameters": [],
        }

        uri = apply_request_parameters(
            uri="https://httpbin.org/anything/{proxy}",
            integration=integration,
            path_params={"proxy": "foo/bar/baz"},
            query_params={"param": "foobar"},
        )
        assert uri == "https://httpbin.org/anything/foo/bar/baz?param=foobar"


class TestApiGatewayRequestValidator(unittest.TestCase):
    def test_if_request_is_valid_with_no_resource_methods(self):
        ctx = ApiInvocationContext(
            method="POST",
            path="/",
            data=b"",
            headers={},
        )
        ctx.account_id = DEFAULT_AWS_ACCOUNT_ID
        ctx.region_name = TEST_AWS_REGION_NAME
        validator = RequestValidator(ctx, Mock())
        assert validator.validate_request() is None

    def test_if_request_is_valid_with_no_matching_method(self):
        ctx = ApiInvocationContext(
            method="POST",
            path="/",
            data=b"",
            headers={},
        )
        ctx.resource = {"resourceMethods": {"GET": {}}}
        ctx.account_id = DEFAULT_AWS_ACCOUNT_ID
        ctx.region_name = TEST_AWS_REGION_NAME
        validator = RequestValidator(ctx, Mock())
        assert validator.validate_request() is None

    def test_if_request_is_valid_with_no_validator(self):
        ctx = ApiInvocationContext(
            method="POST",
            path="/",
            data=b"",
            headers={},
        )
        ctx.resource = {"resourceMethods": {"GET": {}}}
        ctx.account_id = DEFAULT_AWS_ACCOUNT_ID
        ctx.region_name = TEST_AWS_REGION_NAME
        ctx.api_id = "deadbeef"
        ctx.resource = {"resourceMethods": {"POST": {"requestValidatorId": " "}}}
        validator = RequestValidator(ctx, Mock())
        assert validator.validate_request() is None

    def test_if_request_has_body_validator(self):
        ctx = ApiInvocationContext(
            method="POST",
            path="/",
            data=b"",
            headers={},
        )
        ctx.account_id = DEFAULT_AWS_ACCOUNT_ID
        ctx.region_name = TEST_AWS_REGION_NAME
        ctx.api_id = "deadbeef"
        model_name = "schemaName"
        request_validator_id = "112233"
        ctx.resource = {
            "resourceMethods": {
                "POST": {
                    "requestValidatorId": model_name,
                    "requestModels": {"application/json": request_validator_id},
                }
            }
        }
        store = self._mock_store()
        container = RestApiContainer(rest_api={})
        container.validators[request_validator_id] = {"validateRequestBody": True}
        container.models[model_name] = {"schema": '{"type": "object"}'}
        store.rest_apis["deadbeef"] = container
        validator = RequestValidator(ctx, store)
        assert validator.validate_request() is None

    def test_request_validate_body_with_no_request_model(self):
        ctx = ApiInvocationContext(
            method="POST",
            path="/",
            data=b"",
            headers={},
        )
        ctx.account_id = DEFAULT_AWS_ACCOUNT_ID
        ctx.region_name = TEST_AWS_REGION_NAME
        ctx.api_id = "deadbeef"
        request_validator_id = "112233"
        empty_schema = json.dumps(
            {
                "$schema": "http://json-schema.org/draft-04/schema#",
                "title": "Empty Schema",
                "type": "object",
            }
        )

        ctx.resource = {
            "resourceMethods": {
                "POST": {
                    "requestValidatorId": request_validator_id,
                    "requestModels": None,
                }
            }
        }
        store = self._mock_store()
        container = RestApiContainer(rest_api={})
        container.validators = MagicMock()
        container.validators.get.return_value = {"validateRequestBody": True}
        container.models = MagicMock()
        container.models.get.return_value = {"schema": empty_schema}
        store.rest_apis["deadbeef"] = container
        validator = RequestValidator(ctx, store)
        assert validator.validate_request() is None

        container.validators.get.assert_called_with("112233")
        container.models.get.assert_called_with("Empty")

    def test_request_validate_body_with_no_model_for_schema_name(self):
        ctx = ApiInvocationContext(
            method="POST",
            path="/",
            data='{"id":"1"}',
            headers={},
        )
        ctx.account_id = DEFAULT_AWS_ACCOUNT_ID
        ctx.region_name = TEST_AWS_REGION_NAME
        ctx.api_id = "deadbeef"
        model_name = "schemaName"
        request_validator_id = "112233"
        ctx.resource = {
            "resourceMethods": {
                "POST": {
                    "requestValidatorId": model_name,
                    "requestModels": {"application/json": request_validator_id},
                }
            }
        }
        store = self._mock_store()
        container = RestApiContainer(rest_api={})
        container.validators = MagicMock()
        container.validators.get.return_value = {"validateRequestBody": True}
        container.models = MagicMock()
        container.models.get.return_value = None
        store.rest_apis["deadbeef"] = container
        validator = RequestValidator(ctx, store)
        with pytest.raises(BadRequestBody):
            validator.validate_request()

    def test_request_validate_body_with_circular_and_recursive_model(self):
        def _create_context_with_data(body_data: dict):
            ctx = ApiInvocationContext(
                method="POST",
                path="/",
                data=json.dumps(body_data),
                headers={},
            )
            ctx.account_id = DEFAULT_AWS_ACCOUNT_ID
            ctx.region_name = TEST_AWS_REGION_NAME
            ctx.api_id = "deadbeef"
            ctx.resource = {
                "resourceMethods": {
                    "POST": {
                        "requestValidatorId": request_validator_id,
                        "requestModels": {APPLICATION_JSON: "Person"},
                    }
                }
            }
            return ctx

        container = RestApiContainer(rest_api={})

        request_validator_id = "112233"
        container.validators[request_validator_id] = {"validateRequestBody": True}

        # set up the model, Person, which references House
        model_id_person = "model1"
        model_name_person = "Person"
        model_schema_person = {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                },
                "house": {
                    "$ref": "https://domain.com/restapis/deadbeef/models/House",
                },
            },
            "required": ["name"],
        }

        model_person = Model(
            id=model_id_person,
            name=model_name_person,
            contentType=APPLICATION_JSON,
            schema=json.dumps(model_schema_person),
        )
        container.models[model_name_person] = model_person

        # set up the model House, which references the Person model, we have a circular ref, and House itself
        model_id_house = "model2"
        model_name_house = "House"
        model_schema_house = {
            "type": "object",
            "required": ["houseType"],
            "properties": {
                "houseType": {
                    "type": "string",
                },
                "contains": {
                    "type": "array",
                    "items": {
                        "$ref": "https://domain.com/restapis/deadbeef/models/Person",
                    },
                },
                "houses": {
                    "type": "array",
                    "items": {
                        "$ref": "https://domain.com/restapis/deadbeef/models/House",
                    },
                },
            },
        }

        model_house = Model(
            id=model_id_house,
            name=model_name_house,
            contentType=APPLICATION_JSON,
            schema=json.dumps(model_schema_house),
        )
        container.models[model_name_house] = model_house

        store = self._mock_store()
        store.rest_apis["deadbeef"] = container

        invocation_context = _create_context_with_data(
            {
                "name": "test",
                "house": {  # the House object is missing "houseType"
                    "contains": [{"name": "test"}],  # the Person object has the required "name"
                    "houses": [{"coucou": "test"}],  # the House object is missing "houseType"
                },
            }
        )

        validator = RequestValidator(invocation_context, store)
        with pytest.raises(BadRequestBody):
            validator.validate_request()

        invocation_context = _create_context_with_data(
            {
                "name": "test",
                "house": {
                    "houseType": "random",  # the House object has the required ""houseType"
                    "contains": [{"name": "test"}],  # the Person object has the required "name"
                    "houses": [{"houseType": "test"}],  # the House object is missing "houseType"
                },
            }
        )

        validator = RequestValidator(invocation_context, store)
        assert validator.validate_request() is None

    def _mock_client(self):
        return Mock(boto3.client("apigateway", region_name=AWS_REGION_US_EAST_1))

    def _mock_store(self):
        return ApiGatewayStore()


def test_render_template_values():
    util = VelocityUtilApiGateway()

    encoded = util.urlEncode("x=a+b")
    assert encoded == "x%3Da%2Bb"

    decoded = util.urlDecode("x=a+b")
    assert decoded == "x=a b"

    escape_tests = (
        ("it's", "it's"),
        ("0010", "0010"),
        ("true", "true"),
        ("True", "True"),
        ("1.021", "1.021"),
        ('""', '\\"\\"'),
        ('"""', '\\"\\"\\"'),
        ('{"foo": 123}', '{\\"foo\\": 123}'),
        ('{"foo"": 123}', '{\\"foo\\"\\": 123}'),
        (1, "1"),
        (None, "null"),
    )
    for string, expected in escape_tests:
        escaped = util.escapeJavaScript(string)
        assert escaped == expected


class TestVelocityUtilApiGatewayFunctions:
    def test_parse_json(self):
        util = VelocityUtilApiGateway()

        # write table tests for the following input
        a = {"array": "[1,2,3]"}
        obj = util.parseJson(a["array"])
        assert obj[0] == 1

        o = {"object": '{"key1":"var1","key2":{"arr":[1,2,3]}}'}
        obj = util.parseJson(o["object"])
        assert obj.key2.arr[0] == 1

        s = '"string"'
        obj = util.parseJson(s)
        assert obj == "string"

        n = {"number": "1"}
        obj = util.parseJson(n["number"])
        assert obj == 1

        b = {"boolean": "true"}
        obj = util.parseJson(b["boolean"])
        assert obj is True

        z = {"zero_length_array": "[]"}
        obj = util.parseJson(z["zero_length_array"])
        assert obj == []


class TestJSONPatch(unittest.TestCase):
    def test_apply_json_patch(self):
        apply = apply_json_patch_safe

        # test replacing array index
        subject = {"root": [{"arr": ["1", "abc"]}]}
        result = apply(clone(subject), {"op": "replace", "path": "/root/0/arr/0", "value": 2})
        self.assertEqual({"arr": [2, "abc"]}, result["root"][0])

        # test replacing endpoint config type
        operation = {"op": "replace", "path": "/endpointConfiguration/types/0", "value": "EDGE"}
        subject = {
            "id": "b5d563g3yx",
            "endpointConfiguration": {"types": ["REGIONAL"], "vpcEndpointIds": []},
        }
        result = apply(clone(subject), operation)
        self.assertEqual(["EDGE"], result["endpointConfiguration"]["types"])

        # test replacing endpoint config type
        operation = {"op": "add", "path": "/features/-", "value": "feat2"}
        subject = {"features": ["feat1"]}
        result = apply(clone(subject), operation)
        self.assertEqual(["feat1", "feat2"], result["features"])


class TestApplyTemplate(unittest.TestCase):
    def test_apply_template(self):
        api_context = ApiInvocationContext(
            method="POST",
            path="/foo/bar?baz=test",
            data='{"action":"$default","message":"foobar"}',
            headers={"content-type": APPLICATION_JSON},
            stage="local",
        )
        api_context.response = requests_response({})
        api_context.integration = {
            "requestTemplates": {
                APPLICATION_JSON: "$util.escapeJavaScript($input.json('$.message'))"
            },
        }

        rendered_request = RequestTemplates().render(api_context=api_context)

        self.assertEqual('\\"foobar\\"', rendered_request)

    def test_apply_template_no_json_payload(self):
        api_context = ApiInvocationContext(
            method="POST",
            path="/foo/bar?baz=test",
            data=b'"#foobar123"',
            headers={"content-type": APPLICATION_JSON},
            stage="local",
        )
        api_context.integration = {
            "requestTemplates": {
                APPLICATION_JSON: "$util.escapeJavaScript($input.json('$.message'))"
            },
        }

        rendered_request = RequestTemplates().render(api_context=api_context)

        self.assertEqual("[]", rendered_request)


RESPONSE_TEMPLATE_JSON = """

#set( $body = $input.json("$") )
#define( $loop )
{
    #foreach($e in $map.keySet())
       #set( $k = $e )
       #set( $v = $map.get($k))
       "$k": "$v"
       #if( $foreach.hasNext ) , #end
    #end
}
#end
  {
    "body": $body,
    "method": "$context.httpMethod",
    "principalId": "$context.authorizer.principalId",
    "stage": "$context.stage",
    "cognitoPoolClaims" : {
       "sub": "$context.authorizer.claims.sub"
    },
    #set( $map = $context.authorizer )
    "enhancedAuthContext": $loop,

    #set( $map = $input.params().header )
    "headers": $loop,

    #set( $map = $input.params().querystring )
    "query": $loop,

    #set( $map = $input.params().path )
    "path": $loop,

    #set( $map = $context.identity )
    "identity": $loop,

    #set( $map = $stageVariables )
    "stageVariables": $loop,

    "requestPath": "$context.resourcePath"
}
"""

RESPONSE_TEMPLATE_WRONG_JSON = """
#set( $body = $input.json("$") )
  {
    "body": $body,
    "method": $context.httpMethod,
  }
"""

RESPONSE_TEMPLATE_XML = """

#set( $body = $input.json("$") )
#define( $loop )
    #foreach($e in $map.keySet())
       #set( $k = $e )
       #set( $v = $map.get($k))
       <$k>$v</$k>
    #end
#end
  <root method="$context.httpMethod" principalId="$context.authorizer.principalId" requestPath="$context.resourcePath">
    <body>$body</body>
    <stage>$context.stage</stage>
    <cognitoPoolClaims>
       <sub>$context.authorizer.claims.sub</sub>
    </cognitoPoolClaims>

    #set( $map = $context.authorizer )
    <enhancedAuthContext>$loop</enhancedAuthContext>

    #set( $map = $input.params().header )
    <headers>$loop</headers>

    #set( $map = $input.params().querystring )
    <query>$loop</query>

    #set( $map = $input.params().path )
    <path>$loop</path>

    #set( $map = $context.identity )
    <identity>$loop</identity>

    #set( $map = $stageVariables )
    <stageVariables>$loop</stageVariables>
  </root>
"""

RESPONSE_TEMPLATE_WRONG_XML = """
#set( $body = $input.json("$") )
<root>
  <body>$body</body>
  <not-closed>$context.stage
</root>
"""


class TestTemplates:
    @pytest.mark.parametrize(
        "template,accept_content_type",
        [
            (RequestTemplates(), APPLICATION_JSON),
            (ResponseTemplates(), APPLICATION_JSON),
            (RequestTemplates(), "*/*"),
            (ResponseTemplates(), "*/*"),
        ],
    )
    def test_render_custom_template(self, template, accept_content_type):
        api_context = ApiInvocationContext(
            method="POST",
            path="/foo/bar?baz=test",
            data=b'{"spam": "eggs"}',
            headers={"content-type": APPLICATION_JSON, "accept": accept_content_type},
            stage="local",
        )
        api_context.integration = {
            "requestTemplates": {APPLICATION_JSON: RESPONSE_TEMPLATE_JSON},
            "integrationResponses": {
                "200": {"responseTemplates": {APPLICATION_JSON: RESPONSE_TEMPLATE_JSON}}
            },
        }
        api_context.resource_path = "/{proxy+}"
        api_context.path_params = {"id": "bar"}
        api_context.response = requests_response({"spam": "eggs"})
        api_context.context = {
            "httpMethod": api_context.method,
            "stage": api_context.stage,
            "authorizer": {"principalId": "12233"},
            "identity": {"accountId": "00000", "apiKey": "11111"},
            "resourcePath": api_context.resource_path,
        }
        api_context.stage_variables = {"stageVariable1": "value1", "stageVariable2": "value2"}

        rendered_request = template.render(api_context=api_context)
        result_as_json = json.loads(rendered_request)

        assert result_as_json.get("body") == {"spam": "eggs"}
        assert result_as_json.get("method") == "POST"
        assert result_as_json.get("principalId") == "12233"
        assert result_as_json.get("stage") == "local"
        assert result_as_json.get("enhancedAuthContext") == {"principalId": "12233"}
        assert result_as_json.get("identity") == {"accountId": "00000", "apiKey": "11111"}
        assert result_as_json.get("headers") == {
            "content-type": APPLICATION_JSON,
            "accept": accept_content_type,
        }
        assert result_as_json.get("query") == {"baz": "test"}
        assert result_as_json.get("path") == {"id": "bar"}
        assert result_as_json.get("stageVariables") == {
            "stageVariable1": "value1",
            "stageVariable2": "value2",
        }

    def test_render_valid_booleans_in_json(self):
        template = ResponseTemplates()

        # assert that boolean results of _render_json_result(..) are JSON-parseable
        tstring = '{"mybool": $boolTrue}'
        result = template._render_as_text(tstring, {"boolTrue": "true"})
        assert json.loads(result) == {"mybool": True}
        result = template._render_as_text(tstring, {"boolTrue": True})
        assert json.loads(result) == {"mybool": True}

        # older versions of `airspeed` were rendering booleans as False/True, which is no longer valid now
        tstring = '{"mybool": False}'
        with pytest.raises(JSONDecodeError):
            result = template._render_as_text(tstring, {})
            template._validate_json(result)

    def test_error_when_render_invalid_json(self):
        api_context = ApiInvocationContext(
            method="POST",
            path="/foo/bar?baz=test",
            data=b"<root></root>",
            headers={},
        )
        api_context.integration = {
            "integrationResponses": {
                "200": {"responseTemplates": {APPLICATION_JSON: RESPONSE_TEMPLATE_WRONG_JSON}}
            },
        }
        api_context.response = requests_response({"spam": "eggs"})
        api_context.context = {}
        api_context.stage_variables = {}

        template = ResponseTemplates()
        with pytest.raises(JSONDecodeError):
            template.render(api_context=api_context)

    @pytest.mark.parametrize("template", [RequestTemplates(), ResponseTemplates()])
    def test_render_custom_template_in_xml(self, template):
        api_context = ApiInvocationContext(
            method="POST",
            path="/foo/bar?baz=test",
            data=b'{"spam": "eggs"}',
            headers={"content-type": APPLICATION_XML, "accept": APPLICATION_XML},
            stage="local",
        )
        api_context.integration = {
            "requestTemplates": {APPLICATION_XML: RESPONSE_TEMPLATE_XML},
            "integrationResponses": {
                "200": {"responseTemplates": {APPLICATION_XML: RESPONSE_TEMPLATE_XML}}
            },
        }
        api_context.resource_path = "/{proxy+}"
        api_context.path_params = {"id": "bar"}
        api_context.response = requests_response({"spam": "eggs"})
        api_context.context = {
            "httpMethod": api_context.method,
            "stage": api_context.stage,
            "authorizer": {"principalId": "12233"},
            "identity": {"accountId": "00000", "apiKey": "11111"},
            "resourcePath": api_context.resource_path,
        }
        api_context.stage_variables = {"stageVariable1": "value1", "stageVariable2": "value2"}

        rendered_request = template.render(api_context=api_context, template_key=APPLICATION_XML)
        result_as_xml = xmltodict.parse(rendered_request).get("root", {})

        assert result_as_xml.get("body") == '{"spam": "eggs"}'
        assert result_as_xml.get("@method") == "POST"
        assert result_as_xml.get("@principalId") == "12233"
        assert result_as_xml.get("stage") == "local"
        assert result_as_xml.get("enhancedAuthContext") == {"principalId": "12233"}
        assert result_as_xml.get("identity") == {"accountId": "00000", "apiKey": "11111"}
        assert result_as_xml.get("headers") == {
            "content-type": APPLICATION_XML,
            "accept": APPLICATION_XML,
        }
        assert result_as_xml.get("query") == {"baz": "test"}
        assert result_as_xml.get("path") == {"id": "bar"}
        assert result_as_xml.get("stageVariables") == {
            "stageVariable1": "value1",
            "stageVariable2": "value2",
        }

    def test_error_when_render_invalid_xml(self):
        api_context = ApiInvocationContext(
            method="POST",
            path="/foo/bar?baz=test",
            data=b"<root></root>",
            headers={"content-type": APPLICATION_XML, "accept": APPLICATION_XML},
            stage="local",
        )
        api_context.integration = {
            "integrationResponses": {
                "200": {"responseTemplates": {APPLICATION_XML: RESPONSE_TEMPLATE_WRONG_XML}}
            },
        }
        api_context.resource_path = "/{proxy+}"
        api_context.response = requests_response({"spam": "eggs"})
        api_context.context = {}
        api_context.stage_variables = {}

        template = ResponseTemplates()
        with pytest.raises(xml.parsers.expat.ExpatError):
            template.render(api_context=api_context, template_key=APPLICATION_XML)


def test_openapi_resolver_given_unresolvable_references():
    document = {
        "schema": {"$ref": "#/definitions/NotFound"},
        "definitions": {"Found": {"type": "string"}},
    }
    resolver = OpenAPISpecificationResolver(document, allow_recursive=True, rest_api_id="123")
    result = resolver.resolve_references()
    assert result == {"schema": None, "definitions": {"Found": {"type": "string"}}}


def test_openapi_resolver_given_invalid_references():
    document = {"schema": {"$ref": ""}, "definitions": {"Found": {"type": "string"}}}
    resolver = OpenAPISpecificationResolver(document, allow_recursive=True, rest_api_id="123")
    result = resolver.resolve_references()
    assert result == {"schema": None, "definitions": {"Found": {"type": "string"}}}


def test_openapi_resolver_given_schema_list_references():
    # We shouldn't resolve when the $ref is targeting a schema (Model)
    document = {
        "schema": {"$ref": "#/definitions/Found"},
        "definitions": {"Found": {"value": ["v1", "v2"]}},
    }
    resolver = OpenAPISpecificationResolver(document, allow_recursive=True, rest_api_id="123")
    result = resolver.resolve_references()
    assert result == document


def test_openapi_resolver_given_list_references():
    document = {
        "responses": {"$ref": "#/definitions/ResponsePost"},
        "definitions": {"ResponsePost": {"value": ["v1", "v2"]}},
    }
    resolver = OpenAPISpecificationResolver(document, allow_recursive=True, rest_api_id="123")
    result = resolver.resolve_references()
    assert result == {
        "responses": {"value": ["v1", "v2"]},
        "definitions": {"ResponsePost": {"value": ["v1", "v2"]}},
    }


def test_create_invocation_headers():
    invocation_context = ApiInvocationContext(
        method="GET", path="/", data="", headers={"X-Header": "foobar"}
    )
    invocation_context.integration = {
        "requestParameters": {"integration.request.header.X-Custom": "'Event'"}
    }
    headers = invocation_context.headers

    req_params_resolver = RequestParametersResolver()
    req_params = req_params_resolver.resolve(invocation_context)

    headers.update(req_params.get("headers", {}))
    assert headers == {"X-Header": "foobar", "X-Custom": "Event"}

    invocation_context.integration = {
        "requestParameters": {"integration.request.path.foobar": "'CustomValue'"}
    }

    req_params = req_params_resolver.resolve(invocation_context)
    headers.update(req_params.get("headers", {}))
    assert headers == {"X-Header": "foobar", "X-Custom": "Event"}

    path = req_params.get("path", {})
    assert path == {"foobar": "CustomValue"}


class TestApigatewayEvents:
    def test_construct_invocation_event(self):
        tt = [
            {
                "method": "GET",
                "path": "http://localhost.localstack.cloud",
                "headers": {},
                "data": None,
                "query_string_params": None,
                "is_base64_encoded": False,
                "expected": {
                    "path": "http://localhost.localstack.cloud",
                    "headers": {},
                    "multiValueHeaders": {},
                    "body": None,
                    "isBase64Encoded": False,
                    "httpMethod": "GET",
                    "queryStringParameters": None,
                    "multiValueQueryStringParameters": None,
                },
            },
            {
                "method": "GET",
                "path": "http://localhost.localstack.cloud",
                "headers": {},
                "data": None,
                "query_string_params": {},
                "is_base64_encoded": False,
                "expected": {
                    "path": "http://localhost.localstack.cloud",
                    "headers": {},
                    "multiValueHeaders": {},
                    "body": None,
                    "isBase64Encoded": False,
                    "httpMethod": "GET",
                    "queryStringParameters": None,
                    "multiValueQueryStringParameters": None,
                },
            },
            {
                "method": "GET",
                "path": "http://localhost.localstack.cloud",
                "headers": {},
                "data": None,
                "query_string_params": {"foo": "bar"},
                "is_base64_encoded": False,
                "expected": {
                    "path": "http://localhost.localstack.cloud",
                    "headers": {},
                    "multiValueHeaders": {},
                    "body": None,
                    "isBase64Encoded": False,
                    "httpMethod": "GET",
                    "queryStringParameters": {"foo": "bar"},
                    "multiValueQueryStringParameters": {"foo": ["bar"]},
                },
            },
            {
                "method": "GET",
                "path": "http://localhost.localstack.cloud?baz=qux",
                "headers": {},
                "data": None,
                "query_string_params": {"foo": "bar"},
                "is_base64_encoded": False,
                "expected": {
                    "path": "http://localhost.localstack.cloud?baz=qux",
                    "headers": {},
                    "multiValueHeaders": {},
                    "body": None,
                    "isBase64Encoded": False,
                    "httpMethod": "GET",
                    "queryStringParameters": {"foo": "bar"},
                    "multiValueQueryStringParameters": {"foo": ["bar"]},
                },
            },
        ]

        for t in tt:
            result = LambdaProxyIntegration.construct_invocation_event(
                t["method"],
                t["path"],
                t["headers"],
                t["data"],
                t["query_string_params"],
                t["is_base64_encoded"],
            )
            assert result == t["expected"]


class TestRequestParameterResolver:
    def test_resolve_request_parameters(self):
        integration: Dict[str, Any] = {
            "requestParameters": {
                "integration.request.path.pathParam": "method.request.path.id",
                "integration.request.querystring.baz": "method.request.querystring.baz",
                "integration.request.querystring.token": "method.request.header.Authorization",
                "integration.request.querystring.env": "stageVariables.enviroment",
                "integration.request.header.Content-Type": "'application/json'",
                "integration.request.header.body-header": "method.request.body",
                "integration.request.header.testContext": "context.authorizer.myvalue",
            }
        }

        context = ApiInvocationContext(
            method="POST",
            path="/foo/bar?baz=test",
            data="spam_eggs",
            headers={"Authorization": "Bearer 1234"},
            stage="local",
        )
        context.path_params = {"id": "bar"}
        context.integration = integration
        context.stage_variables = {"enviroment": "dev"}
        context.auth_context["authorizer"] = {"MyValue": 1}
        resolver = RequestParametersResolver()
        result = resolver.resolve(context)

        assert result == {
            "path": {"pathParam": "bar"},
            "querystring": {"baz": "test", "token": "Bearer 1234", "env": "dev"},
            "headers": {
                "Content-Type": "application/json",
                "body-header": "spam_eggs",
                "testContext": "1",
            },
        }


class TestModelResolver:
    def test_resolve_regular_model(self):
        container = RestApiContainer(rest_api={})
        # set up the model
        model_id = "model1"
        model_name = "Pet"
        model_schema = {
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "type": {"type": "string"},
                "price": {"type": "number"},
            },
        }

        model = Model(
            id=model_id,
            name=model_name,
            contentType=APPLICATION_JSON,
            schema=json.dumps(model_schema),
        )

        container.models[model_name] = model

        resolver = ModelResolver(rest_api_container=container, model_name=model_name)

        resolved_model = resolver.get_resolved_model()
        # there are no $ref to resolve, the schema should identical
        assert resolved_model == model_schema

    def test_resolve_non_existent_model(self):
        container = RestApiContainer(rest_api={})

        resolver = ModelResolver(rest_api_container=container, model_name="deadbeef")

        resolved_model = resolver.get_resolved_model()
        # the Model does not exist, verify it returns None
        assert resolved_model is None

    def test_resolve_regular_model_with_nested_ref(self):
        container = RestApiContainer(rest_api={})

        # set up the model PetType
        model_id_pet_type = "model0"
        model_name_pet_type = "PetType"
        model_schema_pet_type = {"type": "string", "enum": ["dog", "cat", "fish", "bird", "gecko"]}

        model = Model(
            id=model_id_pet_type,
            name=model_name_pet_type,
            contentType=APPLICATION_JSON,
            schema=json.dumps(model_schema_pet_type),
        )
        container.models[model_name_pet_type] = model

        # set up the model Pet
        model_id_pet = "model1"
        model_name_pet = "Pet"
        model_schema_pet = {
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "type": {"$ref": "https://domain.com/restapis/deadbeef/models/PetType"},
                "price": {"type": "number"},
            },
        }

        model = Model(
            id=model_id_pet,
            name=model_name_pet,
            contentType=APPLICATION_JSON,
            schema=json.dumps(model_schema_pet),
        )
        container.models[model_name_pet] = model

        # set up the model NewPetResponse
        model_id_new_response_pet = "model2"
        model_name_new_response_pet = "NewPetResponse"
        model_schema_new_response_pet = {
            "type": "object",
            "properties": {
                "pet": {"$ref": "https://domain.com/restapis/deadbeef/models/Pet"},
                "message": {"type": "string"},
            },
        }

        model_2 = Model(
            id=model_id_new_response_pet,
            name=model_name_new_response_pet,
            contentType=APPLICATION_JSON,
            schema=json.dumps(model_schema_new_response_pet),
        )
        container.models[model_name_new_response_pet] = model_2

        resolver = ModelResolver(
            rest_api_container=container, model_name=model_name_new_response_pet
        )

        resolved_model = resolver.get_resolved_model()
        # assert that the Pet Model has been resolved and set in $defs for NewPetResponse Model
        assert resolved_model["properties"]["pet"]["$ref"] == "#/$defs/Pet"
        assert resolved_model["$defs"]["Pet"]["type"] == model_schema_pet["type"]
        assert (
            resolved_model["$defs"]["Pet"]["properties"]["id"]
            == model_schema_pet["properties"]["id"]
        )

        # assert that the PetType Model has been resolved in $defs and also set in $defs for Pet Model
        assert resolved_model["$defs"]["Pet"]["properties"]["type"]["$ref"] == "#/$defs/PetType"
        assert resolved_model["$defs"]["PetType"] == model_schema_pet_type

    def test_resolve_regular_model_with_missing_ref(self):
        container = RestApiContainer(rest_api={})
        # set up the model
        model_id_new_response_pet = "model2"
        model_name_new_response_pet = "NewPetResponse"
        model_schema_new_response_pet = {
            "type": "object",
            "properties": {
                "pet": {
                    "$ref": "https://domain.com/restapis/deadbeef/models/Pet"  # this ref is not present
                },
                "message": {"type": "string"},
            },
        }

        model_2 = Model(
            id=model_id_new_response_pet,
            name=model_name_new_response_pet,
            contentType=APPLICATION_JSON,
            schema=json.dumps(model_schema_new_response_pet),
        )
        container.models[model_name_new_response_pet] = model_2

        resolver = ModelResolver(
            rest_api_container=container, model_name=model_name_new_response_pet
        )

        resolved_model = resolver.get_resolved_model()
        assert resolved_model is None

    def test_resolve_model_circular_ref(self):
        container = RestApiContainer(rest_api={})
        # set up the model, Person, which references House
        model_id_person = "model1"
        model_name_person = "Person"
        model_schema_person = {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                },
                "house": {"$ref": "https://domain.com/restapis/deadbeef/models/House"},
            },
        }

        model_person = Model(
            id=model_id_person,
            name=model_name_person,
            contentType=APPLICATION_JSON,
            schema=json.dumps(model_schema_person),
        )
        container.models[model_name_person] = model_person

        # set up the model House, which references the Person model, we have a circular ref
        model_id_house = "model2"
        model_name_house = "House"
        model_schema_house = {
            "type": "object",
            "properties": {
                "contains": {
                    "type": "array",
                    "items": {"$ref": "https://domain.com/restapis/deadbeef/models/Person"},
                }
            },
        }

        model_house = Model(
            id=model_id_house,
            name=model_name_house,
            contentType=APPLICATION_JSON,
            schema=json.dumps(model_schema_house),
        )
        container.models[model_name_house] = model_house

        # we resolve the Person model containing the House model (which contains the Person model)
        resolver = ModelResolver(rest_api_container=container, model_name=model_name_person)

        resolved_model = resolver.get_resolved_model()
        # assert that the House Model has been resolved and set in $defs for Person Model
        assert resolved_model["properties"]["house"]["$ref"] == "#/$defs/House"

        # now assert that the Person $ref in House has been properly resolved to #, indicating a recursive $ref to its
        # own model
        assert resolved_model["$defs"]["House"]["properties"]["contains"]["items"]["$ref"] == "#"

        # now we need to resolve the House schema to see if the cached Person is properly set in $defs with proper
        # references
        resolver = ModelResolver(rest_api_container=container, model_name=model_name_house)

        resolved_model = resolver.get_resolved_model()
        # assert that the Person Model has been resolved and set in $defs for House Model
        assert resolved_model["properties"]["contains"]["items"]["$ref"] == "#/$defs/Person"

        # now assert that the House $ref in Person has been properly resolved to #, indicating a recursive $ref to its
        # own model
        assert resolved_model["$defs"]["Person"]["properties"]["house"]["$ref"] == "#"

    def test_resolve_model_recursive_ref(self):
        container = RestApiContainer(rest_api={})
        # set up the model, Person, which references Person (recursive ref)
        model_id_person = "model1"
        model_name_person = "Person"
        model_schema_person = {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                },
                "children": {
                    "type": "array",
                    "items": {"$ref": "https://domain.com/restapis/deadbeef/models/Person"},
                },
            },
        }

        model_person = Model(
            id=model_id_person,
            name=model_name_person,
            contentType=APPLICATION_JSON,
            schema=json.dumps(model_schema_person),
        )
        container.models[model_name_person] = model_person

        # we resolve the Person model containing the House model (which contains the Person model)
        resolver = ModelResolver(rest_api_container=container, model_name=model_name_person)

        resolved_model = resolver.get_resolved_model()
        # assert that the Person Model has been resolved, and the recursive $ref set to #
        assert resolved_model["properties"]["children"]["items"]["$ref"] == "#"

    def test_resolve_model_circular_ref_with_recursive_ref(self):
        container = RestApiContainer(rest_api={})
        # set up the model, Person, which references House
        model_id_person = "model1"
        model_name_person = "Person"
        model_schema_person = {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                },
                "house": {"$ref": "https://domain.com/restapis/deadbeef/models/House"},
            },
        }

        model_person = Model(
            id=model_id_person,
            name=model_name_person,
            contentType=APPLICATION_JSON,
            schema=json.dumps(model_schema_person),
        )
        container.models[model_name_person] = model_person

        # set up the model House, which references the Person model, we have a circular ref, and House itself
        model_id_house = "model2"
        model_name_house = "House"
        model_schema_house = {
            "type": "object",
            "properties": {
                "contains": {
                    "type": "array",
                    "items": {"$ref": "https://domain.com/restapis/deadbeef/models/Person"},
                },
                "houses": {
                    "type": "array",
                    "items": {"$ref": "https://domain.com/restapis/deadbeef/models/House"},
                },
            },
        }

        model_house = Model(
            id=model_id_house,
            name=model_name_house,
            contentType=APPLICATION_JSON,
            schema=json.dumps(model_schema_house),
        )
        container.models[model_name_house] = model_house

        # we resolve the Person model containing the House model (which contains the Person model)
        resolver = ModelResolver(rest_api_container=container, model_name=model_name_person)

        resolved_model = resolver.get_resolved_model()
        # assert that the House Model has been resolved and set in $defs for Person Model
        assert resolved_model["properties"]["house"]["$ref"] == "#/$defs/House"

        # now assert that the Person $ref in House has been properly resolved to #, indicating a recursive $ref to its
        # own model
        assert resolved_model["$defs"]["House"]["properties"]["contains"]["items"]["$ref"] == "#"

        # now assert that the Person $ref in House has been properly resolved to #, indicating a recursive $ref to its
        # own model
        assert (
            resolved_model["$defs"]["House"]["properties"]["houses"]["items"]["$ref"]
            == "#/$defs/House"
        )


class TestGatewayResponse:
    def test_base_response(self):
        with pytest.raises(BaseGatewayException) as e:
            raise BaseGatewayException()
        assert e.value.message == "Unimplemented Response"

    def test_subclassed_response(self):
        with pytest.raises(BaseGatewayException) as e:
            raise AccessDeniedError("Access Denied")
        assert e.value.message == "Access Denied"
        assert e.value.type == GatewayResponseType.ACCESS_DENIED
