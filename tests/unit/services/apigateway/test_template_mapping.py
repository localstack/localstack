import json
from json import JSONDecodeError

import pytest
import xmltodict

from localstack.constants import APPLICATION_JSON, APPLICATION_XML
from localstack.services.apigateway.next_gen.execute_api.template_mapping import (
    ApiGatewayVtlTemplate,
    MappingTemplateInput,
    MappingTemplateParams,
    MappingTemplateVariables,
    VelocityUtilApiGateway,
)
from localstack.services.apigateway.next_gen.execute_api.variables import (
    ContextVariables,
    ContextVarsAuthorizer,
    ContextVarsIdentity,
)


class TestVelocityUtilApiGatewayFunctions:
    def test_render_template_values(self):
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


class TestApiGatewayVtlTemplate:
    def test_apply_template(self):
        variables = MappingTemplateVariables(
            input=MappingTemplateInput(body='{"action":"$default","message":"foobar"}')
        )

        template = "$util.escapeJavaScript($input.json('$.message'))"
        rendered_request = ApiGatewayVtlTemplate().render_vtl(
            template=template, variables=variables
        )

        assert '\\"foobar\\"' == rendered_request

    def test_apply_template_no_json_payload(self):
        variables = MappingTemplateVariables(input=MappingTemplateInput(body='"#foobar123"'))

        template = "$util.escapeJavaScript($input.json('$.message'))"
        rendered_request = ApiGatewayVtlTemplate().render_vtl(
            template=template, variables=variables
        )

        assert "[]" == rendered_request

    @pytest.mark.parametrize("format", [APPLICATION_JSON, APPLICATION_XML])
    def test_render_custom_template(self, format):
        variables = MappingTemplateVariables(
            input=MappingTemplateInput(
                body='{"spam": "eggs"}',
                params=MappingTemplateParams(
                    path={"proxy": "path"},
                    querystring={"baz": "test"},
                    header={"content-type": format, "accept": format},
                ),
            ),
            context=ContextVariables(
                httpMethod="POST",
                stage="local",
                authorizer=ContextVarsAuthorizer(principalId="12233"),
                identity=ContextVarsIdentity(accountId="00000", apiKey="11111"),
                resourcePath="/{proxy}",
            ),
            stageVariables={"stageVariable1": "value1", "stageVariable2": "value2"},
        )

        template = TEMPLATE_JSON if format == APPLICATION_JSON else TEMPLATE_XML
        template += REQUEST_OVERRIDE

        rendered_request, request_override = ApiGatewayVtlTemplate().render_request(
            template=template, variables=variables
        )
        if format == APPLICATION_JSON:
            rendered_request = json.loads(rendered_request)
            assert rendered_request.get("body") == {"spam": "eggs"}
            assert rendered_request.get("method") == "POST"
            assert rendered_request.get("principalId") == "12233"
        else:
            rendered_request = xmltodict.parse(rendered_request).get("root", {})
            # TODO Verify that those difference between xml and json are expected
            assert rendered_request.get("body") == '{"spam": "eggs"}'
            assert rendered_request.get("@method") == "POST"
            assert rendered_request.get("@principalId") == "12233"

        assert rendered_request.get("stage") == "local"
        assert rendered_request.get("enhancedAuthContext") == {"principalId": "12233"}
        assert rendered_request.get("identity") == {"accountId": "00000", "apiKey": "11111"}
        assert rendered_request.get("headers") == {
            "content-type": format,
            "accept": format,
        }
        assert rendered_request.get("query") == {"baz": "test"}
        assert rendered_request.get("path") == {"proxy": "path"}
        assert rendered_request.get("stageVariables") == {
            "stageVariable1": "value1",
            "stageVariable2": "value2",
        }

        assert request_override == {
            "header": {"multivalue": ["1header", "2header"], "oHeader": "1header"},
            "path": {"proxy": "proxy"},
            "querystring": {"query": "query"},
        }

    def test_render_valid_booleans_in_json(self):
        template = ApiGatewayVtlTemplate()

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

    # TODO Update the following tests when updating the response params
    # def test_error_when_render_invalid_json(self):
    #     api_context = ApiInvocationContext(
    #         method="POST",
    #         path="/foo/bar?baz=test",
    #         data=b"<root></root>",
    #         headers={},
    #     )
    #     api_context.integration = {
    #         "integrationResponses": {
    #             "200": {"responseTemplates": {APPLICATION_JSON: RESPONSE_TEMPLATE_WRONG_JSON}}
    #         },
    #     }
    #     api_context.response = requests_response({"spam": "eggs"})
    #     api_context.context = {}
    #     api_context.stage_variables = {}
    #
    #     template = ResponseTemplates()
    #     with pytest.raises(JSONDecodeError):
    #         template.render(api_context=api_context)
    #


#
#     def test_error_when_render_invalid_xml(self):
#         api_context = ApiInvocationContext(
#             method="POST",
#             path="/foo/bar?baz=test",
#             data=b"<root></root>",
#             headers={"content-type": APPLICATION_XML, "accept": APPLICATION_XML},
#             stage="local",
#         )
#         api_context.integration = {
#             "integrationResponses": {
#                 "200": {"responseTemplates": {APPLICATION_XML: RESPONSE_TEMPLATE_WRONG_XML}}
#             },
#         }
#         api_context.resource_path = "/{proxy+}"
#         api_context.response = requests_response({"spam": "eggs"})
#         api_context.context = {}
#         api_context.stage_variables = {}
#
#         template = ResponseTemplates()
#         with pytest.raises(xml.parsers.expat.ExpatError):
#             template.render(api_context=api_context, template_key=APPLICATION_XML)

TEMPLATE_JSON = """

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

TEMPLATE_WRONG_JSON = """
#set( $body = $input.json("$") )
  {
    "body": $body,
    "method": $context.httpMethod,
  }
"""

TEMPLATE_XML = """

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
REQUEST_OVERRIDE = """

#set($context.requestOverride.header.oHeader = "1header")
#set($context.requestOverride.header.multivalue = ["1header", "2header"])
#set($context.requestOverride.path.proxy = "proxy")
#set($context.requestOverride.querystring.query = "query")
"""

TEMPLATE_WRONG_XML = """
#set( $body = $input.json("$") )
<root>
  <body>$body</body>
  <not-closed>$context.stage
</root>
"""
