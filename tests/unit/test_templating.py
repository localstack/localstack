import base64
import json

import pytest

from localstack.services.apigateway.integration import VtlTemplate
from localstack.utils.common import to_str

# template used to transform incoming requests at the API Gateway (forward to Kinesis)
APIGW_TEMPLATE_TRANSFORM_KINESIS = """{
    "StreamName": "stream-1",
    "Records": [
        #set( $numRecords = $input.path('$.records').size() )
        #if($numRecords > 0)
        #set( $maxIndex = $numRecords - 1 )
        #foreach( $idx in [0..$maxIndex] )
        #set( $elem = $input.path("$.records[${idx}]") )
        #set( $elemJsonB64 = $util.base64Encode($input.json("$.records[${idx}].data")) )
        {
            "Data": "$elemJsonB64",
            "PartitionKey": #if( $elem.partitionKey != '')"$elem.partitionKey"
                            #else"$elemJsonB64.length()"#end
        }#if($foreach.hasNext),#end
        #end
        #end
    ]
}"""

# template used to construct JSON via #define method
APIGW_TEMPLATE_CONSTRUCT_JSON = """
#set( $body = $input.json("$") )

#define( $loop $map )
{
    #foreach($key in $map.keySet())
        #set( $k = $util.escapeJavaScript($key) )
        #set( $v = $util.escapeJavaScript($map.get($key)).replaceAll("\'", "'") )
        "$k":"$v"
        #if( $foreach.hasNext ) , #end
    #end
}
#end
{
    "p0": true,
    "p1": $loop($input.path('$.p1')),
    "p2": $loop($input.path('$.p2'))
}
"""

# APIGW_TEMPLATE_CUSTOM_BODY = """
# #set( $body = $input.json("$") )
#
# #define( $loop )
# {
#     #foreach($key in $map.keySet())
#         #set( $k = $util.escapeJavaScript($key) )
#         #set( $v = $util.escapeJavaScript($map.get($key)).replaceAll("\\'", "'") )
#         "$k": "$v"
#         #if( $foreach.hasNext ) , #end
#     #end
# }
# #end
#
#   {
#     #set( $map = $context.authorizer )
#     "enhancedAuthContext": $loop,
#
#     #set( $map = $input.params().header )
#     "headers": $loop,
#
#     #set( $map = $input.params().querystring )
#     "query": $loop,
#
#     #set( $map = $input.params().path )
#     "path": $loop,
#
#     #set( $map = $context.identity )
#     "identity": $loop,
#
#     #set( $map = $stageVariables )
#     "stageVariables": $loop,
# }
# """


@pytest.fixture
def velocity_template():
    return VtlTemplate()


class TestMessageTransformation:
    def test_array_size(self, velocity_template):
        template = "#set($list = $input.path('$.records')) $list.size()"
        body = {"records": [{"data": {"foo": "bar1"}}, {"data": {"foo": "bar2"}}]}
        variables = {
            "input": {
                "body": body,
            },
        }

        result = velocity_template.render_vtl(template, variables)
        assert result == " 2"

    def test_message_transformation(self, velocity_template):
        template = APIGW_TEMPLATE_TRANSFORM_KINESIS
        records = [
            {"data": {"foo": "foo1", "bar": "bar2"}},
            {"data": {"foo": "foo1", "bar": "bar2"}, "partitionKey": "key123"},
        ]
        variables = {"input": {"body": {"records": records}}}

        def do_test(variables):
            result = velocity_template.render_vtl(template, variables, as_json=True)
            result_decoded = json.loads(to_str(base64.b64decode(result["Records"][0]["Data"])))
            assert result_decoded == records[0]["data"]
            assert result["Records"][0]["PartitionKey"] == "$elem.partitionKey"
            assert result["Records"][1]["PartitionKey"] == "key123"

        # try rendering the template
        do_test(variables)

        # test with empty array
        records = []
        variables = {"input": {"body": {"records": records}}}
        # try rendering the template
        result = velocity_template.render_vtl(template, variables, as_json=True)
        assert result["Records"] == []

    def test_array_in_set_expr(self, velocity_template):
        template = "#set ($bar = $input.path('$.foo')[1]) \n $bar"
        variables = {"input": {"body": {"foo": ["e1", "e2", "e3", "e4"]}}}
        result = velocity_template.render_vtl(template, variables).strip()
        assert result == "e2"

        template = "#set ($bar = $input.path('$.foo')[1][1][1]) $bar"
        variables = {"input": {"body": {"foo": [["e1"], ["e2", ["e3", "e4"]]]}}}
        result = velocity_template.render_vtl(template, variables).strip()
        assert result == "e4"

    def test_string_methods(self, velocity_template):
        context = {"foo": {"bar": "BAZ baz"}}
        variables = {"input": {"body": context}}
        template1 = "${foo.bar.strip().lower().replace(' ','-')}"
        template2 = "${foo.bar.trim().toLowerCase().replace(' ','-')}"
        for template in [template1, template2]:
            result = velocity_template.render_vtl(template, variables=variables)
            assert result == "baz-baz"

    def test_render_urlencoded_string_data(self, velocity_template):
        template = "MessageBody=$util.base64Encode($input.json('$'))"
        variables = {"input": {"body": {"spam": "eggs"}}}
        result = velocity_template.render_vtl(template, variables)
        assert result == "MessageBody=eyJzcGFtIjogImVnZ3MifQ=="

    def test_construct_json_using_define(self, velocity_template):
        template = APIGW_TEMPLATE_CONSTRUCT_JSON
        data = {"p1": {"test": 123}, "p2": {"foo": "bar", "foo2": False}}
        variables = {"input": {"body": data}}
        result = velocity_template.render_vtl(template, variables).strip()
        result = json.loads(result)
        assert result == {'p0': True, 'p1': {'test': '123'}, 'p2': {'foo': 'bar', 'foo2': 'false'}}

    def test_keyset_functions(self, velocity_template):
        template = "#set($list = $input.path('$..var1[1]').keySet()) #foreach($e in $list)$e#end"
        body = {"var1": [{"a": 1}, {"b": 2}]}
        variables = {"input": {"body": body}}
        result = velocity_template.render_vtl(template, variables)
        assert result == " b"
