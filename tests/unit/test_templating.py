import json
import re

from localstack.services.apigateway.templates import ApiGatewayVtlTemplate
from localstack.utils.aws.templating import render_velocity_template

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
                            #else"$elemJsonB64"#end
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
        #set( $v = $util.escapeJavaScript($map.get($key)))
        "$k": "$v"
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

APIGW_TEMPLATE_CUSTOM_BODY = """
#set( $body = $input.json("$") )

#define( $loop )
{
    #foreach($key in $map.keySet())
        #set( $k = $util.escapeJavaScript($key) )
        #set( $v = $util.escapeJavaScript($map.get($key)).replaceAll("\\'", "'") )
        "$k": "$v"
        #if( $foreach.hasNext ) , #end
    #end
}
#end

  {
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
}
"""


class TestMessageTransformationBasic:
    def test_return_macro(self):
        template = """
        #set($v1 = {})
        $v1.put('foo', 'bar')
        #return($v1)
        """
        result = render_velocity_template(template, {})
        expected = {"foo": "bar"}
        assert json.loads(result) == expected

    def test_quiet_return_function(self):
        # render .put(..) without quiet function
        template = """
        #set($v1 = {})
        $v1.put('foo', 'bar1')$v1.put('foo', 'bar2')
        #return($v1)
        """
        result = render_velocity_template(template, {})
        result = re.sub(r"\s+", " ", result).strip()
        assert result == 'bar1 {"foo": "bar2"}'
        # render .put(..) with quiet function
        template = """
        #set($v1 = {})\n$v1.put('foo', 'bar1')$util.qr($v1.put('foo', 'bar2'))\n#return($v1)
        """
        result = render_velocity_template(template, {})
        result = re.sub(r"\s+", " ", result).strip()
        assert result == '{"foo": "bar2"}'

    def test_quiet_return_put(self):
        template = "#set($v1 = {})\n$util.qr($v1.put('value', 'hi2'))\n#return($v1)"
        result = render_velocity_template(template, {})
        assert json.loads(result) == {"value": "hi2"}
        template = "#set($v1 = {})\n$util.qr($v1.put('value', 'hi2'))\n"
        result = render_velocity_template(template, {})
        assert result.strip() == ""

    def test_map_put_all(self):
        template = """
        #set($v1 = {})
        $v1.putAll({'foo1': 'bar', 'foo2': 'bar'})
        result: $v1
        """
        result = render_velocity_template(template, {})
        result = re.sub(r"\s+", " ", result).strip()
        assert result == "result: {'foo1': 'bar', 'foo2': 'bar'}"

    def test_assign_var_loop_return(self):
        template = """
        #foreach($x in [1, 2, 3])
            #if($x == 1 or $x == 3)
                #set($context.return__val = "loop$x")
                #set($context.return__flag = true)
                #return($context.return__val)
            #end
        #end
        #return('end')
        """
        result = render_velocity_template(template, {"context": dict()})
        result = re.sub(r"\s+", " ", result).strip()
        assert result == "loop1 loop3 end"


class TestMessageTransformationApiGateway:
    def test_construct_json_using_define(self):
        template = APIGW_TEMPLATE_CONSTRUCT_JSON
        variables = {"input": {"body": {"p1": {"test": 123}, "p2": {"foo": "bar", "foo2": False}}}}
        result = ApiGatewayVtlTemplate().render_vtl(template, variables)
        result = re.sub(r"\s+", " ", result).strip()
        result = json.loads(result)
        assert result == {"p0": True, "p1": {"test": "123"}, "p2": {"foo": "bar", "foo2": "false"}}

    def test_array_size(self):
        template = "#set($list = $input.path('$.records')) $list.size()"
        body = {"records": [{"data": {"foo": "bar1"}}, {"data": {"foo": "bar2"}}]}
        variables = {
            "input": {
                "body": body,
            },
        }

        result = ApiGatewayVtlTemplate().render_vtl(template, variables)
        assert result == " 2"

    def test_message_transformation(self):
        template = APIGW_TEMPLATE_TRANSFORM_KINESIS
        records = [
            {"data": {"foo": "foo1", "bar": "bar2"}},
            {"data": {"foo": "foo1", "bar": "bar2"}, "partitionKey": "key123"},
        ]
        variables = {"input": {"body": {"records": records}}}

        def do_test(_vars):
            res = ApiGatewayVtlTemplate().render_vtl(template, _vars, as_json=True)
            data_encoded = res["Records"][0]["Data"]
            assert res["Records"][0]["PartitionKey"] == data_encoded
            assert res["Records"][1]["PartitionKey"] == "key123"

        # try rendering the template
        do_test(variables)

        # test with empty array
        records = []
        variables = {"input": {"body": {"records": records}}}
        # try rendering the template
        result = ApiGatewayVtlTemplate().render_vtl(template, variables, as_json=True)
        assert result["Records"] == []

    def test_array_in_set_expr(self):
        template = "#set ($bar = $input.path('$.foo')[1]) \n $bar"
        variables = {"input": {"body": {"foo": ["e1", "e2", "e3", "e4"]}}}
        result = ApiGatewayVtlTemplate().render_vtl(template, variables).strip()
        assert result == "e2"

        template = "#set ($bar = $input.path('$.foo')[1][1][1]) $bar"
        variables = {"input": {"body": {"foo": [["e1"], ["e2", ["e3", "e4"]]]}}}
        result = ApiGatewayVtlTemplate().render_vtl(template, variables).strip()
        assert result == "e4"

    def test_string_methods(self):
        context = {"foo": {"bar": "BAZ baz"}}
        variables = {"input": {"body": context}}
        template1 = "${foo.bar.strip().lower().replace(' ','-')}"
        template2 = "${foo.bar.trim().toLowerCase().replace(' ','-')}"
        for template in [template1, template2]:
            result = ApiGatewayVtlTemplate().render_vtl(template, variables=variables)
            assert result == "baz-baz"

    def test_render_urlencoded_string_data(self):
        template = "MessageBody=$util.base64Encode($input.json('$'))"
        variables = {"input": {"body": {"spam": "eggs"}}}
        result = ApiGatewayVtlTemplate().render_vtl(template, variables)
        assert result == "MessageBody=eyJzcGFtIjogImVnZ3MifQ=="

    def test_keyset_functions(self):
        template = "#set($list = $input.path('$..var1[1]').keySet()) #foreach($e in $list)$e#end"
        body = {"var1": [{"a": 1}, {"b": 2}]}
        variables = {"input": {"body": body}}
        result = ApiGatewayVtlTemplate().render_vtl(template, variables)
        assert result == " b"

    def test_dash_in_variable_name(self):
        template = "#set($start = 1)#set($end = 5)#foreach($i in [$start .. $end])$i -#end"
        result = ApiGatewayVtlTemplate().render_vtl(template, {})
        assert result == "1 -2 -3 -4 -5 -"

        template = """
         $method.request.header.X-My-Header
        """
        variables = {"method": {"request": {"header": {"X-My-Header": "my-header-value"}}}}
        result = ApiGatewayVtlTemplate().render_vtl(template, variables).strip()
        assert result == "my-header-value"
