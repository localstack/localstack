import base64
import json

from localstack.utils.aws.aws_stack import render_velocity_template
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
        #set( $v = $util.escapeJavaScript($map.get($key)).replaceAll("\\\\'", "'") )
        $k: $v
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


class TestMessageTransformation:
    def test_array_size(self):
        template = "#set($list = $input.path('$.records')) $list.size()"
        context = {"records": [{"data": {"foo": "bar1"}}, {"data": {"foo": "bar2"}}]}
        result = render_velocity_template(template, context)
        assert result == " 2"
        result = render_velocity_template(template, json.dumps(context))
        assert result == " 2"

    def test_message_transformation(self):
        template = APIGW_TEMPLATE_TRANSFORM_KINESIS
        records = [
            {"data": {"foo": "foo1", "bar": "bar2"}},
            {"data": {"foo": "foo1", "bar": "bar2"}, "partitionKey": "key123"},
        ]
        context = {"records": records}

        def do_test(context):
            result = render_velocity_template(template, context, as_json=True)
            result_decoded = json.loads(to_str(base64.b64decode(result["Records"][0]["Data"])))
            assert result_decoded == records[0]["data"]
            assert result["Records"][0]["PartitionKey"] == "$elem.partitionKey"
            assert result["Records"][1]["PartitionKey"] == "key123"

        # try rendering the template
        do_test(context)
        # try again with context as string
        do_test(json.dumps(context))

        # test with empty array
        records = []
        context = {"records": records}
        # try rendering the template
        result = render_velocity_template(template, context, as_json=True)
        assert result["Records"] == []

    def test_array_in_set_expr(self):
        template = "#set ($bar = $input.path('$.foo')[1]) \n $bar"
        context = {"foo": ["e1", "e2", "e3", "e4"]}
        result = render_velocity_template(template, context).strip()
        assert result == "e2"

        template = "#set ($bar = $input.path('$.foo')[1][1][1]) $bar"
        context = {"foo": [["e1"], ["e2", ["e3", "e4"]]]}
        result = render_velocity_template(template, context).strip()
        assert result == "e4"

    def test_string_methods(self):
        context = {"foo": {"bar": "BAZ baz"}}
        template1 = "${foo.bar.strip().lower().replace(' ','-')}"
        template2 = "${foo.bar.trim().toLowerCase().replace(' ','-')}"
        for template in [template1, template2]:
            result = render_velocity_template(template, {}, variables=context)
            assert result == "baz-baz"

    def test_render_urlencoded_string_data(self):
        template = "MessageBody=$util.base64Encode($input.json('$'))"
        result = render_velocity_template(template, b'{"spam": "eggs"}')
        assert result == "MessageBody=eyJzcGFtIjogImVnZ3MifQ=="

    def test_construct_json_using_define(self):
        template = APIGW_TEMPLATE_CONSTRUCT_JSON
        context = {"p1": {"test": 123}, "p2": {"foo": "bar", "foo2": False}}
        result = render_velocity_template(template, context).strip()
        result = json.loads(result)
        assert result == {"p0": True, **context}
