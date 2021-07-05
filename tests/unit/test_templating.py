import base64
import json
import unittest

from localstack.utils.aws.aws_stack import render_velocity_template
from localstack.utils.common import to_str

# template used to transform incoming requests at the API Gateway (forward to Kinesis)
APIGATEWAY_TRANSFORMATION_TEMPLATE = """{
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


class TestMessageTransformation(unittest.TestCase):
    def test_array_size(self):
        template = "#set($list = $input.path('$.records')) $list.size()"
        context = {"records": [{"data": {"foo": "bar1"}}, {"data": {"foo": "bar2"}}]}
        result = render_velocity_template(template, context)
        self.assertEqual(" 2", result)
        result = render_velocity_template(template, json.dumps(context))
        self.assertEqual(" 2", result)

    def test_message_transformation(self):
        template = APIGATEWAY_TRANSFORMATION_TEMPLATE
        records = [
            {"data": {"foo": "foo1", "bar": "bar2"}},
            {"data": {"foo": "foo1", "bar": "bar2"}, "partitionKey": "key123"},
        ]
        context = {"records": records}

        def do_test(context):
            result = render_velocity_template(template, context, as_json=True)
            result_decoded = json.loads(to_str(base64.b64decode(result["Records"][0]["Data"])))
            self.assertEqual(records[0]["data"], result_decoded)
            self.assertGreater(len(result["Records"][0]["PartitionKey"]), 0)
            self.assertEqual("key123", result["Records"][1]["PartitionKey"])

        # try rendering the template
        do_test(context)
        # try again with context as string
        do_test(json.dumps(context))

        # test with empty array
        records = []
        context = {"records": records}
        # try rendering the template
        result = render_velocity_template(template, context, as_json=True)
        self.assertEqual([], result["Records"])

    def test_array_in_set_expr(self):
        template = "#set ($bar = $input.path('$.foo')[1]) \n $bar"
        context = {"foo": ["e1", "e2", "e3", "e4"]}
        result = render_velocity_template(template, context).strip()
        self.assertEqual("e2", result)

        template = "#set ($bar = $input.path('$.foo')[1][1][1]) $bar"
        context = {"foo": [["e1"], ["e2", ["e3", "e4"]]]}
        result = render_velocity_template(template, context).strip()
        self.assertEqual("e4", result)

    def test_string_methods(self):
        context = {"foo": {"bar": "BAZ baz"}}
        template1 = "${foo.bar.strip().lower().replace(' ','-')}"
        template2 = "${foo.bar.trim().toLowerCase().replace(' ','-')}"
        for template in [template1, template2]:
            result = render_velocity_template(template, {}, variables=context)
            self.assertEqual("baz-baz", result)

    def test_render_urlencoded_string_data(self):
        template = "MessageBody=$util.base64Encode($input.json('$'))"
        result = render_velocity_template(template, b'{"spam": "eggs"}')
        self.assertEqual("MessageBody=eyJzcGFtIjogImVnZ3MifQ==", result)
