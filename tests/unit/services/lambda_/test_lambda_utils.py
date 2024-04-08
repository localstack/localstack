import json

from localstack.aws.api.lambda_ import Runtime
from localstack.services.lambda_.event_source_listeners.utils import filter_stream_records
from localstack.services.lambda_.lambda_utils import format_name_to_path, get_handler_file_from_name


class TestLambdaUtils:
    def test_format_name_to_path(self):
        assert ".build/handler.js" == format_name_to_path(".build/handler.execute", ".", ".js")
        assert "handler" == format_name_to_path("handler.execute", ".", "")
        assert "CSharpHandlers.dll" == format_name_to_path(
            "./CSharpHandlers::AwsDotnetCsharp.Handler::CreateProfileAsync",
            ":",
            ".dll",
        )
        assert "test/handler.rb" == format_name_to_path("test.handler.execute", ".", ".rb")
        assert "test.handler.py" == format_name_to_path("./test.handler.execute", ".", ".py")
        assert "../handler.js" == format_name_to_path("../handler.execute", ".", ".js")

    def test_get_handler_file_from_name(self):
        assert ".build/handler.js" == get_handler_file_from_name(
            ".build/handler.execute", Runtime.nodejs16_x
        )
        assert "./.build/handler.execute" == get_handler_file_from_name(
            "./.build/handler.execute", Runtime.go1_x
        )
        assert "CSharpHandlers.dll" == get_handler_file_from_name(
            "./CSharpHandlers::AwsDotnetCsharp.Handler::CreateProfileAsync",
            Runtime.dotnetcore3_1,
        )
        assert "test/handler.rb" == get_handler_file_from_name(
            "test.handler.execute", Runtime.ruby3_2
        )
        assert "test.handler.execute" == get_handler_file_from_name(
            "test.handler.execute", Runtime.go1_x
        )
        assert "main" == get_handler_file_from_name("main", Runtime.go1_x)
        assert "../handler.py" == get_handler_file_from_name("../handler.execute")
        assert "bootstrap" == get_handler_file_from_name("", Runtime.provided)


class TestFilterStreamRecords:
    """
    https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html

    Test filtering logic for supported syntax
    """

    records = [
        {
            "partitionKey": "1",
            "sequenceNumber": "49590338271490256608559692538361571095921575989136588898",
            "data": {
                "City": "Seattle",
                "State": "WA",
                "Temperature": 46,
                "Month": "December",
                "Population": None,
                "Flag": "",
            },
            "approximateArrivalTimestamp": 1545084650.987,
            "encryptionType": "NONE",
        }
    ]

    def test_match_metadata(self):
        filters = [{"Filters": [{"Pattern": json.dumps({"partitionKey": ["1"]})}]}]
        assert self.records == filter_stream_records(self.records, filters)

    def test_match_data(self):
        filters = [{"Filters": [{"Pattern": json.dumps({"data": {"State": ["WA"]}})}]}]

        assert self.records == filter_stream_records(self.records, filters)

    def test_match_multiple(self):
        filters = [
            {
                "Filters": [
                    {"Pattern": json.dumps({"partitionKey": ["1"], "data": {"State": ["WA"]}})}
                ]
            }
        ]

        assert self.records == filter_stream_records(self.records, filters)

    def test_match_exists(self):
        filters = [{"Filters": [{"Pattern": json.dumps({"data": {"State": [{"exists": True}]}})}]}]
        assert self.records == filter_stream_records(self.records, filters)

    def test_match_numeric_equals(self):
        filters = [
            {
                "Filters": [
                    {"Pattern": json.dumps({"data": {"Temperature": [{"numeric": ["=", 46]}]}})}
                ]
            }
        ]
        assert self.records == filter_stream_records(self.records, filters)

    def test_match_numeric_range(self):
        filters = [
            {
                "Filters": [
                    {
                        "Pattern": json.dumps(
                            {"data": {"Temperature": [{"numeric": [">", 40, "<", 50]}]}}
                        )
                    }
                ]
            }
        ]
        assert self.records == filter_stream_records(self.records, filters)

    def test_match_prefix(self):
        filters = [{"Filters": [{"Pattern": json.dumps({"data": {"City": [{"prefix": "Sea"}]}})}]}]
        assert self.records == filter_stream_records(self.records, filters)

    def test_match_null(self):
        filters = [{"Filters": [{"Pattern": json.dumps({"data": {"Population": [None]}})}]}]
        assert self.records == filter_stream_records(self.records, filters)

    def test_match_empty(self):
        filters = [{"Filters": [{"Pattern": json.dumps({"data": {"Flag": [""]}})}]}]
        assert self.records == filter_stream_records(self.records, filters)

    def test_no_match_exists(self):
        filters = [{"Filters": [{"Pattern": json.dumps({"data": {"Foo": [{"exists": True}]}})}]}]
        assert [] == filter_stream_records(self.records, filters)

    def test_no_filters(self):
        filters = []
        assert [] == filter_stream_records(self.records, filters)

    def test_no_match_partial(self):
        filters = [
            {
                "Filters": [
                    {"Pattern": json.dumps({"partitionKey": ["2"], "data": {"City": ["Seattle"]}})}
                ]
            }
        ]

        assert [] == filter_stream_records(self.records, filters)

    def test_no_match_exists_dict(self):
        filters = [
            {"Filters": [{"Pattern": json.dumps({"data": {"Foo": {"S": [{"exists": True}]}}})}]}
        ]
        assert [] == filter_stream_records(self.records, filters)
