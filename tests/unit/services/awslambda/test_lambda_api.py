from localstack.services.awslambda.lambda_api import construct_invocation_event


class TestLambdaApi:
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
                    "multiValueQueryStringParameters": {"foo": ("bar",)},
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
                    "multiValueQueryStringParameters": {"foo": ("bar",)},
                },
            },
        ]

        for t in tt:
            result = construct_invocation_event(
                t["method"],
                t["path"],
                t["headers"],
                t["data"],
                t["query_string_params"],
                t["is_base64_encoded"],
            )
            assert result == t["expected"]
