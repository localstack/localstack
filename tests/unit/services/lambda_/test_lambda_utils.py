from localstack.aws.api.lambda_ import Runtime
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
