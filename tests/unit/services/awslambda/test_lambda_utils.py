from localstack.services.awslambda.lambda_utils import (
    LAMBDA_RUNTIME_DOTNETCORE31,
    LAMBDA_RUNTIME_GOLANG,
    LAMBDA_RUNTIME_NODEJS,
    LAMBDA_RUNTIME_PROVIDED,
    LAMBDA_RUNTIME_RUBY,
    format_name_to_path,
    get_handler_file_from_name,
)


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
            ".build/handler.execute", LAMBDA_RUNTIME_NODEJS
        )
        assert "./.build/handler.execute" == get_handler_file_from_name(
            "./.build/handler.execute", LAMBDA_RUNTIME_GOLANG
        )
        assert "CSharpHandlers.dll" == get_handler_file_from_name(
            "./CSharpHandlers::AwsDotnetCsharp.Handler::CreateProfileAsync",
            LAMBDA_RUNTIME_DOTNETCORE31,
        )
        assert "test/handler.rb" == get_handler_file_from_name(
            "test.handler.execute", LAMBDA_RUNTIME_RUBY
        )
        assert "test.handler.execute" == get_handler_file_from_name(
            "test.handler.execute", LAMBDA_RUNTIME_GOLANG
        )
        assert "main" == get_handler_file_from_name("main", LAMBDA_RUNTIME_GOLANG)
        assert "../handler.py" == get_handler_file_from_name("../handler.execute")
        assert "bootstrap" == get_handler_file_from_name("", LAMBDA_RUNTIME_PROVIDED)
