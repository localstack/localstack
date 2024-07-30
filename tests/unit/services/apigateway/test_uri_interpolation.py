import pytest

from localstack.services.apigateway.next_gen.execute_api.helpers import (
    render_uri_with_path_parameters,
    render_uri_with_stage_variables,
)


class TestUriInterpolationStageVariables:
    @pytest.mark.parametrize(
        "uri,expected",
        [
            (
                # A full URI without protocol
                "https://${stageVariables.stageDomain}",
                "https://example.com",
            ),
            (
                # A full domain
                "https://${stageVariables.stageDomain}/resource/operation",
                "https://example.com/resource/operation",
            ),
            (
                # A subdomain
                "https://${stageVariables.stageVar}.example.com/resource/operation",
                "https://stageValue.example.com/resource/operation",
            ),
            (
                # A path
                "https://example.com/${stageVariables.stageVar}/bar",
                "https://example.com/stageValue/bar",
            ),
            (
                # A query string
                "https://example.com/foo?q=${stageVariables.stageVar}",
                "https://example.com/foo?q=stageValue",
            ),
            (
                # AWS URI action or path components
                "arn:aws:apigateway:<region>:<service>:${stageVariables.stageVar}",
                "arn:aws:apigateway:<region>:<service>:stageValue",
            ),
            (
                # AWS integration Lambda function name
                "arn:aws:apigateway:<region>:lambda:path/2015-03-31/functions/arn:aws:lambda:<region>:<account_id>:function:${stageVariables.stageVar}/invocations",
                "arn:aws:apigateway:<region>:lambda:path/2015-03-31/functions/arn:aws:lambda:<region>:<account_id>:function:stageValue/invocations",
            ),
            (
                # AWS integration Lambda function version/alias
                "arn:aws:apigateway:<region>:lambda:path/2015-03-31/functions/arn:aws:lambda:<region>:<account_id>:function:<function_name>:${stageVariables.stageVar}/invocations",
                "arn:aws:apigateway:<region>:lambda:path/2015-03-31/functions/arn:aws:lambda:<region>:<account_id>:function:<function_name>:stageValue/invocations",
            ),
            (
                # Amazon Cognito user pool for a COGNITO_USER_POOLS authorizer.
                "arn:aws:cognito-idp:<region>:<account_id>:userpool/${stageVariables.stageVar}",
                "arn:aws:cognito-idp:<region>:<account_id>:userpool/stageValue",
            ),
            (
                # AWS user/role integration credentials ARN
                "arn:aws:iam::<account_id>:${stageVariables.stageVar}",
                "arn:aws:iam::<account_id>:stageValue",
            ),
        ],
    )
    def test_uri_stage_variables_interpolation(self, uri, expected):
        # test values taken from the documentation
        # https://docs.aws.amazon.com/apigateway/latest/developerguide/aws-api-gateway-stage-variables-reference.html#stage-variables-in-integration-HTTP-uris
        stage_variables = {
            "stageVar": "stageValue",
            "stageDomain": "example.com",
            "moreVar": "var",
        }
        rendered = render_uri_with_stage_variables(uri=uri, stage_variables=stage_variables)
        assert rendered == expected

    def test_uri_interpolating_with_only_curly_braces(self):
        uri_with_only_braces = "https://test.domain.example/root/{path}"
        stage_variables = {"path": "value"}
        rendered = render_uri_with_stage_variables(
            uri=uri_with_only_braces, stage_variables=stage_variables
        )
        assert "{path}" in rendered

    def test_uri_interpolating_with_no_variable(self):
        uri = "https://test.domain.example/root/${stageVariables.path}"
        stage_variables = {}
        rendered = render_uri_with_stage_variables(uri=uri, stage_variables=stage_variables)
        assert rendered == "https://test.domain.example/root/"

    def test_uri_interpolation_with_no_stage_var_prefix(self):
        uri_with_no_prefix = "https://test.domain.example/root/${path}"
        stage_variables = {}
        rendered = render_uri_with_stage_variables(
            uri=uri_with_no_prefix, stage_variables=stage_variables
        )
        assert rendered == "https://test.domain.example/root/${path}"

    def test_uri_interpolating_with_bad_format(self):
        # tested against AWS in an integration URI
        uri_with_bad_format = r"https://test.domain.example/root/${path\}"
        stage_variables = {"path": "value"}
        rendered = render_uri_with_stage_variables(
            uri=uri_with_bad_format, stage_variables=stage_variables
        )
        assert rendered == uri_with_bad_format


class TestUriInterpolationPathParameters:
    def test_uri_render_path_param(self):
        uri_with_only_braces = "https://test.domain.example/root/{path}"
        path_parameters = {"path": "value"}
        rendered = render_uri_with_path_parameters(
            uri=uri_with_only_braces,
            path_parameters=path_parameters,
        )
        assert rendered == "https://test.domain.example/root/value"

    def test_uri_render_missing_path_param(self):
        uri_with_only_braces = "https://test.domain.example/root/{unknown}"
        path_parameters = {"path": "value"}
        rendered = render_uri_with_path_parameters(
            uri=uri_with_only_braces,
            path_parameters=path_parameters,
        )
        assert rendered == "https://test.domain.example/root/{unknown}"

    def test_uri_render_partial_missing_path_param(self):
        uri_with_only_braces = "https://test.domain.example/root/{unknown}/{path}"
        path_parameters = {"path": "value"}
        rendered = render_uri_with_path_parameters(
            uri=uri_with_only_braces,
            path_parameters=path_parameters,
        )
        assert rendered == "https://test.domain.example/root/{unknown}/value"
