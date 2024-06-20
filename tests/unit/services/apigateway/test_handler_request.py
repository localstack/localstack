import pytest
from moto.apigateway.models import APIGatewayBackend, apigateway_backends
from werkzeug.datastructures import Headers

from localstack.http import Request, Response
from localstack.services.apigateway.models import MotoRestAPI, RestApiContainer, RestApiDeployment
from localstack.services.apigateway.next_gen.execute_api.api import RestApiGatewayHandlerChain
from localstack.services.apigateway.next_gen.execute_api.context import RestApiInvocationContext
from localstack.services.apigateway.next_gen.execute_api.handlers.parse import (
    InvocationRequestParser,
)
from localstack.services.apigateway.next_gen.execute_api.handlers.resource_router import (
    InvocationRequestRouter,
)
from localstack.testing.config import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME

TEST_API_ID = "testapi"
TEST_API_STAGE = "dev"


@pytest.fixture
def dummy_deployment():
    # because we depend on Moto here, we have to use the backend because the `MotoRestAPI` uses the backend internally
    # if we only create the RestAPI outside the store, it will fail

    moto_backend: APIGatewayBackend = apigateway_backends[TEST_AWS_ACCOUNT_ID][TEST_AWS_REGION_NAME]
    moto_rest_api = MotoRestAPI(
        account_id=TEST_AWS_ACCOUNT_ID,
        region_name=TEST_AWS_REGION_NAME,
        api_id=TEST_API_ID,
        name="test API",
        description="",
    )

    moto_backend.apis[TEST_API_ID] = moto_rest_api

    yield RestApiDeployment(
        account_id=TEST_AWS_ACCOUNT_ID,
        region=TEST_AWS_REGION_NAME,
        localstack_rest_api=RestApiContainer(rest_api={}),
        moto_rest_api=moto_rest_api,
    )

    moto_backend.reset()


@pytest.fixture
def parse_handler_chain() -> RestApiGatewayHandlerChain:
    """Returns a dummy chain for testing."""
    return RestApiGatewayHandlerChain(request_handlers=[InvocationRequestParser()])


class TestParsingHandler:
    def test_parse_request(self, dummy_deployment, parse_handler_chain):
        headers = Headers({"test-header": "value1", "test-header-multi": ["value2", "value3"]})
        body = b"random-body"
        request = Request(
            body=body,
            headers=headers,
            query_string="test-param=1&test-param-2=2&test-multi=val1&test-multi=val2",
            path="/normal-path",
        )
        context = RestApiInvocationContext(request)
        context.deployment = dummy_deployment

        parse_handler_chain.handle(context, Response())

        assert context.request == request
        assert context.account_id == TEST_AWS_ACCOUNT_ID
        assert context.region == TEST_AWS_REGION_NAME

        assert context.invocation_request["http_method"] == "GET"
        assert context.invocation_request["raw_headers"] == Headers(
            {
                "test-header": "value1",
                "test-header-multi": ["value2", "value3"],
                "content-length": len(body),
            }
        )
        assert context.invocation_request["headers"] == {
            "test-header": "value1",
            "test-header-multi": "value2",
            "content-length": "11",
        }
        assert context.invocation_request["multi_value_headers"] == {
            "test-header": ["value1"],
            "test-header-multi": ["value2", "value3"],
            "content-length": ["11"],
        }
        assert context.invocation_request["body"] == body
        assert (
            context.invocation_request["path"]
            == context.invocation_request["raw_path"]
            == "/normal-path"
        )

    def test_parse_raw_path(self, dummy_deployment, parse_handler_chain):
        request = Request("GET", "/foo/bar/ed", raw_path="//foo%2Fbar/ed")

        context = RestApiInvocationContext(request)
        context.deployment = dummy_deployment

        parse_handler_chain.handle(context, Response())

        # depending on the usage, we need the forward slashes or not
        # for example, for routing, we need the singular forward slash
        # but for passing the path to a lambda proxy event for example, we need the raw path as it was in the environ
        assert context.invocation_request["path"] == "/foo%2Fbar/ed"
        assert context.invocation_request["raw_path"] == "//foo%2Fbar/ed"

    def test_parse_user_request_path(self, dummy_deployment, parse_handler_chain):
        # simulate a path request
        request = Request(
            "GET",
            path=f"/restapis/{TEST_API_ID}/_user_request_/foo/bar/ed",
            raw_path=f"/restapis/{TEST_API_ID}/_user_request_//foo%2Fbar/ed",
        )

        context = RestApiInvocationContext(request)
        context.deployment = dummy_deployment

        parse_handler_chain.handle(context, Response())

        # assert that the user request prefix has been stripped off
        assert context.invocation_request["path"] == "/foo%2Fbar/ed"
        assert context.invocation_request["raw_path"] == "//foo%2Fbar/ed"


class TestRoutingHandler:
    @pytest.fixture
    def deployment_with_routes(self, dummy_deployment):
        """
        This can be represented by the following routes:
        - (No method) - /
        - GET         - /foo
        - PUT         - /foo/{param}
        - (No method) - /proxy
        - DELETE      - /proxy/{proxy+}
        - (No method) - /proxy/bar
        - DELETE      - /proxy/bar/{param}

        Note: we have the base `/proxy` route to not have greedy matching on the base route, and the other child routes
        are to assert the `{proxy+} has less priority than hardcoded routes
        """
        # path: /
        root_resource = dummy_deployment.moto_rest_api.default
        # path: /foo
        hard_coded_resource = dummy_deployment.moto_rest_api.add_child(
            path="foo", parent_id=root_resource.id
        )
        # path: /foo/{param}
        param_resource = dummy_deployment.moto_rest_api.add_child(
            path="{param}",
            parent_id=hard_coded_resource.id,
        )
        # path: /proxy
        hard_coded_resource_2 = dummy_deployment.moto_rest_api.add_child(
            path="proxy", parent_id=root_resource.id
        )
        # path: /proxy/bar
        hard_coded_resource_3 = dummy_deployment.moto_rest_api.add_child(
            path="bar", parent_id=hard_coded_resource_2.id
        )
        # path: /proxy/bar/{param}
        param_resource_2 = dummy_deployment.moto_rest_api.add_child(
            path="{param}",
            parent_id=hard_coded_resource_3.id,
        )
        # path: /proxy/{proxy+}
        proxy_resource = dummy_deployment.moto_rest_api.add_child(
            path="{proxy+}",
            parent_id=hard_coded_resource_2.id,
        )
        hard_coded_resource.add_method(
            method_type="GET",
            authorization_type="NONE",
            api_key_required=False,
        )
        param_resource.add_method(
            method_type="PUT",
            authorization_type="NONE",
            api_key_required=False,
        )
        proxy_resource.add_method(
            method_type="DELETE",
            authorization_type="NONE",
            api_key_required=False,
        )
        param_resource_2.add_method(
            method_type="DELETE",
            authorization_type="NONE",
            api_key_required=False,
        )

        return dummy_deployment

    @staticmethod
    def get_path_from_addressing(path: str, addressing: str) -> str:
        if addressing == "host":
            return path
        else:
            return f"/restapis/{TEST_API_ID}/_user_request_{path}"

    @pytest.mark.parametrize("addressing", ["host", "user_request"])
    def test_route_request_no_param(self, deployment_with_routes, parse_handler_chain, addressing):
        request = Request(
            "GET",
            path=self.get_path_from_addressing("/foo", addressing),
        )

        context = RestApiInvocationContext(request)
        context.deployment = deployment_with_routes

        parse_handler_chain.handle(context, Response())
        handler = InvocationRequestRouter()
        handler(parse_handler_chain, context, Response())

        assert context.resource["pathPart"] == "foo"
        assert context.resource["path"] == "/foo"
        assert context.resource["resourceMethods"]["GET"]
        # TODO: maybe assert more regarding the data inside Resource Methods, but we don't use it yet

        assert context.resource_method == context.resource["resourceMethods"]["GET"]
        assert context.invocation_request["path_parameters"] == {}

    @pytest.mark.parametrize("addressing", ["host", "user_request"])
    def test_route_request_with_path_parameter(
        self, deployment_with_routes, parse_handler_chain, addressing
    ):
        request = Request(
            "PUT",
            path=self.get_path_from_addressing("/foo/random-value", addressing),
        )

        context = RestApiInvocationContext(request)
        context.deployment = deployment_with_routes

        parse_handler_chain.handle(context, Response())
        handler = InvocationRequestRouter()
        handler(parse_handler_chain, context, Response())

        assert context.resource["pathPart"] == "{param}"
        assert context.resource["path"] == "/foo/{param}"
        # TODO: maybe assert more regarding the data inside Resource Methods, but we don't use it yet
        assert context.resource_method == context.resource["resourceMethods"]["PUT"]

        assert context.invocation_request["path_parameters"] == {"param": "random-value"}

    @pytest.mark.parametrize("addressing", ["host", "user_request"])
    def test_route_request_with_greedy_parameter(
        self, deployment_with_routes, parse_handler_chain, addressing
    ):
        # assert that a path which does not contain `/proxy/bar` will be routed to {proxy+}
        request = Request(
            "DELETE",
            path=self.get_path_from_addressing("/proxy/this/is/a/proxy/req2%Fuest", addressing),
        )
        router_handler = InvocationRequestRouter()

        context = RestApiInvocationContext(request)
        context.deployment = deployment_with_routes

        parse_handler_chain.handle(context, Response())
        router_handler(parse_handler_chain, context, Response())

        assert context.resource["pathPart"] == "{proxy+}"
        assert context.resource["path"] == "/proxy/{proxy+}"
        # TODO: maybe assert more regarding the data inside Resource Methods, but we don't use it yet
        assert context.resource_method == context.resource["resourceMethods"]["DELETE"]

        assert context.invocation_request["path_parameters"] == {
            "proxy": "this/is/a/proxy/req2%Fuest"
        }

        # assert that a path which does contain `/proxy/bar` will be routed to `/proxy/bar/{param}` if it has only
        # one resource after `bar`
        request = Request(
            "DELETE",
            path=self.get_path_from_addressing("/proxy/bar/foobar", addressing),
        )
        context = RestApiInvocationContext(request)
        context.deployment = deployment_with_routes

        parse_handler_chain.handle(context, Response())
        router_handler(parse_handler_chain, context, Response())

        assert context.resource["path"] == "/proxy/bar/{param}"
        assert context.invocation_request["path_parameters"] == {"param": "foobar"}

        # assert that a path which does contain `/proxy/bar` will be routed to {proxy+} if it does not conform to
        # `/proxy/bar/{param}`
        # TODO: validate this with AWS
        request = Request(
            "DELETE",
            path=self.get_path_from_addressing("/proxy/test2/is/a/proxy/req2%Fuest", addressing),
        )
        context = RestApiInvocationContext(request)
        context.deployment = deployment_with_routes

        parse_handler_chain.handle(context, Response())
        router_handler(parse_handler_chain, context, Response())

        assert context.resource["path"] == "/proxy/{proxy+}"
        assert context.invocation_request["path_parameters"] == {
            "proxy": "test2/is/a/proxy/req2%Fuest"
        }

    @pytest.mark.parametrize("addressing", ["host", "user_request"])
    def test_route_request_no_match_on_path(
        self, deployment_with_routes, parse_handler_chain, addressing
    ):
        request = Request(
            "GET",
            path=self.get_path_from_addressing("/wrong-test", addressing),
        )

        context = RestApiInvocationContext(request)
        context.deployment = deployment_with_routes

        parse_handler_chain.handle(context, Response())
        # manually invoking the handler here as exceptions would be swallowed by the chain
        handler = InvocationRequestRouter()
        with pytest.raises(Exception, match="Not found"):
            handler(parse_handler_chain, context, Response())

    @pytest.mark.parametrize("addressing", ["host", "user_request"])
    def test_route_request_no_match_on_method(
        self, deployment_with_routes, parse_handler_chain, addressing
    ):
        request = Request(
            "POST",
            path=self.get_path_from_addressing("/test", addressing),
        )

        context = RestApiInvocationContext(request)
        context.deployment = deployment_with_routes

        parse_handler_chain.handle(context, Response())
        # manually invoking the handler here as exceptions would be swallowed by the chain
        handler = InvocationRequestRouter()
        with pytest.raises(Exception, match="Not found"):
            handler(parse_handler_chain, context, Response())

    @pytest.mark.parametrize("addressing", ["host", "user_request"])
    def test_route_request_with_double_slash_and_trailing_and_encoded(
        self, deployment_with_routes, parse_handler_chain, addressing
    ):
        request = Request(
            "PUT",
            path=self.get_path_from_addressing("/foo/foo%2Fbar/", addressing),
            raw_path=self.get_path_from_addressing("//foo/foo%2Fbar/", addressing),
        )

        context = RestApiInvocationContext(request)
        context.deployment = deployment_with_routes

        parse_handler_chain.handle(context, Response())
        handler = InvocationRequestRouter()
        handler(parse_handler_chain, context, Response())

        assert context.resource["path"] == "/foo/{param}"
        assert context.invocation_request["path_parameters"] == {"param": "foo%2Fbar"}
