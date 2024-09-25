import pytest
from moto.apigateway.models import APIGatewayBackend, Stage, apigateway_backends
from moto.apigateway.models import RestAPI as MotoRestAPI
from werkzeug.datastructures import Headers

from localstack.http import Request, Response
from localstack.services.apigateway.models import RestApiContainer
from localstack.services.apigateway.next_gen.execute_api.api import RestApiGatewayHandlerChain
from localstack.services.apigateway.next_gen.execute_api.context import RestApiInvocationContext
from localstack.services.apigateway.next_gen.execute_api.gateway_response import (
    MissingAuthTokenError,
)
from localstack.services.apigateway.next_gen.execute_api.handlers.parse import (
    InvocationRequestParser,
)
from localstack.services.apigateway.next_gen.execute_api.handlers.resource_router import (
    InvocationRequestRouter,
)
from localstack.services.apigateway.next_gen.execute_api.helpers import (
    freeze_rest_api,
    parse_trace_id,
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
    moto_rest_api.stages[TEST_API_STAGE] = Stage(
        name=TEST_API_STAGE,
        variables={"foo": "bar"},
    )

    yield freeze_rest_api(
        account_id=TEST_AWS_ACCOUNT_ID,
        region=TEST_AWS_REGION_NAME,
        moto_rest_api=moto_rest_api,
        localstack_rest_api=RestApiContainer(rest_api={}),
    )

    moto_backend.reset()


@pytest.fixture
def get_invocation_context():
    def _create_context(request: Request) -> RestApiInvocationContext:
        context = RestApiInvocationContext(request)
        context.api_id = TEST_API_ID
        context.stage = TEST_API_STAGE
        context.account_id = TEST_AWS_ACCOUNT_ID
        context.region = TEST_AWS_REGION_NAME
        return context

    return _create_context


@pytest.fixture
def parse_handler_chain() -> RestApiGatewayHandlerChain:
    """Returns a dummy chain for testing."""
    return RestApiGatewayHandlerChain(request_handlers=[InvocationRequestParser()])


class TestParsingHandler:
    def test_parse_request(self, dummy_deployment, parse_handler_chain, get_invocation_context):
        host_header = f"{TEST_API_ID}.execute-api.host.com"
        headers = Headers(
            {
                "test-header": "value1",
                "test-header-multi": ["value2", "value3"],
                "host": host_header,
            }
        )
        body = b"random-body"
        request = Request(
            body=body,
            headers=headers,
            query_string="test-param=1&test-param-2=2&test-multi=val1&test-multi=val2",
            path=f"/{TEST_API_STAGE}/normal-path",
        )
        context = get_invocation_context(request)
        context.deployment = dummy_deployment

        parse_handler_chain.handle(context, Response())

        assert context.request == request
        assert context.account_id == TEST_AWS_ACCOUNT_ID
        assert context.region == TEST_AWS_REGION_NAME

        assert context.invocation_request["http_method"] == "GET"
        assert context.invocation_request["headers"] == Headers(
            {
                "host": host_header,
                "test-header": "value1",
                "test-header-multi": ["value2", "value3"],
            }
        )
        assert context.invocation_request["body"] == body
        assert (
            context.invocation_request["path"]
            == context.invocation_request["raw_path"]
            == "/normal-path"
        )

        assert context.context_variables["domainName"] == host_header
        assert context.context_variables["domainPrefix"] == TEST_API_ID
        assert context.context_variables["path"] == f"/{TEST_API_STAGE}/normal-path"

        assert "Root=" in context.trace_id

    def test_parse_raw_path(self, dummy_deployment, parse_handler_chain, get_invocation_context):
        request = Request(
            "GET",
            path=f"/{TEST_API_STAGE}/foo/bar/ed",
            raw_path=f"/{TEST_API_STAGE}//foo%2Fbar/ed",
        )

        context = get_invocation_context(request)
        context.deployment = dummy_deployment

        parse_handler_chain.handle(context, Response())

        # depending on the usage, we need the forward slashes or not
        # for example, for routing, we need the singular forward slash
        # but for passing the path to a lambda proxy event for example, we need the raw path as it was in the environ
        assert context.invocation_request["path"] == "/foo%2Fbar/ed"
        assert context.invocation_request["raw_path"] == "//foo%2Fbar/ed"

    def test_parse_user_request_path(
        self, dummy_deployment, parse_handler_chain, get_invocation_context
    ):
        # simulate a path request
        request = Request(
            "GET",
            path=f"/restapis/{TEST_API_ID}/{TEST_API_STAGE}/_user_request_/foo/bar/ed",
            raw_path=f"/restapis/{TEST_API_ID}/{TEST_API_STAGE}/_user_request_//foo%2Fbar/ed",
        )

        context = get_invocation_context(request)
        context.deployment = dummy_deployment

        parse_handler_chain.handle(context, Response())

        # assert that the user request prefix has been stripped off
        assert context.invocation_request["path"] == "/foo%2Fbar/ed"
        assert context.invocation_request["raw_path"] == "//foo%2Fbar/ed"

    def test_parse_localstack_only_path(
        self, dummy_deployment, parse_handler_chain, get_invocation_context
    ):
        # simulate a path request
        request = Request(
            "GET",
            path=f"/_aws/execute-api/{TEST_API_ID}/{TEST_API_STAGE}/foo/bar/ed",
            raw_path=f"/_aws/execute-api/{TEST_API_ID}/{TEST_API_STAGE}//foo%2Fbar/ed",
        )

        context = get_invocation_context(request)
        context.deployment = dummy_deployment

        parse_handler_chain.handle(context, Response())

        # assert that the user request prefix has been stripped off
        assert context.invocation_request["path"] == "/foo%2Fbar/ed"
        assert context.invocation_request["raw_path"] == "//foo%2Fbar/ed"

    @pytest.mark.parametrize("addressing", ["host", "user_request", "path_style"])
    def test_parse_path_same_as_stage(
        self, dummy_deployment, parse_handler_chain, get_invocation_context, addressing
    ):
        path = TEST_API_STAGE
        if addressing == "host":
            full_path = f"/{TEST_API_STAGE}/{path}"
        elif addressing == "path_style":
            full_path = f"/_aws/execute-api/{TEST_API_ID}/{TEST_API_STAGE}/{path}"
        else:
            full_path = f"/restapis/{TEST_API_ID}/{TEST_API_STAGE}/_user_request_/{path}"

        # simulate a path request
        request = Request("GET", path=full_path)

        context = get_invocation_context(request)
        context.deployment = dummy_deployment

        parse_handler_chain.handle(context, Response())

        # assert that the user request prefix has been stripped off
        assert context.invocation_request["path"] == f"/{TEST_API_STAGE}"
        assert context.invocation_request["raw_path"] == f"/{TEST_API_STAGE}"

    @pytest.mark.parametrize("addressing", ["user_request", "path_style"])
    def test_cased_api_id_in_path(
        self, dummy_deployment, parse_handler_chain, get_invocation_context, addressing
    ):
        if addressing == "path_style":
            full_path = f"/_aws/execute-api/TestApi/{TEST_API_STAGE}/test"
        else:
            full_path = f"/restapis/{TEST_API_ID}/TestApi/_user_request_/test"

        # simulate a path request
        request = Request("GET", path=full_path)

        context = get_invocation_context(request)
        context.deployment = dummy_deployment

        parse_handler_chain.handle(context, Response())

        # assert that the user request prefix has been stripped off
        assert context.invocation_request["path"] == "/test"
        assert context.invocation_request["raw_path"] == "/test"

    def test_trace_id_logic(self):
        headers = Headers({"x-amzn-trace-id": "Root=trace;Parent=parent"})
        trace = InvocationRequestParser.populate_trace_id(headers)
        assert trace == "Root=trace;Parent=parent;Sampled=1"

        no_trace_headers = Headers()
        trace = InvocationRequestParser.populate_trace_id(no_trace_headers)
        parsed_trace = parse_trace_id(trace)
        assert len(parsed_trace["Root"]) == 35
        assert len(parsed_trace["Parent"]) == 16
        assert parsed_trace["Sampled"] == "0"

        no_parent_headers = Headers({"x-amzn-trace-id": "Root=trace"})
        trace = InvocationRequestParser.populate_trace_id(no_parent_headers)
        parsed_trace = parse_trace_id(trace)
        assert parsed_trace["Root"] == "trace"
        assert len(parsed_trace["Parent"]) == 16
        assert parsed_trace["Sampled"] == "0"


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
        moto_backend: APIGatewayBackend = apigateway_backends[TEST_AWS_ACCOUNT_ID][
            TEST_AWS_REGION_NAME
        ]
        moto_rest_api = moto_backend.apis[TEST_API_ID]

        # path: /
        root_resource = moto_rest_api.default
        # path: /foo
        hard_coded_resource = moto_rest_api.add_child(path="foo", parent_id=root_resource.id)
        # path: /foo/{param}
        param_resource = moto_rest_api.add_child(
            path="{param}",
            parent_id=hard_coded_resource.id,
        )
        # path: /proxy
        hard_coded_resource_2 = moto_rest_api.add_child(path="proxy", parent_id=root_resource.id)
        # path: /proxy/bar
        hard_coded_resource_3 = moto_rest_api.add_child(
            path="bar", parent_id=hard_coded_resource_2.id
        )
        # path: /proxy/bar/{param}
        param_resource_2 = moto_rest_api.add_child(
            path="{param}",
            parent_id=hard_coded_resource_3.id,
        )
        # path: /proxy/{proxy+}
        proxy_resource = moto_rest_api.add_child(
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

        return freeze_rest_api(
            account_id=dummy_deployment.account_id,
            region=dummy_deployment.region,
            moto_rest_api=moto_rest_api,
            localstack_rest_api=dummy_deployment.rest_api,
        )

    @pytest.fixture
    def deployment_with_any_routes(self, dummy_deployment):
        """
        This can be represented by the following routes:
        - (No method) - /
        - GET         - /foo
        - ANY         - /foo
        - PUT         - /foo/{param}
        - ANY         - /foo/{param}
        """
        moto_backend: APIGatewayBackend = apigateway_backends[TEST_AWS_ACCOUNT_ID][
            TEST_AWS_REGION_NAME
        ]
        moto_rest_api = moto_backend.apis[TEST_API_ID]

        # path: /
        root_resource = moto_rest_api.default
        # path: /foo
        hard_coded_resource = moto_rest_api.add_child(path="foo", parent_id=root_resource.id)
        # path: /foo/{param}
        param_resource = moto_rest_api.add_child(
            path="{param}",
            parent_id=hard_coded_resource.id,
        )

        hard_coded_resource.add_method(
            method_type="GET",
            authorization_type="NONE",
            api_key_required=False,
        )
        hard_coded_resource.add_method(
            method_type="ANY",
            authorization_type="NONE",
            api_key_required=False,
        )
        # we test different order of setting the Method, to make sure ANY is always matched last
        # because this will influence the original order of the Werkzeug Rules in the Map
        # Because we only return the `Resource` as the endpoint, we always fetch manually the right
        # `resourceMethod` from the request method.
        param_resource.add_method(
            method_type="ANY",
            authorization_type="NONE",
            api_key_required=False,
        )
        param_resource.add_method(
            method_type="PUT",
            authorization_type="NONE",
            api_key_required=False,
        )

        return freeze_rest_api(
            account_id=dummy_deployment.account_id,
            region=dummy_deployment.region,
            moto_rest_api=moto_rest_api,
            localstack_rest_api=dummy_deployment.rest_api,
        )

    @staticmethod
    def get_path_from_addressing(path: str, addressing: str) -> str:
        if addressing == "host":
            return f"/{TEST_API_STAGE}{path}"
        elif addressing == "user_request":
            return f"/restapis/{TEST_API_ID}/{TEST_API_STAGE}/_user_request_/{path}"
        else:
            # this new style allows following the regular order in an easier way, stage is always before path
            return f"/_aws/execute-api/{TEST_API_ID}/{TEST_API_STAGE}{path}"

    @pytest.mark.parametrize("addressing", ["host", "user_request", "path_style"])
    def test_route_request_no_param(
        self, deployment_with_routes, parse_handler_chain, get_invocation_context, addressing
    ):
        request = Request(
            "GET",
            path=self.get_path_from_addressing("/foo", addressing),
        )

        context = get_invocation_context(request)
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
        assert context.stage_variables == {"foo": "bar"}

    @pytest.mark.parametrize("addressing", ["host", "user_request", "path_style"])
    def test_route_request_with_path_parameter(
        self, deployment_with_routes, parse_handler_chain, get_invocation_context, addressing
    ):
        request = Request(
            "PUT",
            path=self.get_path_from_addressing("/foo/random-value", addressing),
        )

        context = get_invocation_context(request)
        context.deployment = deployment_with_routes

        parse_handler_chain.handle(context, Response())
        handler = InvocationRequestRouter()
        handler(parse_handler_chain, context, Response())

        assert context.resource["pathPart"] == "{param}"
        assert context.resource["path"] == "/foo/{param}"
        # TODO: maybe assert more regarding the data inside Resource Methods, but we don't use it yet
        assert context.resource_method == context.resource["resourceMethods"]["PUT"]

        assert context.invocation_request["path_parameters"] == {"param": "random-value"}
        assert context.context_variables["resourcePath"] == "/foo/{param}"
        assert context.context_variables["resourceId"] == context.resource["id"]

    @pytest.mark.parametrize("addressing", ["host", "user_request", "path_style"])
    def test_route_request_with_greedy_parameter(
        self, deployment_with_routes, parse_handler_chain, get_invocation_context, addressing
    ):
        # assert that a path which does not contain `/proxy/bar` will be routed to {proxy+}
        request = Request(
            "DELETE",
            path=self.get_path_from_addressing("/proxy/this/is/a/proxy/req2%Fuest", addressing),
        )
        router_handler = InvocationRequestRouter()

        context = get_invocation_context(request)
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
        context = get_invocation_context(request)
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
        context = get_invocation_context(request)
        context.deployment = deployment_with_routes

        parse_handler_chain.handle(context, Response())
        router_handler(parse_handler_chain, context, Response())

        assert context.resource["path"] == "/proxy/{proxy+}"
        assert context.invocation_request["path_parameters"] == {
            "proxy": "test2/is/a/proxy/req2%Fuest"
        }

    @pytest.mark.parametrize("addressing", ["host", "user_request", "path_style"])
    def test_route_request_no_match_on_path(
        self, deployment_with_routes, parse_handler_chain, get_invocation_context, addressing
    ):
        request = Request(
            "GET",
            path=self.get_path_from_addressing("/wrong-test", addressing),
        )

        context = get_invocation_context(request)
        context.deployment = deployment_with_routes

        parse_handler_chain.handle(context, Response())
        # manually invoking the handler here as exceptions would be swallowed by the chain
        handler = InvocationRequestRouter()
        with pytest.raises(MissingAuthTokenError):
            handler(parse_handler_chain, context, Response())

    @pytest.mark.parametrize("addressing", ["host", "user_request", "path_style"])
    def test_route_request_no_match_on_method(
        self, deployment_with_routes, parse_handler_chain, get_invocation_context, addressing
    ):
        request = Request(
            "POST",
            path=self.get_path_from_addressing("/test", addressing),
        )

        context = get_invocation_context(request)
        context.deployment = deployment_with_routes

        parse_handler_chain.handle(context, Response())
        # manually invoking the handler here as exceptions would be swallowed by the chain
        handler = InvocationRequestRouter()
        with pytest.raises(MissingAuthTokenError):
            handler(parse_handler_chain, context, Response())

    @pytest.mark.parametrize("addressing", ["host", "user_request", "path_style"])
    def test_route_request_with_double_slash_and_trailing_and_encoded(
        self, deployment_with_routes, parse_handler_chain, get_invocation_context, addressing
    ):
        request = Request(
            "PUT",
            path=self.get_path_from_addressing("/foo/foo%2Fbar/", addressing),
            raw_path=self.get_path_from_addressing("//foo/foo%2Fbar/", addressing),
        )

        context = get_invocation_context(request)
        context.deployment = deployment_with_routes

        parse_handler_chain.handle(context, Response())
        handler = InvocationRequestRouter()
        handler(parse_handler_chain, context, Response())

        assert context.resource["path"] == "/foo/{param}"
        assert context.invocation_request["path_parameters"] == {"param": "foo%2Fbar"}

    @pytest.mark.parametrize("addressing", ["host", "user_request", "path_style"])
    def test_route_request_any_is_last(
        self, deployment_with_any_routes, parse_handler_chain, get_invocation_context, addressing
    ):
        handler = InvocationRequestRouter()

        def handle(_request: Request) -> RestApiInvocationContext:
            _context = get_invocation_context(_request)
            _context.deployment = deployment_with_any_routes
            parse_handler_chain.handle(_context, Response())
            handler(parse_handler_chain, _context, Response())
            return _context

        request = Request(
            "GET",
            path=self.get_path_from_addressing("/foo", addressing),
        )
        context = handle(request)

        assert context.resource["path"] == "/foo"
        assert context.resource["resourceMethods"]["GET"]

        request = Request(
            "DELETE",
            path=self.get_path_from_addressing("/foo", addressing),
        )
        context = handle(request)

        assert context.resource["path"] == "/foo"
        assert context.resource["resourceMethods"]["ANY"]

        request = Request(
            "PUT",
            path=self.get_path_from_addressing("/foo/random-value", addressing),
        )

        context = handle(request)

        assert context.resource["path"] == "/foo/{param}"
        assert context.resource_method == context.resource["resourceMethods"]["PUT"]

        request = Request(
            "GET",
            path=self.get_path_from_addressing("/foo/random-value", addressing),
        )

        context = handle(request)

        assert context.resource["path"] == "/foo/{param}"
        assert context.resource_method == context.resource["resourceMethods"]["ANY"]
