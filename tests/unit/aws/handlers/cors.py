import pytest

from localstack.aws.api import RequestContext
from localstack.aws.chain import HandlerChain
from localstack.aws.handlers.cors import CorsEnforcer, CorsResponseEnricher, cors_aware
from localstack.http import Request, Response, route
from localstack.services.edge import ROUTER


@pytest.fixture()
def add_edge_route():
    rules = []

    def _add_edge_route(fn):
        rules.append(ROUTER.add_route_endpoint(fn))

    yield _add_edge_route

    for rule in rules:
        ROUTER.remove_rule(rule)


@cors_aware()
@route(path="/cors_aware_route_path")
def cors_aware_route():
    pass


@route(path="/non_cors_aware_route_path")
def non_cors_aware_route():
    pass


def test_cors_aware_edge_route_ignored(add_edge_route):
    add_edge_route(cors_aware_route)

    cors_enforcer = CorsEnforcer()
    cors_enricher = CorsResponseEnricher()
    chain = HandlerChain([cors_enforcer, cors_enricher])

    context = RequestContext()
    context.request = Request(
        method="GET",
        path="/cors_aware_route_path",
        headers={"origin": "https://unsafe-origin.evil"},
    )
    response = Response()
    chain.handle(context, response)

    # Make sure the request is _not_ handled by the CorsEnforcer or CorsEnricher
    assert response.status_code == 200
    assert "Access-Control-Allow-Methods" not in response.headers


def test_non_cors_aware_unsafe_edge_route_blocked(add_edge_route):
    add_edge_route(non_cors_aware_route)

    cors_enforcer = CorsEnforcer()
    cors_enricher = CorsResponseEnricher()
    chain = HandlerChain([cors_enforcer, cors_enricher])

    context = RequestContext()
    context.request = Request(
        method="GET",
        path="/non_cors_aware_route_path",
        headers={"origin": "https://unsafe-origin.evil"},
    )
    response = Response()
    chain.handle(context, response)
    # Make sure the request has been blocked by the CORS enforcer
    assert response.status_code == 403


def test_non_cors_aware_safe_edge_route_enriched(add_edge_route):
    add_edge_route(non_cors_aware_route)

    cors_enforcer = CorsEnforcer()
    cors_enricher = CorsResponseEnricher()
    chain = HandlerChain([cors_enforcer, cors_enricher])

    context = RequestContext()
    context.request = Request(method="GET", path="/non_cors_aware_route_path")
    response = Response()
    chain.handle(context, response)

    # Make sure the request has not been blocked and has been enriched by the CORS enforcer
    assert response.status_code == 200
    assert "Access-Control-Allow-Methods" in response.headers


def test_non_edge_route_enriched(add_edge_route):
    add_edge_route(non_cors_aware_route)

    cors_enforcer = CorsEnforcer()
    cors_enricher = CorsResponseEnricher()
    chain = HandlerChain([cors_enforcer, cors_enricher])

    context = RequestContext()
    context.request = Request(method="GET", path="/random_non_edge_route")
    response = Response()
    chain.handle(context, response)

    # Make sure the request has not been blocked and has been enriched by the CORS enforcer
    assert response.status_code == 200
    assert "Access-Control-Allow-Methods" in response.headers
