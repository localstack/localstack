from moto.route53 import responses as route53_responses
from moto.route53.models import route53_backend
from moto.route53.responses import DELETE_HEALTH_CHECK_RESPONSE
from moto.route53.urls import url_paths as route53_url_paths
from six.moves.urllib.parse import parse_qs, urlparse

from localstack import config
from localstack.services.infra import start_moto_server

XMLNS_ROUTE53 = "https://route53.amazonaws.com/doc/2013-04-01/"


def apply_patches():
    # patch function to match hosted zone if zone name ends with a dot
    def list_hosted_zones_by_name_response(self, request, full_url, headers):
        parsed_url = urlparse(full_url)
        query_params = parse_qs(parsed_url.query)
        dnsname = query_params.get("dnsname")
        dnsname = dnsname and dnsname[0]
        all_zones = route53_backend.get_all_hosted_zones()
        zones1 = [zone for zone in all_zones if zone.name == dnsname]
        zones2 = [zone for zone in all_zones if zone.name == "%s." % dnsname]
        if not zones1 and zones2:
            full_url = full_url.replace("dnsname=%s" % dnsname, "dnsname=%s." % dnsname)
        return list_hosted_zones_by_name_response_orig(self, request, full_url, headers)

    list_hosted_zones_by_name_response_orig = (
        route53_responses.Route53.list_hosted_zones_by_name_response
    )
    route53_responses.Route53.list_hosted_zones_by_name_response = (
        list_hosted_zones_by_name_response
    )

    def get_or_delete_health_check(self, request, full_url, headers):
        parsed_url = urlparse(full_url)
        parts = parsed_url.path.strip("/").split("/")
        health_check_id = parts[-1]
        if request.method == "GET":
            health_check = route53_backend.health_checks.get(health_check_id)
            if not health_check:
                return 404, {}, ""
            result = """<GetHealthCheckResponse xmlns="{}">{}</GetHealthCheckResponse>"""
            result = result.format(XMLNS_ROUTE53, health_check.to_xml()).strip()
            return result
        if request.method == "DELETE":
            route53_backend.delete_health_check(health_check_id)
            return 200, headers, DELETE_HEALTH_CHECK_RESPONSE

    if not hasattr(route53_responses.Route53, "get_or_delete_health_check"):
        route53_responses.Route53.get_or_delete_health_check = get_or_delete_health_check

    # update URL path mappings to enable the patch
    route53_url_paths[
        r"{0}/(?P<api_version>[\d_-]+)/healthcheck/(?P<health_check_id>[^/]+)/?$"
    ] = route53_responses.Route53().get_or_delete_health_check


def start_route53(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_ROUTE53
    apply_patches()
    return start_moto_server(
        "route53",
        port,
        name="Route53",
        asynchronous=asynchronous,
        update_listener=update_listener,
    )
