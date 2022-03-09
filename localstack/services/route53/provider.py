from datetime import datetime
from urllib.parse import parse_qs, urlparse

from moto.route53 import responses as route53_responses
from moto.route53.models import route53_backend
from moto.route53.responses import DELETE_HEALTH_CHECK_RESPONSE
from moto.route53.urls import url_paths as route53_url_paths

from localstack.aws.api import RequestContext
from localstack.aws.api.route53 import (
    VPC,
    AssociateVPCComment,
    AssociateVPCWithHostedZoneResponse,
    ChangeInfo,
    ChangeStatus,
    DisassociateVPCComment,
    DisassociateVPCFromHostedZoneResponse,
    GetChangeResponse,
    ResourceId,
    Route53Api,
    VPCAssociationNotFound,
)
from localstack.aws.api.route53resolver import Route53ResolverApi
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.route53.models import HostedZoneAssociation, Route53Backend
from localstack.utils.aws import aws_stack
from localstack.utils.patch import patch
from localstack.utils.strings import short_uid

XMLNS_ROUTE53 = "https://route53.amazonaws.com/doc/2013-04-01/"


class Route53ResolverProvider(Route53ResolverApi):
    pass


class Route53Provider(Route53Api, ServiceLifecycleHook):
    def __init__(self):
        apply_patches()

    def get_change(self, context: RequestContext, id: ResourceId) -> GetChangeResponse:
        change_info = ChangeInfo(Id=id, Status=ChangeStatus.INSYNC, SubmittedAt=datetime.now())
        return GetChangeResponse(ChangeInfo=change_info)

    def associate_vpc_with_hosted_zone(
        self,
        context: RequestContext,
        hosted_zone_id: ResourceId,
        vpc: VPC,
        comment: AssociateVPCComment = None,
    ) -> AssociateVPCWithHostedZoneResponse:
        region_details = Route53Backend.get()
        # TODO: handle NoSuchHostedZone and ConflictingDomainExist
        zone_details = region_details.vpc_hosted_zone_associations.get(hosted_zone_id) or []
        hosted_zone_association = HostedZoneAssociation(
            hosted_zone_id=hosted_zone_id,
            id=short_uid(),
            vpc=vpc,
            status=ChangeStatus.INSYNC,
            submitted_at=datetime.now(),
        )
        zone_details.append(hosted_zone_association)
        vpc_id = vpc.get("VPCId")
        # update VPC info in hosted zone moto object - fixes required after https://github.com/spulec/moto/pull/4786
        hosted_zone = route53_backend.zones.get(hosted_zone_id)
        if not getattr(hosted_zone, "vpcid", None):
            hosted_zone.vpcid = vpc_id
        if not getattr(hosted_zone, "vpcregion", None):
            hosted_zone.vpcregion = aws_stack.get_region()

        region_details.vpc_hosted_zone_associations[hosted_zone_id] = zone_details
        return AssociateVPCWithHostedZoneResponse(
            ChangeInfo=ChangeInfo(
                Id=short_uid(), Status=ChangeStatus.INSYNC, SubmittedAt=datetime.now()
            )
        )

    def disassociate_vpc_from_hosted_zone(
        self,
        context: RequestContext,
        hosted_zone_id: ResourceId,
        vpc: VPC,
        comment: DisassociateVPCComment = None,
    ) -> DisassociateVPCFromHostedZoneResponse:
        region_details = Route53Backend.get()
        zone_details = region_details.vpc_hosted_zone_associations.get(hosted_zone_id) or []

        def _match(_zone: HostedZoneAssociation):
            return _zone.hosted_zone_id == hosted_zone_id and _zone.vpc.get("VPCId") == vpc.get(
                "VPCId"
            )

        matching_hosted_zones = [z for z in zone_details if _match(z)]
        not_matching_zones = [z for z in zone_details if not _match(z)]

        if not matching_hosted_zones:
            raise VPCAssociationNotFound()

        region_details.vpc_hosted_zone_associations[hosted_zone_id] = not_matching_zones
        return DisassociateVPCFromHostedZoneResponse(
            ChangeInfo=ChangeInfo(
                Id=matching_hosted_zones[0].id,
                Status=matching_hosted_zones[0].status,
                SubmittedAt=matching_hosted_zones[0].submitted_at,
            )
        )


def get_or_delete_health_check(request, full_url, headers):
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


@patch(route53_responses.Route53.list_hosted_zones_by_name_response)
def list_hosted_zones_by_name_response(fn, self, request, full_url, headers):
    """Patch function to match hosted zone if zone name ends with a dot"""
    parsed_url = urlparse(full_url)
    query_params = parse_qs(parsed_url.query)
    dns_name = query_params.get("dnsname")
    dns_name = dns_name and dns_name[0]
    all_zones = route53_backend.get_all_hosted_zones()
    zones1 = [zone for zone in all_zones if zone.name == dns_name]
    zones2 = [zone for zone in all_zones if zone.name == "%s." % dns_name]
    if not zones1 and zones2:
        full_url = full_url.replace("dnsname=%s" % dns_name, "dnsname=%s." % dns_name)
    return fn(self, request, full_url, headers)


def apply_patches():
    if not hasattr(route53_responses.Route53, "get_or_delete_health_check"):
        route53_responses.Route53.get_or_delete_health_check = get_or_delete_health_check
    # update URL path mappings to enable the patch
    path_regex = r"{0}/(?P<api_version>[\d_-]+)/healthcheck/(?P<health_check_id>[^/]+)/?$"
    route53_url_paths[path_regex] = route53_responses.Route53().get_or_delete_health_check
