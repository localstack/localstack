from datetime import datetime
from typing import Optional

import moto.route53.models as route53_models
from moto.route53.models import route53_backend

from localstack.aws.api import RequestContext
from localstack.aws.api.route53 import (
    VPC,
    AssociateVPCComment,
    AssociateVPCWithHostedZoneResponse,
    ChangeInfo,
    ChangeStatus,
    DeleteHealthCheckResponse,
    DisassociateVPCComment,
    DisassociateVPCFromHostedZoneResponse,
    GetChangeResponse,
    GetHealthCheckResponse,
    HealthCheck,
    HealthCheckId,
    NoSuchHealthCheck,
    ResourceId,
    Route53Api,
    VPCAssociationNotFound,
)
from localstack.aws.api.route53resolver import Route53ResolverApi
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.route53.models import HostedZoneAssociation, Route53Backend
from localstack.utils.aws import aws_stack
from localstack.utils.strings import short_uid


class Route53ResolverProvider(Route53ResolverApi):
    pass


class Route53Provider(Route53Api, ServiceLifecycleHook):
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

    def get_health_check(
        self, context: RequestContext, health_check_id: HealthCheckId
    ) -> GetHealthCheckResponse:
        health_check: Optional[route53_models.HealthCheck] = route53_backend.health_checks.get(
            health_check_id, None
        )
        if not health_check:
            raise NoSuchHealthCheck(
                f"No health check exists with the specified ID {health_check_id}"
            )
        return GetHealthCheckResponse(
            HealthCheck=HealthCheck(
                Id=health_check.id, CallerReference=health_check.caller_reference
            )
        )

    def delete_health_check(
        self, context: RequestContext, health_check_id: HealthCheckId
    ) -> DeleteHealthCheckResponse:
        health_check = route53_backend.delete_health_check(health_check_id)
        if not health_check:
            raise NoSuchHealthCheck(
                f"No health check exists with the specified ID {health_check_id}"
            )
        return {}
