import re
from moto.ec2 import models as ec2_models
from moto.ec2.responses import security_groups
from moto.ec2.exceptions import InvalidPermissionNotFoundError
from moto.ec2.responses.reserved_instances import ReservedInstances
from localstack import config
from localstack.services.infra import start_moto_server

REGEX_FLAGS = re.IGNORECASE | re.MULTILINE | re.DOTALL


def patch_ec2():
    def patch_revoke_security_group_egress(backend):
        revoke_security_group_egress_orig = backend.revoke_security_group_egress

        def revoke_security_group_egress(*args, **kwargs):
            try:
                return revoke_security_group_egress_orig(*args, **kwargs)
            except InvalidPermissionNotFoundError:
                # this can happen, as CidrIpv6 is not yet supported by moto
                if args[4] == []:
                    return '_ignore_'

        return revoke_security_group_egress

    def patch_delete_nat_gateway(backend):
        def delete_nat_gateway(nat_gateway_id):
            gateway = backend.nat_gateways.get(nat_gateway_id)
            if gateway:
                gateway.state = 'deleted'
        return delete_nat_gateway

    for region, backend in ec2_models.ec2_backends.items():
        backend.revoke_security_group_egress = patch_revoke_security_group_egress(backend)
        backend.delete_nat_gateway = patch_delete_nat_gateway(backend)

    # TODO Implement Reserved Instance backend
    # https://github.com/localstack/localstack/issues/2435
    def describe_reserved_instances_offerings(self):
        template = self.response_template(DESCRIBE_RESERVED_INSTANCES_OFFERINGS_RESPONSE)
        return template.render({})

    def purchase_reserved_instances_offering(self):
        template = self.response_template(PURCHASE_RESERVED_INSTANCES_OFFERINGS_RESPONSE)
        return template.render({})

    def describe_reserved_instances(self):
        template = self.response_template(DESCRIBE_RESERVED_INSTANCES_RESPONSE)
        return template.render({})

    ReservedInstances.describe_reserved_instances_offerings = describe_reserved_instances_offerings
    ReservedInstances.purchase_reserved_instances_offering = purchase_reserved_instances_offering
    ReservedInstances.describe_reserved_instances = describe_reserved_instances

    # make sure we report groupName only for default VPCs (i.e., omit for custom VPCs with vpc_id)
    search = r'</groupId>\s*<groupName>\{\{\s*source_group.name\s*\}\}</groupName>'
    replace = r'</groupId>{% if not group.vpc_id %}<groupName>{{ source_group.name }}</groupName>{% endif %}'
    security_groups.DESCRIBE_SECURITY_GROUPS_RESPONSE = re.sub(search, replace,
        security_groups.DESCRIBE_SECURITY_GROUPS_RESPONSE, flags=REGEX_FLAGS)


def start_ec2(port=None, asynchronous=False, update_listener=None):
    patch_ec2()
    port = port or config.PORT_EC2

    return start_moto_server('ec2', port, name='EC2', asynchronous=asynchronous, update_listener=update_listener)


DESCRIBE_RESERVED_INSTANCES_OFFERINGS_RESPONSE = """
<DescribeReservedInstancesOfferingsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <requestId>2bc7dafa-dafd-4257-bdf9-c0814EXAMPLE</requestId>
  <reservedInstancesOfferingsSet>
    <item>
      <reservedInstancesOfferingId>a6ce8269-7b8c-42cd-a7f5-0841cEXAMPLE</reservedInstancesOfferingId>
      <instanceType>t2.small</instanceType>
      <availabilityZone>us-east-1a</availabilityZone>
      <duration>2332800</duration>
      <fixedPrice>0.0</fixedPrice>
      <usagePrice>0.0</usagePrice>
      <productDescription>Linux/UNIX</productDescription>
      <instanceTenancy>default</instanceTenancy>
      <currencyCode>USD</currencyCode>
      <offeringType>Heavy Utilization</offeringType>
      <recurringCharges>
           <item>
                <frequency>Hourly</frequency>
                <amount>0.19</amount>
            </item>
      </recurringCharges>
      <marketplace>true</marketplace>
      <pricingDetailsSet>
        <item>
          <price>0.0</price>
          <count>3</count>
        </item>
      </pricingDetailsSet>
       <offeringClass>standard</offeringClass>
      <scope>Availability Zone</scope>
    </item>
  </reservedInstancesOfferingsSet>
</DescribeReservedInstancesOfferingsResponse>"""

PURCHASE_RESERVED_INSTANCES_OFFERINGS_RESPONSE = """
<PurchaseReservedInstancesOfferingResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
  <reservedInstancesId>e5a2ff3b-7d14-494f-90af-0b5d0EXAMPLE</reservedInstancesId>
</PurchaseReservedInstancesOfferingResponse>"""

DESCRIBE_RESERVED_INSTANCES_RESPONSE = """
<DescribeReservedInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
   <requestId>59dbff89-35bd-4eac-99ed-be587EXAMPLE</requestId>
   <reservedInstancesSet>
      <item>
         <reservedInstancesId>e5a2ff3b-7d14-494f-90af-0b5d0EXAMPLE</reservedInstancesId>
         <instanceType>m1.xlarge</instanceType>
         <availabilityZone>us-east-1a</availabilityZone>
         <start>2015-07-14T11:00:00Z</start>
         <end>2016-07-13T12:00:00Z</end>
         <duration>31536000</duration>
         <fixedPrice>0.0</fixedPrice>
         <usagePrice>0.034</usagePrice>
         <instanceCount>2</instanceCount>
         <productDescription>Linux/UNIX (Amazon VPC)</productDescription>
         <state>active</state>
         <instanceTenancy>default</instanceTenancy>
         <currencyCode>USD</currencyCode>
         <offeringType>Partial Upfront</offeringType>
         <recurringCharges>
                  <item>
                        <frequency>Hourly</frequency>
                        <amount>0.05</amount>
                  </item>
         </recurringCharges>
         <offeringClass>standard</offeringClass>
         <scope>AvailabilityZone</scope>
      </item>
   </reservedInstancesSet>
</DescribeReservedInstancesResponse>"""
