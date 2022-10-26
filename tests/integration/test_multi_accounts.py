import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest.fixtures import _client


@pytest.fixture
def client_factory():
    region_name = "eu-central-1"

    def _client_factory(service: str, aws_access_key_id: str):
        return _client(service, region_name=region_name, aws_access_key_id=aws_access_key_id)

    yield _client_factory


class TestMultiAccounts:
    def test_account_id_namespacing_for_moto_backends(self, client_factory):
        #
        # ACM
        #

        account_id1 = "420420420420"
        account_id2 = "133713371337"

        # Ensure resources are isolated by account ID namespaces
        acm_client1 = client_factory("acm", account_id1)
        acm_client2 = client_factory("acm", account_id2)

        acm_client1.request_certificate(DomainName="example.com")

        certs = acm_client1.list_certificates()
        assert len(certs["CertificateSummaryList"]) == 1

        certs = acm_client2.list_certificates()
        assert len(certs["CertificateSummaryList"]) == 0

        #
        # EC2
        #

        ec2_client1 = client_factory("ec2", account_id1)
        ec2_client2 = client_factory("ec2", account_id2)

        # Ensure resources are namespaced by account ID
        ec2_client1.create_key_pair(KeyName="lorem")
        pairs = ec2_client1.describe_key_pairs()
        assert len(pairs["KeyPairs"]) == 1

        pairs = ec2_client2.describe_key_pairs()
        assert len(pairs["KeyPairs"]) == 0

        # Ensure name conflicts don't happen across namespaces
        ec2_client2.create_key_pair(KeyName="lorem")
        ec2_client2.create_key_pair(KeyName="ipsum")

        pairs = ec2_client2.describe_key_pairs()
        assert len(pairs["KeyPairs"]) == 2

        pairs = ec2_client1.describe_key_pairs()
        assert len(pairs["KeyPairs"]) == 1

        # Ensure account ID resolver is correctly patched in Moto
        # Calls originating in Moto must make use of client provided account ID
        ec2_client1.create_vpc(CidrBlock="10.1.0.0/16")
        vpcs = ec2_client1.describe_vpcs()["Vpcs"]
        assert all([vpc["OwnerId"] == account_id1 for vpc in vpcs])

        #
        # ELB
        #

        elb_client1 = client_factory("elbv2", account_id1)
        elb_client2 = client_factory("elbv2", account_id2)

        # Ensure namespacing works for interdependent services
        # In order to create an LB, a valid Subnet is required, which is part of EC2
        subnet_id1 = ec2_client1.describe_subnets()["Subnets"][0]["SubnetId"]

        # Creating LB in same namespace as subnet must work
        elb_client1.create_load_balancer(Name="lorem", Subnets=[subnet_id1])

        # and fail in second namespace throwing invalid subnet error
        with pytest.raises(ClientError) as exc:
            elb_client2.create_load_balancer(Name="lorem", Subnets=[subnet_id1])
        err = exc.value.response["Error"]
        assert err["Code"] == "InvalidSubnetID.NotFound"

    def test_account_id_namespacing_for_localstack_backends(self, client_factory):
        # Ensure resources are isolated by account ID namespaces
        account_id1 = "420420420420"
        account_id2 = "133713371337"

        #
        # IOT
        #

        iot_client1 = client_factory("iot", account_id1)
        iot_client2 = client_factory("iot", account_id2)

        iot_client1.create_thing(thingName="foo")

        assert len(iot_client1.list_things()["things"]) == 1
        assert len(iot_client2.list_things()["things"]) == 0

        iot_client2.create_thing(thingName="foo")
        iot_client2.create_thing(thingName="bar")

        assert len(iot_client1.list_things()["things"]) == 1
        assert len(iot_client2.list_things()["things"]) == 2

        #
        # Amplify
        #

        amplify_client1 = client_factory("amplify", account_id1)
        amplify_client2 = client_factory("amplify", account_id2)

        amplify_client1.create_app(name="foo")

        assert len(amplify_client1.list_apps()["apps"]) == 1
        assert len(amplify_client2.list_apps()["apps"]) == 0

        amplify_client2.create_app(name="foo")
        amplify_client2.create_app(name="bar")

        assert len(amplify_client1.list_apps()["apps"]) == 1
        assert len(amplify_client2.list_apps()["apps"]) == 2

        #
        # Appconfig
        #

        appconfig_client1 = client_factory("appconfig", account_id1)
        appconfig_client2 = client_factory("appconfig", account_id2)

        appconfig_client1.create_application(Name="foo")

        assert len(appconfig_client1.list_applications()["Items"]) == 1
        assert len(appconfig_client2.list_applications()["Items"]) == 0

        appconfig_client2.create_application(Name="foo")
        appconfig_client2.create_application(Name="bar")

        assert len(appconfig_client1.list_applications()["Items"]) == 1
        assert len(appconfig_client2.list_applications()["Items"]) == 2
