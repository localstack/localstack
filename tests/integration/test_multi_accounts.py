import pytest

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

    def test_account_id_namespacing_for_localstack_backends(self, client_factory):
        # Ensure resources are isolated by account ID namespaces
        account_id1 = "420420420420"
        account_id2 = "133713371337"

        sns_client1 = client_factory("sns", account_id1)
        sns_client2 = client_factory("sns", account_id2)

        arn1 = sns_client1.create_topic(Name="foo")["TopicArn"]

        assert len(sns_client1.list_topics()["Topics"]) == 1
        assert len(sns_client2.list_topics()["Topics"]) == 0

        arn2 = sns_client2.create_topic(Name="foo")["TopicArn"]
        arn3 = sns_client2.create_topic(Name="bar")["TopicArn"]

        assert len(sns_client1.list_topics()["Topics"]) == 1
        assert len(sns_client2.list_topics()["Topics"]) == 2

        sns_client1.tag_resource(ResourceArn=arn1, Tags=[{"Key": "foo", "Value": "1"}])

        assert len(sns_client1.list_tags_for_resource(ResourceArn=arn1)["Tags"]) == 1
        assert len(sns_client2.list_tags_for_resource(ResourceArn=arn2)["Tags"]) == 0
        assert len(sns_client2.list_tags_for_resource(ResourceArn=arn3)["Tags"]) == 0

        sns_client2.tag_resource(ResourceArn=arn2, Tags=[{"Key": "foo", "Value": "1"}])
        sns_client2.tag_resource(ResourceArn=arn2, Tags=[{"Key": "bar", "Value": "1"}])
        sns_client2.tag_resource(ResourceArn=arn3, Tags=[{"Key": "foo", "Value": "1"}])

        assert len(sns_client1.list_tags_for_resource(ResourceArn=arn1)["Tags"]) == 1
        assert len(sns_client2.list_tags_for_resource(ResourceArn=arn2)["Tags"]) == 2
        assert len(sns_client2.list_tags_for_resource(ResourceArn=arn3)["Tags"]) == 1
