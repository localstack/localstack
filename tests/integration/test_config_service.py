import json
import unittest

from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid


class TestConfigService(unittest.TestCase):
    def setUp(self):
        self.config_service_client = aws_stack.connect_to_service("config")
        self.iam_client = aws_stack.connect_to_service("iam")

    def create_configuration_recorder(self, iam_role_name):
        assume_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                }
            ],
        }

        iam_role_arn = self.iam_client.create_role(
            RoleName=iam_role_name,
            AssumeRolePolicyDocument=json.dumps(assume_policy_document),
        )['Role']['Arn']


        configuration_recorder_name = 'test'

        self.config_service_client.put_configuration_recorder(
            ConfigurationRecorder={
                'name': configuration_recorder_name,
                'roleARN': iam_role_arn,
                'recordingGroup': {
                    'allSupported': True,
                    'includeGlobalResourceTypes': True,
                    'resourceTypes': ['AWS::EC2::Instance']
                }
            }
        )

    def test_put_configuration_recorder(self):
        iam_role_name = "role-{}".format(short_uid())
        configuration_recorder_name = 'test'

        self.create_configuration_recorder(iam_role_name)

        self.config_service_client.put_configuration_recorder(
            ConfigurationRecorder={
                'name': configuration_recorder_name,
                'roleARN': iam_role_arn,
                'recordingGroup': {
                    'allSupported': True,
                    'includeGlobalResourceTypes': True,
                    'resourceTypes': ['AWS::EC2::Instance']
                }
            }
        )

        configuration_recorder_data = self.config_service_client.describe_configuration_recorders()['ConfigurationRecorders'][0]

        self.assertIn(configuration_recorder_name, configuration_recorder_data['name'])
        self.assertIn(iam_role_arn, configuration_recorder_data['roleARN'])






    def test_import_certificate(self):
        acm = aws_stack.connect_to_service("acm")

        certs_before = acm.list_certificates().get("CertificateSummaryList", [])

        with self.assertRaises(Exception) as ctx:
            acm.import_certificate(Certificate=b"CERT123", PrivateKey=b"KEY123")
        self.assertIn("PEM", str(ctx.exception))

        private_key = ec2_utils.random_key_pair()["material"]
        result = acm.import_certificate(Certificate=DIGICERT_ROOT_CERT, PrivateKey=private_key)
        self.assertIn("CertificateArn", result)

        expected_arn = "arn:aws:acm:{0}:{1}:certificate".format(
            aws_stack.get_region(), TEST_AWS_ACCOUNT_ID
        )
        acm_cert_arn = result["CertificateArn"].split("/")[0]
        self.assertEqual(expected_arn, acm_cert_arn)

        certs_after = acm.list_certificates().get("CertificateSummaryList", [])
        self.assertEqual(len(certs_before) + 1, len(certs_after))

    def test_domain_validation(self):
        acm = aws_stack.connect_to_service("acm")

        domain_name = "example-%s.com" % short_uid()
        options = [{"DomainName": domain_name, "ValidationDomain": domain_name}]
        result = acm.request_certificate(DomainName=domain_name, DomainValidationOptions=options)
        self.assertIn("CertificateArn", result)

        result = acm.describe_certificate(CertificateArn=result["CertificateArn"])
        options = result["Certificate"]["DomainValidationOptions"]
        self.assertEqual(1, len(options))






 put-configuration-recorder --configuration-recorder name=default,roleARN=arn:aws:iam:123456789012:-:role/config-role --recording-group allSupported=true,includeGlobalResourceTypes=true

(base) ✔ /tmp
13:28 $ aws configservice --endpoint-url=http://localhost:4566 --region us-east-1 --profile localstack put-delivery-channel --delivery-channel file://deliveryChannel.json
(base) ✔ /tmp
13:28 $ cat deliveryChannel.json
{
    "name": "default",
    "s3BucketName": "test",
    "snsTopicARN": "arn:aws:sns:us-east-1:000000000000:config-topic",
    "configSnapshotDeliveryProperties": {
        "deliveryFrequency": "Twelve_Hours"
    }
}
(base) ✔ /tmp
13:28 $ aws configservice --endpoint-url=http://localhost:4566 --region us-east-1 --profile localstack start-configuration-recorder --configuration-recorder-name default


$ aws configservice --endpoint-url=http://localhost:4566 --region us-east-1 --profile localstack describe-configuration-recorders
{
    "ConfigurationRecorders": [
        {
            "name": "default",
            "roleARN": "arn:aws:iam:123456789012:-:role/config-role",
            "recordingGroup": {
                "allSupported": true,
                "includeGlobalResourceTypes": true,
                "resourceTypes": []
            }
        }
    ]
}


$ aws configservice --endpoint-url=http://localhost:4566 --region us-east-1 --profile localstack describe-configuration-recorder-status --configuration-recorder-names default
{
    "ConfigurationRecordersStatus": [
        {
            "name": "default",
            "lastStartTime": "2021-08-27T13:28:34+02:00",
            "recording": true,
            "lastStatus": "PENDING",
            "lastStatusChangeTime": "2021-08-27T13:28:34+02:00"
        }
    ]
}


