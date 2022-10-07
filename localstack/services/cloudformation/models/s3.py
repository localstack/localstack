import json
import re

from botocore.exceptions import ClientError

from localstack.constants import S3_STATIC_WEBSITE_HOSTNAME, S3_VIRTUAL_HOSTNAME
from localstack.services.cloudformation.deployment_utils import (
    PLACEHOLDER_RESOURCE_NAME,
    dump_json_params,
    generate_default_name,
)
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.services.s3 import s3_listener, s3_utils
from localstack.utils.aws import aws_stack
from localstack.utils.cloudformation.cfn_utils import rename_params
from localstack.utils.common import canonical_json, md5
from localstack.utils.testutil import delete_all_s3_objects


class S3BucketPolicy(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::S3::BucketPolicy"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        policy = self.props.get("Policy")
        return policy and md5(canonical_json(json.loads(policy)))

    def fetch_state(self, stack_name, resources):
        bucket_name = self.props.get("Bucket") or self.resource_id
        bucket_name = self.resolve_refs_recursively(stack_name, bucket_name, resources)
        return aws_stack.connect_to_service("s3").get_bucket_policy(Bucket=bucket_name)

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "put_bucket_policy",
                "parameters": rename_params(
                    dump_json_params(None, "PolicyDocument"),
                    {"PolicyDocument": "Policy", "Bucket": "Bucket"},
                ),
            },
            "delete": {"function": "delete_bucket_policy", "parameters": {"Bucket": "Bucket"}},
        }


class S3Bucket(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::S3::Bucket"

    def get_resource_name(self):
        return self.normalize_bucket_name(self.props.get("BucketName"))

    @staticmethod
    def normalize_bucket_name(bucket_name):
        return s3_utils.normalize_bucket_name(bucket_name)

    @staticmethod
    def add_defaults(resource, stack_name: str):
        role_name = resource.get("Properties", {}).get("BucketName")
        if not role_name:
            resource["Properties"]["BucketName"] = s3_listener.normalize_bucket_name(
                generate_default_name(stack_name, resource["LogicalResourceId"])
            )

    @classmethod
    def get_deploy_templates(cls):
        def convert_acl_cf_to_s3(acl):
            """Convert a CloudFormation ACL string (e.g., 'PublicRead') to an S3 ACL string (e.g., 'public-read')"""
            return re.sub("(?<!^)(?=[A-Z])", "-", acl).lower()

        def s3_bucket_notification_config(params, **kwargs):
            notif_config = params.get("NotificationConfiguration")
            if not notif_config:
                return None

            lambda_configs = []
            queue_configs = []
            topic_configs = []

            attr_tuples = (
                (
                    "LambdaConfigurations",
                    lambda_configs,
                    "LambdaFunctionArn",
                    "Function",
                ),
                ("QueueConfigurations", queue_configs, "QueueArn", "Queue"),
                ("TopicConfigurations", topic_configs, "TopicArn", "Topic"),
            )

            # prepare lambda/queue/topic notification configs
            for attrs in attr_tuples:
                for notif_cfg in notif_config.get(attrs[0]) or []:
                    filter_rules = notif_cfg.get("Filter", {}).get("S3Key", {}).get("Rules")
                    entry = {
                        attrs[2]: notif_cfg[attrs[3]],
                        "Events": [notif_cfg["Event"]],
                    }
                    if filter_rules:
                        entry["Filter"] = {"Key": {"FilterRules": filter_rules}}
                    attrs[1].append(entry)

            # construct final result
            result = {
                "Bucket": params.get("BucketName") or PLACEHOLDER_RESOURCE_NAME,
                "NotificationConfiguration": {
                    "LambdaFunctionConfigurations": lambda_configs,
                    "QueueConfigurations": queue_configs,
                    "TopicConfigurations": topic_configs,
                },
            }
            return result

        def _pre_delete(resource_id, resources, resource_type, func, stack_name):
            s3 = aws_stack.connect_to_service("s3")
            resource = resources[resource_id]
            props = resource["Properties"]
            bucket_name = props.get("BucketName")
            try:
                s3.delete_bucket_policy(Bucket=bucket_name)
            except Exception:
                pass
            s3_listener.remove_bucket_notification(resource["PhysicalResourceId"])
            # TODO: divergence from how AWS deals with bucket deletes (should throw an error)
            try:
                delete_all_s3_objects(bucket_name)
            except Exception as e:
                if "NoSuchBucket" not in str(e):
                    raise

        def _add_bucket_tags(resource_id, resources, resource_type, func, stack_name):
            s3 = aws_stack.connect_to_service("s3")
            resource = resources[resource_id]
            props = resource["Properties"]
            bucket_name = props.get("BucketName")
            tags = props.get("Tags", [])
            if len(tags) > 0:
                s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": tags})

        def _put_bucket_versioning(resource_id, resources, resource_type, func, stack_name):
            s3_client = aws_stack.connect_to_service("s3")
            resource = resources[resource_id]
            props = resource["Properties"]
            bucket_name = props.get("BucketName")
            versioning_config = props.get("VersioningConfiguration")
            if versioning_config:
                s3_client.put_bucket_versioning(
                    Bucket=bucket_name,
                    VersioningConfiguration={
                        "Status": versioning_config.get("Status", "Disabled"),
                    },
                )

        def _create_bucket(resource_id, resources, resource_type, func, stack_name):
            s3_client = aws_stack.connect_to_service("s3")
            resource = resources[resource_id]
            props = resource["Properties"]
            bucket_name = props.get("BucketName")
            try:
                s3_client.head_bucket(Bucket=bucket_name)
            except ClientError as e:
                if e.response["Error"]["Message"] == "Not Found":
                    bucket_name = props.get("BucketName")
                    params = {
                        "Bucket": bucket_name,
                        "ACL": convert_acl_cf_to_s3(props.get("AccessControl", "PublicRead")),
                    }
                    if aws_stack.get_region() != "us-east-1":
                        params["CreateBucketConfiguration"] = {
                            "LocationConstraint": aws_stack.get_region()
                        }
                    s3_client.create_bucket(**params)

        result = {
            "create": [
                {"function": _create_bucket},
                {
                    "function": "put_bucket_notification_configuration",
                    "parameters": s3_bucket_notification_config,
                },
                {"function": _put_bucket_versioning},
                {"function": _add_bucket_tags},
            ],
            "delete": [
                {"function": _pre_delete},
                {"function": "delete_bucket", "parameters": {"Bucket": "BucketName"}},
            ],
        }
        return result

    def fetch_state(self, stack_name, resources):
        props = self.props
        bucket_name = self._get_bucket_name()
        bucket_name = self.resolve_refs_recursively(stack_name, bucket_name, resources)
        bucket_name = self.normalize_bucket_name(bucket_name)
        s3_client = aws_stack.connect_to_service("s3")
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        notifs = props.get("NotificationConfiguration")
        if not response or not notifs:
            return response
        configs = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
        has_notifs = (
            configs.get("TopicConfigurations")
            or configs.get("QueueConfigurations")
            or configs.get("LambdaFunctionConfigurations")
        )
        if notifs and not has_notifs:
            return None
        return response

    def get_cfn_attribute(self, attribute_name):
        if attribute_name in ["DomainName", "RegionalDomainName"]:
            bucket_name = self._get_bucket_name()
            return "%s.%s" % (bucket_name, S3_VIRTUAL_HOSTNAME)

        if attribute_name == "WebsiteURL":
            bucket_name = self.props.get("BucketName")
            return f"https://{bucket_name}.{S3_STATIC_WEBSITE_HOSTNAME}"

        return super(S3Bucket, self).get_cfn_attribute(attribute_name)

    def get_physical_resource_id(self, attribute=None, **kwargs):
        bucket_name = self.props.get("BucketName")
        if attribute == "Arn":
            return aws_stack.s3_bucket_arn(bucket_name)
        return bucket_name

    def _get_bucket_name(self):
        return self.props.get("BucketName") or self.resource_id
