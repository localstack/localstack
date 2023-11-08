import re

from botocore.exceptions import ClientError

from localstack.aws.connect import connect_to
from localstack.config import S3_STATIC_WEBSITE_HOSTNAME, S3_VIRTUAL_HOSTNAME
from localstack.services.cloudformation.cfn_utils import rename_params
from localstack.services.cloudformation.deployment_utils import (
    dump_json_params,
    generate_default_name,
)
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.services.s3.utils import normalize_bucket_name
from localstack.utils.aws import arns
from localstack.utils.common import canonical_json, md5
from localstack.utils.testutil import delete_all_s3_objects
from localstack.utils.urls import localstack_host


class S3BucketPolicy(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::S3::BucketPolicy"

    def fetch_state(self, stack_name, resources):
        bucket_name = self.props.get("Bucket") or self.logical_resource_id
        return connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).s3.get_bucket_policy(Bucket=bucket_name)

    @staticmethod
    def get_deploy_templates():
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = md5(
                canonical_json(resource["Properties"]["PolicyDocument"])
            )

        return {
            "create": {
                "function": "put_bucket_policy",
                "parameters": rename_params(
                    dump_json_params(None, "PolicyDocument"),
                    {"PolicyDocument": "Policy", "Bucket": "Bucket"},
                ),
                "result_handler": _handle_result,
            },
            "delete": {"function": "delete_bucket_policy", "parameters": {"Bucket": "Bucket"}},
        }


class S3Bucket(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::S3::Bucket"

    @staticmethod
    def normalize_bucket_name(bucket_name):
        return normalize_bucket_name(bucket_name)

    @staticmethod
    def add_defaults(resource, stack_name: str):
        role_name = resource.get("Properties", {}).get("BucketName")
        if not role_name:
            resource["Properties"]["BucketName"] = normalize_bucket_name(
                generate_default_name(stack_name, resource["LogicalResourceId"])
            )

    @classmethod
    def get_deploy_templates(cls):
        def convert_acl_cf_to_s3(acl):
            """Convert a CloudFormation ACL string (e.g., 'PublicRead') to an S3 ACL string (e.g., 'public-read')"""
            return re.sub("(?<!^)(?=[A-Z])", "-", acl).lower()

        def transform_website_configuration(website_configuration: dict) -> dict:
            if not website_configuration:
                return {}
            output = {}
            if index := website_configuration.get("IndexDocument"):
                output["IndexDocument"] = {"Suffix": index}
            if error := website_configuration.get("ErrorDocument"):
                output["ErrorDocument"] = {"Key": error}
            if redirect_all := website_configuration.get("RedirectAllRequestsTo"):
                output["RedirectAllRequestsTo"] = redirect_all

            for r in website_configuration.get("RoutingRules", []):
                rule = {}
                if condition := r.get("RoutingRuleCondition"):
                    rule["Condition"] = condition
                if redirect := r.get("RedirectRule"):
                    rule["Redirect"] = redirect
                output.setdefault("RoutingRules", []).append(rule)

            return output

        def transform_cfn_cors(cors_config):
            # See https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketCors.html
            # https://docs.aws.amazon.com/AmazonS3/latest/API/API_CORSRule.html
            # only AllowedMethods and AllowedOrigins are required
            if not cors_config:
                return {}

            cors_rules = []
            for cfn_rule in cors_config.get("CorsRules", []):
                rule = {
                    "AllowedOrigins": cfn_rule.get("AllowedOrigins"),
                    "AllowedMethods": cfn_rule.get("AllowedMethods"),
                }
                # we should not pass those to PutBucketCors if they are None, as S3 will provide default values and
                # does not accept None
                if (allowed_headers := cfn_rule.get("AllowedHeaders")) is not None:
                    rule["AllowedHeaders"] = allowed_headers

                if (allowed_headers := cfn_rule.get("ExposedHeaders")) is not None:
                    rule["ExposeHeaders"] = allowed_headers

                if (allowed_headers := cfn_rule.get("MaxAge")) is not None:
                    rule["MaxAgeSeconds"] = allowed_headers

                if (allowed_headers := cfn_rule.get("Id")) is not None:
                    rule["ID"] = allowed_headers

                cors_rules.append(rule)

            return {"CORSRules": cors_rules}

        def s3_bucket_notification_config(
            account_id: str,
            region_name: str,
            properties: dict,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ) -> dict | None:
            notif_config = properties.get("NotificationConfiguration")
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
                "Bucket": properties.get("BucketName"),
                "NotificationConfiguration": {
                    "LambdaFunctionConfigurations": lambda_configs,
                    "QueueConfigurations": queue_configs,
                    "TopicConfigurations": topic_configs,
                },
            }
            if notif_config.get("EventBridgeConfiguration", {}).get("EventBridgeEnabled"):
                result["NotificationConfiguration"]["EventBridgeConfiguration"] = {}

            return result

        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            bucket_name = resource["Properties"]["BucketName"]
            resource["PhysicalResourceId"] = bucket_name
            resource["Properties"]["Arn"] = arns.s3_bucket_arn(bucket_name)
            domain_name = f"{bucket_name}.{S3_VIRTUAL_HOSTNAME}"
            resource["Properties"]["DomainName"] = domain_name
            resource["Properties"]["RegionalDomainName"] = domain_name
            # by default (parity) s3 website only supports http
            #   https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteHosting.html
            #   "Amazon S3 website endpoints do not support HTTPS. If you want to use HTTPS,
            #   you can use Amazon CloudFront [...]"
            resource["Properties"][
                "WebsiteURL"
            ] = f"http://{bucket_name}.{S3_STATIC_WEBSITE_HOSTNAME}:{localstack_host().port}"
            # resource["Properties"]["DualStackDomainName"] = ?

        def _pre_delete(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            s3 = connect_to(aws_access_key_id=account_id, region_name=region_name).s3
            props = resource["Properties"]
            bucket_name = props.get("BucketName")
            try:
                s3.delete_bucket_policy(Bucket=bucket_name)
            except Exception:
                pass
            # TODO: divergence from how AWS deals with bucket deletes (should throw an error)
            try:
                delete_all_s3_objects(s3, bucket_name)
            except Exception as e:
                if "NoSuchBucket" not in str(e):
                    raise

        def _add_bucket_tags(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            s3 = connect_to(aws_access_key_id=account_id, region_name=region_name).s3
            props = resource["Properties"]
            bucket_name = props.get("BucketName")
            tags = props.get("Tags", [])
            if len(tags) > 0:
                s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": tags})

        def _put_bucket_versioning(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            s3_client = connect_to(aws_access_key_id=account_id, region_name=region_name).s3
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

        def _put_bucket_cors_configuration(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            s3_client = connect_to(aws_access_key_id=account_id, region_name=region_name).s3
            props = resource["Properties"]
            bucket_name = props.get("BucketName")
            cors_configuration = transform_cfn_cors(props.get("CorsConfiguration"))
            if cors_configuration:
                s3_client.put_bucket_cors(
                    Bucket=bucket_name,
                    CORSConfiguration=cors_configuration,
                )

        def _put_bucket_website_configuration(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            s3_client = connect_to(aws_access_key_id=account_id, region_name=region_name).s3
            props = resource["Properties"]
            bucket_name = props.get("BucketName")
            website_config = transform_website_configuration(props.get("WebsiteConfiguration"))
            if website_config:
                s3_client.put_bucket_website(
                    Bucket=bucket_name,
                    WebsiteConfiguration=website_config,
                )

        def _create_bucket(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            s3_client = connect_to(aws_access_key_id=account_id, region_name=region_name).s3
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
                    if region_name != "us-east-1":
                        params["CreateBucketConfiguration"] = {
                            "LocationConstraint": region_name,
                        }
                    s3_client.create_bucket(**params)

        result = {
            "create": [
                {
                    "function": _create_bucket,
                    "result_handler": _handle_result,
                },
                {
                    "function": "put_bucket_notification_configuration",
                    "parameters": s3_bucket_notification_config,
                },
                {"function": _put_bucket_versioning},
                {"function": _put_bucket_cors_configuration},
                {"function": _add_bucket_tags},
                {"function": _put_bucket_website_configuration},
            ],
            "delete": [
                {"function": _pre_delete},
                {"function": "delete_bucket", "parameters": {"Bucket": "BucketName"}},
            ],
        }
        return result

    def fetch_state(self, stack_name, resources):
        props = self.props
        bucket_name = props["BucketName"]
        bucket_name = self.normalize_bucket_name(bucket_name)
        s3_client = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).s3
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

        website_config_props = props.get("WebsiteConfiguration")
        website_config = s3_client.get_bucket_website_configuration(Bucket=bucket_name)
        if website_config_props and not website_config:
            return None

        return response
