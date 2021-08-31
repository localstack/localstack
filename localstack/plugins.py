import os
import sys

from localstack import config
from localstack.constants import TRUE_STRINGS
from localstack.utils.aws.request_context import patch_request_handling
from localstack.utils.bootstrap import ENV_SCRIPT_STARTING_DOCKER

# Note: make sure not to add any additional imports at the global scope here!


def register_localstack_plugins():

    # skip loading plugins for Docker launching, to increase startup speed
    if os.environ.get(ENV_SCRIPT_STARTING_DOCKER) not in TRUE_STRINGS:
        do_register_localstack_plugins()

    docker_flags = []

    # add Docker flags for edge ports
    for port in [config.EDGE_PORT, config.EDGE_PORT_HTTP]:
        if port:
            docker_flags += ["-p {p}:{p}".format(p=port)]

    result = {"docker": {"run_flags": " ".join(docker_flags)}}
    return result


def do_register_localstack_plugins():
    # register default plugins
    try:
        from localstack.services import edge
        from localstack.services.acm import acm_starter
        from localstack.services.apigateway import apigateway_listener, apigateway_starter
        from localstack.services.cloudwatch import cloudwatch_listener, cloudwatch_starter
        from localstack.services.configservice import configservice_starter
        from localstack.services.dynamodb import dynamodb_listener, dynamodb_starter
        from localstack.services.ec2 import ec2_listener, ec2_starter
        from localstack.services.es import es_starter
        from localstack.services.events import events_listener, events_starter
        from localstack.services.iam import iam_listener, iam_starter
        from localstack.services.infra import (
            start_cloudformation,
            start_dynamodbstreams,
            start_firehose,
            start_lambda,
            start_sns,
            start_ssm,
            start_sts,
        )
        from localstack.services.kinesis import kinesis_listener, kinesis_starter
        from localstack.services.kms import kms_listener, kms_starter
        from localstack.services.logs import logs_listener, logs_starter
        from localstack.services.plugins import Plugin, register_plugin
        from localstack.services.redshift import redshift_starter
        from localstack.services.resourcegroups import rg_listener, rg_starter
        from localstack.services.resourcegroupstaggingapi import rgta_listener, rgta_starter
        from localstack.services.route53 import route53_listener, route53_starter
        from localstack.services.s3 import s3_listener, s3_starter
        from localstack.services.secretsmanager import (
            secretsmanager_listener,
            secretsmanager_starter,
        )
        from localstack.services.ses import ses_listener, ses_starter
        from localstack.services.sns import sns_listener
        from localstack.services.sqs import sqs_listener, sqs_starter
        from localstack.services.ssm import ssm_listener
        from localstack.services.stepfunctions import stepfunctions_listener, stepfunctions_starter
        from localstack.services.sts import sts_listener, sts_starter
        from localstack.services.support import support_starter
        from localstack.services.swf import swf_listener, swf_starter

        register_plugin(Plugin("edge", start=edge.start_edge, active=True))

        register_plugin(Plugin("acm", start=acm_starter.start_acm))

        register_plugin(
            Plugin(
                "apigateway",
                start=apigateway_starter.start_apigateway,
                listener=apigateway_listener.UPDATE_APIGATEWAY,
            )
        )

        register_plugin(Plugin("cloudformation", start=start_cloudformation))

        register_plugin(Plugin("config", start=configservice_starter.start_configservice))

        register_plugin(
            Plugin(
                "cloudwatch",
                start=cloudwatch_starter.start_cloudwatch,
                listener=cloudwatch_listener.UPDATE_CLOUD_WATCH,
            )
        )

        register_plugin(
            Plugin(
                "dynamodb",
                start=dynamodb_starter.start_dynamodb,
                check=dynamodb_starter.check_dynamodb,
                listener=dynamodb_listener.UPDATE_DYNAMODB,
            )
        )

        register_plugin(Plugin("dynamodbstreams", start=start_dynamodbstreams))

        register_plugin(
            Plugin("ec2", start=ec2_starter.start_ec2, listener=ec2_listener.UPDATE_EC2)
        )

        register_plugin(Plugin("es", start=es_starter.start_elasticsearch_service))

        register_plugin(Plugin("firehose", start=start_firehose))

        register_plugin(
            Plugin("iam", start=iam_starter.start_iam, listener=iam_listener.UPDATE_IAM)
        )

        register_plugin(
            Plugin("sts", start=sts_starter.start_sts, listener=sts_listener.UPDATE_STS)
        )

        register_plugin(
            Plugin(
                "kinesis",
                start=kinesis_starter.start_kinesis,
                check=kinesis_starter.check_kinesis,
                listener=kinesis_listener.UPDATE_KINESIS,
            )
        )

        register_plugin(
            Plugin("kms", start=kms_starter.start_kms, listener=kms_listener.UPDATE_KMS)
        )

        register_plugin(Plugin("lambda", start=start_lambda))

        register_plugin(
            Plugin(
                "logs",
                start=logs_starter.start_cloudwatch_logs,
                listener=logs_listener.UPDATE_LOGS,
            )
        )

        register_plugin(Plugin("redshift", start=redshift_starter.start_redshift))

        register_plugin(
            Plugin(
                "route53",
                start=route53_starter.start_route53,
                listener=route53_listener.UPDATE_ROUTE53,
            )
        )

        register_plugin(
            Plugin(
                "s3",
                start=s3_starter.start_s3,
                check=s3_starter.check_s3,
                listener=s3_listener.UPDATE_S3,
            )
        )

        register_plugin(
            Plugin(
                "secretsmanager",
                start=secretsmanager_starter.start_secretsmanager,
                check=secretsmanager_starter.check_secretsmanager,
                listener=secretsmanager_listener.UPDATE_SECRETSMANAGER,
            )
        )

        register_plugin(
            Plugin("ses", start=ses_starter.start_ses, listener=ses_listener.UPDATE_SES)
        )

        register_plugin(Plugin("sns", start=start_sns, listener=sns_listener.UPDATE_SNS))

        register_plugin(
            Plugin(
                "sqs",
                start=sqs_starter.start_sqs,
                listener=sqs_listener.UPDATE_SQS,
                check=sqs_starter.check_sqs,
            )
        )

        register_plugin(Plugin("ssm", start=start_ssm, listener=ssm_listener.UPDATE_SSM))

        register_plugin(Plugin("sts", start=start_sts))

        register_plugin(
            Plugin(
                "events",
                start=events_starter.start_events,
                listener=events_listener.UPDATE_EVENTS,
            )
        )

        register_plugin(
            Plugin(
                "stepfunctions",
                start=stepfunctions_starter.start_stepfunctions,
                listener=stepfunctions_listener.UPDATE_STEPFUNCTIONS,
            )
        )

        register_plugin(
            Plugin(
                "swf",
                start=swf_starter.start_swf,
                check=swf_starter.check_swf,
                listener=swf_listener.UPDATE_SWF,
            )
        )

        register_plugin(
            Plugin(
                "resourcegroupstaggingapi",
                start=rgta_starter.start_rgsa,
                listener=rgta_listener.UPDATE_RGSA,
            )
        )

        register_plugin(
            Plugin(
                "resource-groups",
                start=rg_starter.start_rg,
                listener=rg_listener.UPDATE_RG,
            )
        )

        register_plugin(Plugin("support", start=support_starter.start_support))

        # apply patches
        patch_request_handling()

    except Exception as e:
        if not os.environ.get(ENV_SCRIPT_STARTING_DOCKER):
            print("Unable to register plugins: %s" % e)
            sys.stdout.flush()
        raise e
