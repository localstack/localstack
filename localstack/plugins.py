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
        from localstack.services.plugins import Service, register_service
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

        register_service(Service("edge", start=edge.start_edge, active=True))

        register_service(Service("acm", start=acm_starter.start_acm))

        register_service(
            Service(
                "apigateway",
                start=apigateway_starter.start_apigateway,
                listener=apigateway_listener.UPDATE_APIGATEWAY,
            )
        )

        register_service(Service("cloudformation", start=start_cloudformation))

        register_service(Service("config", start=configservice_starter.start_configservice))

        register_service(
            Service(
                "cloudwatch",
                start=cloudwatch_starter.start_cloudwatch,
                listener=cloudwatch_listener.UPDATE_CLOUD_WATCH,
            )
        )

        register_service(
            Service(
                "dynamodb",
                start=dynamodb_starter.start_dynamodb,
                check=dynamodb_starter.check_dynamodb,
                listener=dynamodb_listener.UPDATE_DYNAMODB,
            )
        )

        register_service(Service("dynamodbstreams", start=start_dynamodbstreams))

        register_service(
            Service("ec2", start=ec2_starter.start_ec2, listener=ec2_listener.UPDATE_EC2)
        )

        register_service(Service("es", start=es_starter.start_elasticsearch_service))

        register_service(Service("firehose", start=start_firehose))

        register_service(
            Service("iam", start=iam_starter.start_iam, listener=iam_listener.UPDATE_IAM)
        )

        register_service(
            Service("sts", start=sts_starter.start_sts, listener=sts_listener.UPDATE_STS)
        )

        register_service(
            Service(
                "kinesis",
                start=kinesis_starter.start_kinesis,
                check=kinesis_starter.check_kinesis,
                listener=kinesis_listener.UPDATE_KINESIS,
            )
        )

        register_service(
            Service("kms", start=kms_starter.start_kms, listener=kms_listener.UPDATE_KMS)
        )

        register_service(Service("lambda", start=start_lambda))

        register_service(
            Service(
                "logs",
                start=logs_starter.start_cloudwatch_logs,
                listener=logs_listener.UPDATE_LOGS,
            )
        )

        register_service(Service("redshift", start=redshift_starter.start_redshift))

        register_service(
            Service(
                "route53",
                start=route53_starter.start_route53,
                listener=route53_listener.UPDATE_ROUTE53,
            )
        )

        register_service(
            Service(
                "s3",
                start=s3_starter.start_s3,
                check=s3_starter.check_s3,
                listener=s3_listener.UPDATE_S3,
            )
        )

        register_service(
            Service(
                "secretsmanager",
                start=secretsmanager_starter.start_secretsmanager,
                check=secretsmanager_starter.check_secretsmanager,
                listener=secretsmanager_listener.UPDATE_SECRETSMANAGER,
            )
        )

        register_service(
            Service("ses", start=ses_starter.start_ses, listener=ses_listener.UPDATE_SES)
        )

        register_service(Service("sns", start=start_sns, listener=sns_listener.UPDATE_SNS))

        register_service(
            Service(
                "sqs",
                start=sqs_starter.start_sqs,
                listener=sqs_listener.UPDATE_SQS,
                check=sqs_starter.check_sqs,
            )
        )

        register_service(Service("ssm", start=start_ssm, listener=ssm_listener.UPDATE_SSM))

        register_service(Service("sts", start=start_sts))

        register_service(
            Service(
                "events",
                start=events_starter.start_events,
                listener=events_listener.UPDATE_EVENTS,
            )
        )

        register_service(
            Service(
                "stepfunctions",
                start=stepfunctions_starter.start_stepfunctions,
                listener=stepfunctions_listener.UPDATE_STEPFUNCTIONS,
            )
        )

        register_service(
            Service(
                "swf",
                start=swf_starter.start_swf,
                check=swf_starter.check_swf,
                listener=swf_listener.UPDATE_SWF,
            )
        )

        register_service(
            Service(
                "resourcegroupstaggingapi",
                start=rgta_starter.start_rgsa,
                listener=rgta_listener.UPDATE_RGSA,
            )
        )

        register_service(
            Service(
                "resource-groups",
                start=rg_starter.start_rg,
                listener=rg_listener.UPDATE_RG,
            )
        )

        register_service(Service("support", start=support_starter.start_support))

        # apply patches
        patch_request_handling()

    except Exception as e:
        if not os.environ.get(ENV_SCRIPT_STARTING_DOCKER):
            print("Unable to register plugins: %s" % e)
            sys.stdout.flush()
        raise e
