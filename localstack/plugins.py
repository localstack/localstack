import sys
from localstack.services.es import es_starter
from localstack.services.s3 import s3_listener, s3_starter
from localstack.services.sns import sns_listener
from localstack.services.sqs import sqs_listener, sqs_starter
from localstack.services.iam import iam_listener
from localstack.services.infra import (register_plugin, Plugin,
    start_sns, start_ses, start_apigateway, start_elasticsearch_service, start_lambda,
    start_redshift, start_firehose, start_cloudwatch, start_dynamodbstreams, start_route53,
    start_ssm, start_sts, start_secretsmanager, start_iam, start_cloudwatch_logs, start_ec2)
from localstack.services.kinesis import kinesis_listener, kinesis_starter
from localstack.services.dynamodb import dynamodb_listener, dynamodb_starter
from localstack.services.apigateway import apigateway_listener
from localstack.services.stepfunctions import stepfunctions_starter, stepfunctions_listener
from localstack.services.cloudformation import cloudformation_listener, cloudformation_starter


# register default plugins

def register_localstack_plugins():
    try:
        register_plugin(Plugin('es',
            start=start_elasticsearch_service))
        register_plugin(Plugin('elasticsearch',
            start=es_starter.start_elasticsearch,
            check=es_starter.check_elasticsearch))
        register_plugin(Plugin('s3',
            start=s3_starter.start_s3,
            check=s3_starter.check_s3,
            listener=s3_listener.UPDATE_S3))
        register_plugin(Plugin('sns',
            start=start_sns,
            listener=sns_listener.UPDATE_SNS))
        register_plugin(Plugin('sqs',
            start=sqs_starter.start_sqs,
            listener=sqs_listener.UPDATE_SQS))
        register_plugin(Plugin('ses',
            start=start_ses))
        register_plugin(Plugin('ssm',
            start=start_ssm))
        register_plugin(Plugin('sts',
            start=start_sts))
        register_plugin(Plugin('iam',
            start=start_iam,
            listener=iam_listener.UPDATE_IAM))
        register_plugin(Plugin('secretsmanager',
            start=start_secretsmanager))
        register_plugin(Plugin('apigateway',
            start=start_apigateway,
            listener=apigateway_listener.UPDATE_APIGATEWAY))
        register_plugin(Plugin('dynamodb',
            start=dynamodb_starter.start_dynamodb,
            check=dynamodb_starter.check_dynamodb,
            listener=dynamodb_listener.UPDATE_DYNAMODB))
        register_plugin(Plugin('dynamodbstreams',
            start=start_dynamodbstreams))
        register_plugin(Plugin('firehose',
            start=start_firehose))
        register_plugin(Plugin('lambda',
            start=start_lambda))
        register_plugin(Plugin('kinesis',
            start=kinesis_starter.start_kinesis,
            check=kinesis_starter.check_kinesis,
            listener=kinesis_listener.UPDATE_KINESIS))
        register_plugin(Plugin('redshift',
            start=start_redshift))
        register_plugin(Plugin('route53',
            start=start_route53))
        register_plugin(Plugin('cloudformation',
            start=cloudformation_starter.start_cloudformation,
            listener=cloudformation_listener.UPDATE_CLOUDFORMATION))
        register_plugin(Plugin('cloudwatch',
            start=start_cloudwatch))
        register_plugin(Plugin('logs',
            start=start_cloudwatch_logs))
        register_plugin(Plugin('stepfunctions',
            start=stepfunctions_starter.start_stepfunctions,
            listener=stepfunctions_listener.UPDATE_STEPFUNCTIONS))
        register_plugin(Plugin('ec2',
            start=start_ec2))
    except Exception as e:
        print('Unable to register plugins: %s' % e)
        sys.stdout.flush()
        raise e
