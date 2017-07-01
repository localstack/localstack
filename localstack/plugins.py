from localstack.services.infra import *
from localstack.services.apigateway import apigateway_listener
from localstack.services.cloudformation import cloudformation_listener
from localstack.services.dynamodb import dynamodb_listener, dynamodb_starter
from localstack.services.kinesis import kinesis_listener, kinesis_starter
from localstack.services.sns import sns_listener
from localstack.services.s3 import s3_listener, s3_starter
from localstack.services.es import es_starter


# register default plugins

def register_localstack_plugins():
    try:
        register_plugin(Plugin('es',
            start=start_elasticsearch_service))
        register_plugin(Plugin('elasticsearch',
            start=es_starter.start_elasticsearch,
            check=es_starter.check_elasticsearch))
        register_plugin(Plugin('s3',
            start=start_s3,
            check=s3_starter.check_s3,
            listener=s3_listener.update_s3))
        register_plugin(Plugin('sns',
            start=start_sns,
            listener=sns_listener.update_sns))
        register_plugin(Plugin('sqs',
            start=start_sqs))
        register_plugin(Plugin('ses',
            start=start_ses))
        register_plugin(Plugin('apigateway',
            start=start_apigateway,
            listener=apigateway_listener.update_apigateway))
        register_plugin(Plugin('dynamodb',
            start=dynamodb_starter.start_dynamodb,
            check=dynamodb_starter.check_dynamodb,
            listener=dynamodb_listener.update_dynamodb))
        register_plugin(Plugin('dynamodbstreams',
            start=start_dynamodbstreams))
        register_plugin(Plugin('firehose',
            start=start_firehose))
        register_plugin(Plugin('lambda',
            start=start_lambda))
        register_plugin(Plugin('kinesis',
            start=kinesis_starter.start_kinesis,
            check=kinesis_starter.check_kinesis,
            listener=kinesis_listener.update_kinesis))
        register_plugin(Plugin('redshift',
            start=start_redshift))
        register_plugin(Plugin('route53',
            start=start_route53))
        register_plugin(Plugin('cloudformation',
            start=start_cloudformation,
            listener=cloudformation_listener.update_cloudformation))
        register_plugin(Plugin('cloudwatch',
            start=start_cloudwatch))
    except Exception as e:
        print('Unable to register plugins: %s' % e)
        raise e
