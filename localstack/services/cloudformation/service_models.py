from moto.cloudformation.exceptions import UnformattedGetAttTemplateException
from localstack.utils.aws import aws_stack


class BaseModel(object):
    def __init__(self, **params):
        self.params = params

    @classmethod
    def create_from_cloudformation_json(cls, resource_name, cloudformation_json, region_name):
        props = cloudformation_json['Properties']
        return cls(**props)

    def get_cfn_attribute(self, attribute_name):
        attr = self.params.get(attribute_name)
        if attr is None:
            attr = getattr(self, attribute_name.lower(), None)
            if attr is None:
                raise UnformattedGetAttTemplateException()
        return attr


class EventsRule(BaseModel):
    def get_cfn_attribute(self, attribute_name):
        if attribute_name == 'Arn':
            return self.params.get('Arn') or aws_stack.events_rule_arn(self.params.get('Name'))
        return super(EventsRule, self).get_cfn_attribute(attribute_name)


class LogsLogGroup(BaseModel):

    def get_cfn_attribute(self, attribute_name):
        if attribute_name == 'Arn':
            return self.params.get('Arn') or aws_stack.log_group_arn(self.params.get('LogGroupName'))
        return super(LogsLogGroup, self).get_cfn_attribute(attribute_name)


class CloudFormationStack(BaseModel):
    pass


class ElasticsearchDomain(BaseModel):
    pass


class FirehoseDeliveryStream(BaseModel):
    pass


class GatewayResponse(BaseModel):
    pass


class S3BucketPolicy(BaseModel):
    pass


class StepFunctionsActivity(BaseModel):
    pass


class SNSSubscription(BaseModel):
    pass


class SSMParameter(BaseModel):
    pass


class SecretsManagerSecret(BaseModel):
    pass
