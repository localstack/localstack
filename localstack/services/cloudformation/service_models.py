class BaseModel(object):
    def __init__(self, **params):
        self.params = params

    @classmethod
    def create_from_cloudformation_json(cls, resource_name, cloudformation_json, region_name):
        props = cloudformation_json['Properties']
        return cls(**props)


class CloudFormationStack(BaseModel):
    pass


class EventsRule(BaseModel):
    pass


class ElasticsearchDomain(BaseModel):
    pass


class FirehoseDeliveryStream(BaseModel):
    pass


class GatewayResponse(BaseModel):
    pass


class LogsLogGroup(BaseModel):
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
