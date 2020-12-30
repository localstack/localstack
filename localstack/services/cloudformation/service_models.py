from moto.s3.models import FakeBucket
from moto.sqs.models import Queue as MotoQueue
from moto.iam.models import Role as MotoRole
from moto.core.models import CloudFormationModel
from moto.cloudformation.exceptions import UnformattedGetAttTemplateException
from localstack.utils.aws import aws_stack
from localstack.utils.common import camel_to_snake_case


class BaseModel(CloudFormationModel):
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


class GenericBaseObject(BaseModel):
    """ Abstract base class representing a resource model class in LocalStack.
        This class keeps references to a combination of (1) the CF resource
        properties (as defined in the template), and (2) the current deployment
        state of a resource.

        Concrete subclasses will implement convenience methods to manage resources,
        e.g., fetching the latest deployment state, getting the resource name, etc.
    """

    def __init__(self, resource_name, resource_json, region_name=None, **params):
        self.region_name = region_name or aws_stack.get_region()
        self.resource_name = resource_name
        self.resource_json = resource_json
        self.resource_type = resource_json['Type']
        # properties, as defined in the template
        self.properties = resource_json.get('Properties') or {}
        # state, as determined from the deployed resource
        self.state = {}
        # TODO remove physical_resource_id attribute from all subclasses entirely?
        self.physical_resource_id = self.resource_json.get('PhysicalResourceId')

    def get_cfn_attribute(self, attribute_name):
        """ Retrieve the given CF attribute for this resource (inherited from moto's CloudFormationModel) """
        if attribute_name in ['Arn', 'Ref'] and hasattr(self, 'arn'):
            return self.arn
        if attribute_name in ['PhysicalResourceId', 'Ref']:
            if self.resource_json.get('PhysicalResourceId'):
                self.physical_resource_id = self.resource_json.get('PhysicalResourceId')
            if self.physical_resource_id:
                return self.physical_resource_id
        props = self.props
        if attribute_name in props:
            return props.get(attribute_name)

        raise UnformattedGetAttTemplateException()

    def update_state(self, details):
        """ Update the deployment state of this resource (existing attributes will be overwritten). """
        details = details or {}
        update_props = {k: v for k, v in details.items() if k not in self.props}
        self.props.update(update_props)
        return self.props

    def set_resource_state(self, state):
        """ Return the deployment state of this resource. """
        self.state = state or {}

    def get_resource_name(self):
        """ Return the name of this resource, based on its properties (to be overwritten by subclass) """
        return None

    @property
    def props(self):
        """ Return a copy of (1) the resource properties (from the template), combined with
            (2) the current deployment state properties of the resource. """
        result = dict(self.properties)
        result.update(self.state or {})
        return result

    @classmethod
    def update_from_cloudformation_json(cls,
            original_resource, new_resource_name, cloudformation_json, region_name):
        props = cloudformation_json.get('Properties', {})
        for key, val in props.items():
            snake_key = camel_to_snake_case(key)
            lower_key = key.lower()
            for candidate in [key, lower_key, snake_key]:
                if hasattr(original_resource, candidate) or candidate == snake_key:
                    setattr(original_resource, candidate, val)
                    break
        return original_resource

    @classmethod
    def create_from_cloudformation_json(cls, resource_name, resource_json, region_name):
        return cls(resource_name=resource_name, resource_json=resource_json, region_name=region_name)


class EventsRule(BaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::Events::Rule'

    def get_cfn_attribute(self, attribute_name):
        if attribute_name == 'Arn':
            return self.params.get('Arn') or aws_stack.events_rule_arn(self.params.get('Name'))
        return super(EventsRule, self).get_cfn_attribute(attribute_name)


class LogsLogGroup(BaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::Logs::LogGroup'

    def get_cfn_attribute(self, attribute_name):
        if attribute_name == 'Arn':
            return self.params.get('Arn') or aws_stack.log_group_arn(self.params.get('LogGroupName'))
        return super(LogsLogGroup, self).get_cfn_attribute(attribute_name)


class CloudFormationStack(BaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::CloudFormation::Stack'


class ElasticsearchDomain(BaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::Elasticsearch::Domain'


class FirehoseDeliveryStream(BaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::KinesisFirehose::DeliveryStream'


class SFNStateMachine(BaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::StepFunctions::StateMachine'

    def get_resource_name(self):
        return self.props.get('StateMachineName')


class IAMRole(BaseModel, MotoRole):

    def get_resource_name(self):
        return self.props.get('RoleName')


class GatewayResponse(BaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::ApiGateway::GatewayResponse'


class S3Bucket(GenericBaseObject, FakeBucket):
    def get_resource_name(self):
        return self.normalize_bucket_name(self.props.get('BucketName'))

    @staticmethod
    def normalize_bucket_name(bucket_name):
        bucket_name = bucket_name or ''
        # AWS automatically converts upper to lower case chars in bucket names
        bucket_name = bucket_name.lower()
        return bucket_name


class S3BucketPolicy(BaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::S3::BucketPolicy'


class StepFunctionsActivity(BaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::StepFunctions::Activity'


class SNSSubscription(GenericBaseObject):
    @staticmethod
    def cloudformation_type():
        return 'AWS::SNS::Subscription'


class SQSQueue(GenericBaseObject, MotoQueue):
    def get_resource_name(self):
        return self.props.get('QueueName')


class SSMParameter(BaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::SSM::Parameter'


class SecretsManagerSecret(BaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::SecretsManager::Secret'
