from moto.s3.models import FakeBucket
from moto.sqs.models import Queue as MotoQueue
from moto.iam.models import Role as MotoRole
from moto.core.models import CloudFormationModel
from moto.cloudformation.exceptions import UnformattedGetAttTemplateException
from localstack.utils.aws import aws_stack
from localstack.utils.common import camel_to_snake_case


class DependencyNotYetSatisfied(Exception):
    """ Exception indicating that a resource dependency is not (yet) deployed/available. """
    def __init__(self, resource_ids, message=None):
        message = message or 'Unresolved dependencies: %s' % resource_ids
        super(DependencyNotYetSatisfied, self).__init__(message)
        resource_ids = resource_ids if isinstance(resource_ids, list) else [resource_ids]
        self.resource_ids = resource_ids


# TODO remove?
# class BaseModel(CloudFormationModel):
#     def __init__(self, **params):
#         self.params = params
#
#     @classmethod
#     def create_from_cloudformation_json(cls, resource_name, cloudformation_json, region_name):
#         props = cloudformation_json['Properties']
#         return cls(**props)
#
#     def get_cfn_attribute(self, attribute_name):
#         attr = self.params.get(attribute_name)
#         if attr is None:
#             attr = getattr(self, attribute_name.lower(), None)
#             if attr is None:
#                 raise UnformattedGetAttTemplateException()
#         return attr


class GenericBaseModel(CloudFormationModel):
    """ Abstract base class representing a resource model class in LocalStack.
        This class keeps references to a combination of (1) the CF resource
        properties (as defined in the template), and (2) the current deployment
        state of a resource.

        Concrete subclasses will implement convenience methods to manage resources,
        e.g., fetching the latest deployment state, getting the resource name, etc.
    """

    def __init__(self, resource_json, region_name=None, **params):
        self.region_name = region_name or aws_stack.get_region()
        self.resource_json = resource_json
        self.resource_type = resource_json['Type']
        # properties, as defined in the template
        self.properties = resource_json.get('Properties') or {}
        # state, as determined from the deployed resource
        self.state = {}

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
        """ Return the name of this resource, based on its properties (to be overwritten by subclasses) """
        return None

    def get_physical_resource_id(self, attribute=None, **kwargs):
        """ Determine the physical resource ID (Ref) of this resource (to be overwritten by subclasses) """
        return None

    @property
    def physical_resource_id(self):
        """ Return the (cached) physical resource ID. """
        return self.resource_json.get('PhysicalResourceId')

    # TODO: change the signature to pass in a Stack instance (instead of stack_name and resources)
    def fetch_state(self, stack_name, resources):
        """ Fetch the latest deployment state of this resource, or return None if not currently deployed. """
        return None

    @property
    def props(self):
        """ Return a copy of (1) the resource properties (from the template), combined with
            (2) the current deployment state properties of the resource. """
        result = dict(self.properties)
        result.update(self.state or {})
        return result

    @property
    def resource_id(self):
        """ Return the logical resource ID of this resource (i.e., the ref. name within the stack's resources). """
        return self.resource_json['LogicalResourceId']

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

    def resolve_refs_recursively(self, stack_name, value, resources):
        # TODO: restructure code to avoid circular import here
        from localstack.utils.cloudformation.template_deployer import resolve_refs_recursively
        return resolve_refs_recursively(stack_name, value, resources)


class EventsRule(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::Events::Rule'

    def get_cfn_attribute(self, attribute_name):
        if attribute_name == 'Arn':
            return self.params.get('Arn') or aws_stack.events_rule_arn(self.params.get('Name'))
        return super(EventsRule, self).get_cfn_attribute(attribute_name)

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get('Name')


class LogsLogGroup(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::Logs::LogGroup'

    def get_cfn_attribute(self, attribute_name):
        if attribute_name == 'Arn':
            return self.params.get('Arn') or aws_stack.log_group_arn(self.params.get('LogGroupName'))
        return super(LogsLogGroup, self).get_cfn_attribute(attribute_name)

    def fetch_state(self, stack_name, resources):
        group_name = self.props.get('LogGroupName')
        group_name = self.resolve_refs_recursively(stack_name, group_name, resources)
        logs = aws_stack.connect_to_service('logs')
        groups = logs.describe_log_groups(logGroupNamePrefix=group_name)['logGroups']
        return ([g for g in groups if g['logGroupName'] == group_name] or [None])[0]


class CloudFormationStack(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::CloudFormation::Stack'


class LambdaFunction(GenericBaseModel):

    @staticmethod
    def cloudformation_type():
        return 'AWS::Lambda::Function'

    def fetch_state(self, stack_name, resources):
        func_name = self.resolve_refs_recursively(stack_name, self.props['FunctionName'], resources)
        return aws_stack.connect_to_service('lambda').get_function(FunctionName=func_name)

    def get_physical_resource_id(self, attribute=None, **kwargs):
        func_name = self.props.get('FunctionName')
        if attribute == 'Arn':
            return aws_stack.lambda_function_arn(func_name)
        return func_name


class LambdaFunctionVersion(GenericBaseModel):

    def fetch_state(self, stack_name, resources):
        name = self.resolve_refs_recursively(stack_name, self.props.get('FunctionName'), resources)
        if not name:
            return None
        func_name = aws_stack.lambda_function_name(name)
        func_version = name.split(':')[7] if len(name.split(':')) > 7 else '$LATEST'
        versions = aws_stack.connect_to_service('lambda').list_versions_by_function(FunctionName=func_name)
        return ([v for v in versions['Versions'] if v['Version'] == func_version] or [None])[0]

    @staticmethod
    def cloudformation_type():
        return 'AWS::Lambda::Version'


class ElasticsearchDomain(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::Elasticsearch::Domain'

    def fetch_state(self, stack_name, resources):
        domain_name = self.props.get('DomainName') or self.resource_id
        domain_name = self.resolve_refs_recursively(stack_name, domain_name, resources)
        return aws_stack.connect_to_service('es').describe_elasticsearch_domain(DomainName=domain_name)


class FirehoseDeliveryStream(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::KinesisFirehose::DeliveryStream'

    def fetch_state(self, stack_name, resources):
        stream_name = self.props.get('DeliveryStreamName') or self.resource_id
        stream_name = self.resolve_refs_recursively(stack_name, stream_name, resources)
        return aws_stack.connect_to_service('firehose').describe_delivery_stream(DeliveryStreamName=stream_name)


class KinesisStream(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::Kinesis::Stream'

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return aws_stack.kinesis_stream_arn(self.props.get('Name'))

    def fetch_state(self, stack_name, resources):
        stream_name = self.resolve_refs_recursively(stack_name, self.props['Name'], resources)
        result = aws_stack.connect_to_service('kinesis').describe_stream(StreamName=stream_name)
        return result


class SFNStateMachine(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::StepFunctions::StateMachine'

    def get_resource_name(self):
        return self.props.get('StateMachineName')

    def fetch_state(self, stack_name, resources):
        sm_name = self.props.get('StateMachineName') or self.resource_id
        sm_name = self.resolve_refs_recursively(stack_name, sm_name, resources)
        sfn_client = aws_stack.connect_to_service('stepfunctions')
        state_machines = sfn_client.list_state_machines()['stateMachines']
        sm_arn = [m['stateMachineArn'] for m in state_machines if m['name'] == sm_name]
        if not sm_arn:
            return None
        result = sfn_client.describe_state_machine(stateMachineArn=sm_arn[0])
        return result


class SFNActivity(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::StepFunctions::Activity'

    def fetch_state(self, stack_name, resources):
        act_name = self.props.get('Name') or self.resource_id
        act_name = self.resolve_refs_recursively(stack_name, act_name, resources)
        sfn_client = aws_stack.connect_to_service('stepfunctions')
        activities = sfn_client.list_activities()['activities']
        result = [a['activityArn'] for a in activities if a['name'] == act_name]
        if not result:
            return None
        return result[0]


class IAMRole(GenericBaseModel, MotoRole):
    def get_resource_name(self):
        return self.props.get('RoleName')


class IAMPolicy(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::IAM::Policy'

    def fetch_state(self, stack_name, resources):
        def _filter(pols):
            return [p for p in pols['AttachedPolicies'] if p['PolicyName'] == policy_name]
        iam = aws_stack.connect_to_service('iam')
        props = self.props
        policy_name = props['PolicyName']
        # The policy in cloudformation is InlinePolicy, which can be attached to either of [Roles, Users, Groups]
        # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html
        result = {}
        roles = props.get('Roles', [])
        users = props.get('Users', [])
        groups = props.get('Groups', [])
        for role in roles:
            role = self.resolve_refs_recursively(stack_name, role, resources)
            result['role:%s' % role] = _filter(iam.list_attached_role_policies(RoleName=role))
        for user in users:
            user = self.resolve_refs_recursively(stack_name, user, resources)
            result['user:%s' % user] = _filter(iam.list_attached_user_policies(UserName=user))
        for group in groups:
            group = self.resolve_refs_recursively(stack_name, group, resources)
            result['group:%s' % group] = _filter(iam.list_attached_group_policies(GroupName=group))
        return {k: v for k, v in result.items() if v}


class GatewayResponse(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::ApiGateway::GatewayResponse'


class S3Bucket(GenericBaseModel, FakeBucket):
    def get_resource_name(self):
        return self.normalize_bucket_name(self.props.get('BucketName'))

    @staticmethod
    def normalize_bucket_name(bucket_name):
        bucket_name = bucket_name or ''
        # AWS automatically converts upper to lower case chars in bucket names
        bucket_name = bucket_name.lower()
        return bucket_name

    def fetch_state(self, stack_name, resources):
        props = self.props
        bucket_name = props.get('BucketName') or self.resource_id
        bucket_name = self.resolve_refs_recursively(stack_name, bucket_name, resources)
        bucket_name = self.normalize_bucket_name(bucket_name)
        s3_client = aws_stack.connect_to_service('s3')
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        notifs = props.get('NotificationConfiguration')
        if not response or not notifs:
            return response
        configs = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
        has_notifs = (configs.get('TopicConfigurations') or configs.get('QueueConfigurations') or
            configs.get('LambdaFunctionConfigurations'))
        if notifs and not has_notifs:
            return None
        return response


class S3BucketPolicy(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::S3::BucketPolicy'

    def fetch_state(self, stack_name, resources):
        bucket_name = self.props.get('Bucket') or self.resource_id
        bucket_name = self.resolve_refs_recursively(stack_name, bucket_name, resources)
        return aws_stack.connect_to_service('s3').get_bucket_policy(Bucket=bucket_name)


class StepFunctionsActivity(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::StepFunctions::Activity'


class SQSQueue(GenericBaseModel, MotoQueue):
    def get_resource_name(self):
        return self.props.get('QueueName')

    def get_physical_resource_id(self, attribute=None, **kwargs):
        queue_url = None
        props = self.props
        try:
            queue_url = aws_stack.get_sqs_queue_url(props.get('QueueName'))
        except Exception as e:
            if 'NonExistentQueue' in str(e):
                raise DependencyNotYetSatisfied(resource_ids=self.resource_id, message='Unable to get queue: %s' % e)
        if attribute == 'Arn':
            return aws_stack.sqs_queue_arn(props.get('QueueName'))
        return queue_url

    def fetch_state(self, stack_name, resources):
        queue_name = self.resolve_refs_recursively(stack_name, self.props['QueueName'], resources)
        sqs_client = aws_stack.connect_to_service('sqs')
        queues = sqs_client.list_queues()
        result = list(filter(lambda item:
            # TODO possibly find a better way to compare resource_id with queue URLs
            item.endswith('/%s' % queue_name), queues.get('QueueUrls', [])))
        if not result:
            return None
        result = sqs_client.get_queue_attributes(QueueUrl=result[0], AttributeNames=['All'])['Attributes']
        result['Arn'] = result['QueueArn']
        return result


class SNSTopic(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::SNS::Topic'

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return aws_stack.sns_topic_arn(self.props.get('TopicName'))

    def fetch_state(self, stack_name, resources):
        topic_name = self.resolve_refs_recursively(stack_name, self.props['TopicName'], resources)
        topics = aws_stack.connect_to_service('sns').list_topics()
        result = list(filter(lambda item: item['TopicArn'].split(':')[-1] == topic_name, topics.get('Topics', [])))
        return result[0] if result else None


class SNSSubscription(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::SNS::Subscription'

    def fetch_state(self, stack_name, resources):
        props = self.props
        topic_arn = props.get('TopicArn')
        topic_arn = self.resolve_refs_recursively(stack_name, topic_arn, resources)
        if topic_arn is None:
            return
        subs = aws_stack.connect_to_service('sns').list_subscriptions_by_topic(TopicArn=topic_arn)
        result = [sub for sub in subs['Subscriptions'] if
            props.get('Protocol') == sub['Protocol'] and props.get('Endpoint') == sub['Endpoint']]
        # TODO: use get_subscription_attributes to compare FilterPolicy
        return result[0] if result else None


class SSMParameter(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::SSM::Parameter'


class SecretsManagerSecret(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::SecretsManager::Secret'

    def fetch_state(self, stack_name, resources):
        secret_name = self.props.get('Name') or self.resource_id
        secret_name = self.resolve_refs_recursively(stack_name, secret_name, resources)
        return aws_stack.connect_to_service('secretsmanager').describe_secret(SecretId=secret_name)
