import re
import logging
from moto.s3.models import FakeBucket
from moto.sqs.models import Queue as MotoQueue
from moto.iam.models import Role as MotoRole
from moto.core.models import CloudFormationModel
from moto.cloudformation.exceptions import UnformattedGetAttTemplateException
from localstack.constants import AWS_REGION_US_EAST_1, LOCALHOST
from localstack.utils.aws import aws_stack
from localstack.utils.common import camel_to_snake_case

LOG = logging.getLogger(__name__)

# name pattern of IAM policies associated with Lambda functions
LAMBDA_POLICY_NAME_PATTERN = 'lambda_policy_%s'

# placeholders
PLACEHOLDER_RESOURCE_NAME = '__resource_name__'
PLACEHOLDER_AWS_NO_VALUE = '__aws_no_value__'

# ref attribute definitions
REF_ATTRS = ['PhysicalResourceId', 'Ref']
REF_ID_ATTRS = REF_ATTRS + ['Id']
REF_ARN_ATTRS = ['Ref', 'Arn']


class DependencyNotYetSatisfied(Exception):
    """ Exception indicating that a resource dependency is not (yet) deployed/available. """
    def __init__(self, resource_ids, message=None):
        message = message or 'Unresolved dependencies: %s' % resource_ids
        super(DependencyNotYetSatisfied, self).__init__(message)
        resource_ids = resource_ids if isinstance(resource_ids, list) else [resource_ids]
        self.resource_ids = resource_ids


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

    # ----------------------
    # ABSTRACT BASE METHODS
    # ----------------------

    def set_resource_state(self, state):
        """ Return the deployment state of this resource. """
        self.state = state or {}

    def get_resource_name(self):
        """ Return the name of this resource, based on its properties (to be overwritten by subclasses) """
        return None

    def get_physical_resource_id(self, attribute=None, **kwargs):
        """ Determine the physical resource ID (Ref) of this resource (to be overwritten by subclasses) """
        return None

    # TODO: change the signature to pass in a Stack instance (instead of stack_name and resources)
    def fetch_state(self, stack_name, resources):
        """ Fetch the latest deployment state of this resource, or return None if not currently deployed. """
        return None

    # TODO: change the signature to pass in a Stack instance (instead of stack_name and resources)
    def update_resource(self, new_resource, stack_name, resources):
        """ Update the deployment of this resource, using the updated properties (implemented by subclasses). """
        pass

    @staticmethod
    def get_deploy_templates():
        """ Return template configurations used to create the final API requests (implemented by subclasses). """
        pass

    # ----------------------
    # GENERIC BASE METHODS
    # ----------------------

    def get_cfn_attribute(self, attribute_name):
        """ Retrieve the given CF attribute for this resource (inherited from moto's CloudFormationModel) """
        if attribute_name in REF_ARN_ATTRS and hasattr(self, 'arn'):
            return self.arn
        if attribute_name in REF_ATTRS:
            result = self.get_physical_resource_id(attribute=attribute_name)
            if result:
                return result
        props = self.props
        if attribute_name in props:
            return props.get(attribute_name)

        raise UnformattedGetAttTemplateException()

    # ----------------------
    # GENERIC UTIL METHODS
    # ----------------------

    def update_state(self, details):
        """ Update the deployment state of this resource (existing attributes will be overwritten). """
        details = details or {}
        update_props = {k: v for k, v in details.items() if k not in self.props}
        self.props.update(update_props)
        return self.props

    @property
    def physical_resource_id(self):
        """ Return the (cached) physical resource ID. """
        return self.resource_json.get('PhysicalResourceId')

    @property
    def logical_resource_id(self):
        """ Return the logical resource ID. """
        return self.resource_json.get('LogicalResourceId')

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

    def fetch_state(self, stack_name, resources):
        rule_name = self.resolve_refs_recursively(stack_name, self.props.get('Name'), resources)
        result = aws_stack.connect_to_service('events').describe_rule(Name=rule_name) or {}
        return result if result.get('Name') else None


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

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get('StackId')

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service('cloudformation')
        child_stack_name = self.props['StackName']
        child_stack_name = self.resolve_refs_recursively(stack_name, child_stack_name, resources)
        result = client.describe_stacks(StackName=child_stack_name)
        result = (result.get('Stacks') or [None])[0]
        return result

    @classmethod
    def get_deploy_templates(cls):
        def get_nested_stack_params(params, **kwargs):
            nested_stack_name = params['StackName']
            stack_params = params.get('Parameters', {})
            stack_params = [{'ParameterKey': k, 'ParameterValue': str(v).lower() if isinstance(v, bool) else str(v)}
                for k, v in stack_params.items()]
            result = {
                'StackName': nested_stack_name,
                'TemplateURL': params.get('TemplateURL'),
                'Parameters': stack_params
            }
            return result

        return {
            'create': {
                'function': 'create_stack',
                'parameters': get_nested_stack_params
            }
        }


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

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource['Properties']
        client = aws_stack.connect_to_service('lambda')
        keys = ('FunctionName', 'Role', 'Handler', 'Description', 'Timeout', 'MemorySize', 'Environment', 'Runtime')
        update_props = dict([(k, props[k]) for k in keys if k in props])
        update_props = self.resolve_refs_recursively(stack_name, update_props, resources)
        if 'Code' in props:
            code = props['Code'] or {}
            if not code.get('ZipFile'):
                LOG.debug('Updating code for Lambda "%s" from location: %s' % (props['FunctionName'], code))
            client.update_function_code(FunctionName=props['FunctionName'], **code)
        if 'Environment' in update_props:
            environment_variables = update_props['Environment'].get('Variables', {})
            update_props['Environment']['Variables'] = {k: str(v) for k, v in environment_variables.items()}
        return client.update_function_configuration(**update_props)


class LambdaFunctionVersion(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::Lambda::Version'

    def fetch_state(self, stack_name, resources):
        name = self.resolve_refs_recursively(stack_name, self.props.get('FunctionName'), resources)
        if not name:
            return None
        func_name = aws_stack.lambda_function_name(name)
        func_version = name.split(':')[7] if len(name.split(':')) > 7 else '$LATEST'
        versions = aws_stack.connect_to_service('lambda').list_versions_by_function(FunctionName=func_name)
        return ([v for v in versions['Versions'] if v['Version'] == func_version] or [None])[0]


class LambdaEventSourceMapping(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::Lambda::EventSourceMapping'

    def fetch_state(self, stack_name, resources):
        props = self.props
        resource_id = props['FunctionName'] or self.resource_id
        source_arn = props.get('EventSourceArn')
        resource_id = self.resolve_refs_recursively(stack_name, resource_id, resources)
        source_arn = self.resolve_refs_recursively(stack_name, source_arn, resources)
        if not resource_id or not source_arn:
            raise Exception('ResourceNotFound')
        mappings = aws_stack.connect_to_service('lambda').list_event_source_mappings(
            FunctionName=resource_id, EventSourceArn=source_arn)
        mapping = list(filter(lambda m:
            m['EventSourceArn'] == source_arn and m['FunctionArn'] == aws_stack.lambda_function_arn(resource_id),
            mappings['EventSourceMappings']))
        if not mapping:
            raise Exception('ResourceNotFound')
        return mapping[0]


class LambdaPermission(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::Lambda::Permission'

    def fetch_state(self, stack_name, resources):
        iam = aws_stack.connect_to_service('iam')
        props = self.props
        policy_name = LAMBDA_POLICY_NAME_PATTERN % props.get('FunctionName')
        policy_arn = aws_stack.policy_arn(policy_name)
        policy = iam.get_policy(PolicyArn=policy_arn)['Policy']
        version = policy.get('DefaultVersionId')
        policy = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version)['PolicyVersion']
        statements = policy['Document']['Statement']
        statements = statements if isinstance(statements, list) else [statements]
        func_arn = aws_stack.lambda_function_arn(props['FunctionName'])
        principal = props.get('Principal')
        existing = [s for s in statements if s['Action'] == props['Action'] and
            s['Resource'] == func_arn and
            (not principal or s['Principal'] in [{'Service': principal}, {'Service': [principal]}])]
        return existing[0] if existing else None


class ElasticsearchDomain(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::Elasticsearch::Domain'

    def get_physical_resource_id(self, attribute=None, **kwargs):
        domain_name = self._domain_name()
        if attribute == 'Arn':
            return aws_stack.elasticsearch_domain_arn(domain_name)
        return domain_name

    def fetch_state(self, stack_name, resources):
        domain_name = self._domain_name()
        domain_name = self.resolve_refs_recursively(stack_name, domain_name, resources)
        return aws_stack.connect_to_service('es').describe_elasticsearch_domain(DomainName=domain_name)

    def _domain_name(self):
        return self.props.get('DomainName') or self.resource_id


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

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource['Properties']
        client = aws_stack.connect_to_service('stepfunctions')
        sm_arn = self.props.get('stateMachineArn')
        if not sm_arn:
            self.state = self.fetch_state(stack_name=stack_name, resources=resources)
            sm_arn = self.state['stateMachineArn']
        kwargs = {
            'stateMachineArn': sm_arn,
            'definition': props['DefinitionString'],
        }
        return client.update_state_machine(**kwargs)


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
    @staticmethod
    def cloudformation_type():
        return 'AWS::IAM::Role'

    def get_resource_name(self):
        return self.props.get('RoleName')

    def fetch_state(self, stack_name, resources):
        role_name = self.resolve_refs_recursively(stack_name, self.props.get('RoleName'), resources)
        return aws_stack.connect_to_service('iam').get_role(RoleName=role_name)['Role']

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource['Properties']
        client = aws_stack.connect_to_service('iam')
        return client.update_role(RoleName=props.get('RoleName'), Description=props.get('Description') or '')


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

    def fetch_state(self, stack_name, resources):
        props = self.props
        api_id = self.resolve_refs_recursively(stack_name, props['RestApiId'], resources)
        if not api_id:
            return
        client = aws_stack.connect_to_service('apigateway')
        result = client.get_gateway_response(restApiId=api_id, responseType=props['ResponseType'])
        return result if 'responseType' in result else None


class GatewayRestAPI(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::ApiGateway::RestApi'

    def fetch_state(self, stack_name, resources):
        apis = aws_stack.connect_to_service('apigateway').get_rest_apis()['items']
        api_name = self.props.get('Name') or self.resource_id
        api_name = self.resolve_refs_recursively(stack_name, api_name, resources)
        result = list(filter(lambda api: api['name'] == api_name, apis))
        return result[0] if result else None


class GatewayDeployment(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::ApiGateway::Deployment'

    def fetch_state(self, stack_name, resources):
        api_id = self.props['RestApiId'] or self.resource_id
        api_id = self.resolve_refs_recursively(stack_name, api_id, resources)
        if not api_id:
            return None
        result = aws_stack.connect_to_service('apigateway').get_deployments(restApiId=api_id)['items']
        # TODO possibly filter results by stage name or other criteria
        return result[0] if result else None


class GatewayResource(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::ApiGateway::Resource'

    def fetch_state(self, stack_name, resources):
        props = self.props
        api_id = props.get('RestApiId') or self.resource_id
        api_id = self.resolve_refs_recursively(stack_name, api_id, resources)
        parent_id = self.resolve_refs_recursively(stack_name, props.get('ParentId'), resources)
        if not api_id or not parent_id:
            return None
        api_resources = aws_stack.connect_to_service('apigateway').get_resources(restApiId=api_id)['items']
        target_resource = list(filter(lambda res:
            res.get('parentId') == parent_id and res['pathPart'] == props['PathPart'], api_resources))
        if not target_resource:
            return None
        path = aws_stack.get_apigateway_path_for_resource(api_id,
            target_resource[0]['id'], resources=api_resources)
        result = list(filter(lambda res: res['path'] == path, api_resources))
        return result[0] if result else None


class GatewayMethod(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::ApiGateway::Method'

    def fetch_state(self, stack_name, resources):
        props = self.props
        api_id = self.resolve_refs_recursively(stack_name, props['RestApiId'], resources)
        res_id = self.resolve_refs_recursively(stack_name, props['ResourceId'], resources)
        if not api_id or not res_id:
            return None
        res_obj = aws_stack.connect_to_service('apigateway').get_resource(restApiId=api_id, resourceId=res_id)
        match = [v for (k, v) in res_obj.get('resourceMethods', {}).items()
                 if props['HttpMethod'] in (v.get('httpMethod'), k)]
        int_props = props.get('Integration') or {}
        if int_props.get('Type') == 'AWS_PROXY':
            match = [m for m in match if
                m.get('methodIntegration', {}).get('type') == 'AWS_PROXY' and
                m.get('methodIntegration', {}).get('httpMethod') == int_props.get('IntegrationHttpMethod')]
        return match[0] if match else None

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource['Properties']
        client = aws_stack.connect_to_service('apigateway')
        integration = props.get('Integration')
        kwargs = {
            'restApiId': props['RestApiId'],
            'resourceId': props['ResourceId'],
            'httpMethod': props['HttpMethod'],
            'requestParameters': props.get('RequestParameters') or {}
        }
        if integration:
            kwargs['type'] = integration['Type']
            kwargs['integrationHttpMethod'] = integration.get('IntegrationHttpMethod')
            kwargs['uri'] = integration.get('Uri')
            return client.put_integration(**kwargs)
        kwargs['authorizationType'] = props.get('AuthorizationType')

        return client.put_method(**kwargs)

    def get_physical_resource_id(self, attribute=None, **kwargs):
        props = self.props
        result = '%s-%s-%s' % (props.get('RestApiId'), props.get('ResourceId'), props.get('HttpMethod'))
        return result


class GatewayStage(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::ApiGateway::Stage'

    def fetch_state(self, stack_name, resources):
        api_id = self.props.get('RestApiId') or self.resource_id
        api_id = self.resolve_refs_recursively(stack_name, api_id, resources)
        if not api_id:
            return None
        result = aws_stack.connect_to_service('apigateway').get_stage(restApiId=api_id,
            stageName=self.props['StageName'])
        return result


class S3Bucket(GenericBaseModel, FakeBucket):
    def get_resource_name(self):
        return self.normalize_bucket_name(self.props.get('BucketName'))

    @staticmethod
    def normalize_bucket_name(bucket_name):
        bucket_name = bucket_name or ''
        # AWS automatically converts upper to lower case chars in bucket names
        bucket_name = bucket_name.lower()
        return bucket_name

    @staticmethod
    def get_deploy_templates():

        def convert_acl_cf_to_s3(acl):
            """ Convert a CloudFormation ACL string (e.g., 'PublicRead') to an S3 ACL string (e.g., 'public-read') """
            return re.sub('(?<!^)(?=[A-Z])', '-', acl).lower()

        def s3_bucket_notification_config(params, **kwargs):
            notif_config = params.get('NotificationConfiguration')
            if not notif_config:
                return None

            lambda_configs = []
            queue_configs = []
            topic_configs = []

            attr_tuples = (
                ('LambdaConfigurations', lambda_configs, 'LambdaFunctionArn', 'Function'),
                ('QueueConfigurations', queue_configs, 'QueueArn', 'Queue'),
                ('TopicConfigurations', topic_configs, 'TopicArn', 'Topic')
            )

            # prepare lambda/queue/topic notification configs
            for attrs in attr_tuples:
                for notif_cfg in notif_config.get(attrs[0]) or []:
                    filter_rules = notif_cfg.get('Filter', {}).get('S3Key', {}).get('Rules')
                    entry = {
                        attrs[2]: notif_cfg[attrs[3]],
                        'Events': [notif_cfg['Event']]
                    }
                    if filter_rules:
                        entry['Filter'] = {'Key': {'FilterRules': filter_rules}}
                    attrs[1].append(entry)

            # construct final result
            result = {
                'Bucket': params.get('BucketName') or PLACEHOLDER_RESOURCE_NAME,
                'NotificationConfiguration': {
                    'LambdaFunctionConfigurations': lambda_configs,
                    'QueueConfigurations': queue_configs,
                    'TopicConfigurations': topic_configs
                }
            }
            return result

        def get_bucket_location_config(**kwargs):
            region = aws_stack.get_region()
            if region == AWS_REGION_US_EAST_1:
                return None
            return {'LocationConstraint': region}

        result = {
            'create': [{
                'function': 'create_bucket',
                'parameters': {
                    'Bucket': ['BucketName', PLACEHOLDER_RESOURCE_NAME],
                    'ACL': lambda params, **kwargs: convert_acl_cf_to_s3(params.get('AccessControl', 'PublicRead')),
                    'CreateBucketConfiguration': lambda params, **kwargs: get_bucket_location_config()
                }
            }, {
                'function': 'put_bucket_notification_configuration',
                'parameters': s3_bucket_notification_config
            }],
            'delete': [{
                'function': 'delete_bucket',
                'parameters': {
                    'Bucket': 'BucketName'
                }
            }]
        }
        return result

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

    def get_cfn_attribute(self, attribute_name):
        if attribute_name == 'RegionalDomainName':
            return LOCALHOST
        return super(S3Bucket, self).get_cfn_attribute(attribute_name)


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
    @staticmethod
    def cloudformation_type():
        return 'AWS::SQS::Queue'

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


class DynamoDBTable(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::DynamoDB::Table'

    def get_physical_resource_id(self, attribute=None, **kwargs):
        table_name = self.props.get('TableName')
        if attribute in REF_ID_ATTRS:
            return table_name
        return aws_stack.dynamodb_table_arn(table_name)

    def fetch_state(self, stack_name, resources):
        table_name = self.props.get('TableName') or self.resource_id
        table_name = self.resolve_refs_recursively(stack_name, table_name, resources)
        return aws_stack.connect_to_service('dynamodb').describe_table(TableName=table_name)


class QueuePolicy(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::SQS::QueuePolicy'


class SSMParameter(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::SSM::Parameter'

    def fetch_state(self, stack_name, resources):
        param_name = self.props.get('Name') or self.resource_id
        param_name = self.resolve_refs_recursively(stack_name, param_name, resources)
        return aws_stack.connect_to_service('ssm').get_parameter(Name=param_name)['Parameter']


class SecretsManagerSecret(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return 'AWS::SecretsManager::Secret'

    def fetch_state(self, stack_name, resources):
        secret_name = self.props.get('Name') or self.resource_id
        secret_name = self.resolve_refs_recursively(stack_name, secret_name, resources)
        result = aws_stack.connect_to_service('secretsmanager').describe_secret(SecretId=secret_name)
        return result
