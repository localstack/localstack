import dataclasses
from concurrent.futures import Future, ThreadPoolExecutor
from logging import Logger
from typing import TypedDict, Optional, TypeVar, Generic

from localstack.aws.connect import connect_to, ServiceLevelClientFactory
from localstack.services.cloudformation.models.sns import SNSTopic

########
# scaffolding

# ... scaffold --type-name "AWS::Lambda::Function"
# 1. download schema from AWS & save it locally
# 2. based on the schema generate types for properties
# 3. create provider skeleton
# 4. create test file with base tests for new provider


###################
# executing the provider

# session based on provider credentials (i.e. credentials used for logs, metrics, ...)
# session based on caller credentials (i.e. credentials used in handler)
# properties

# deployer

RESOURCE_PROVIDERS: dict[str, ResourceProvider] = dict()


class DeploymentStateContainer:
    callback_context: dict
    desiredState: dict


class Registry:
    ...


class ProviderDispatcher:
    registry: Registry


class Provider:
    def create_changeset(self):
        """
        if type == CREATE
            * create empty stack
            * create change set
            * fetch the template (if necessary)

            * create hydrated stack from template
                * parse the template & validate CFn schema
                * process (incl. resolving) stack parameters
                * validating resolvability / build DAG of resources / dependencies

            * hand off to template processing (=> ASYNC)
                * transformations
                * resolve dynamic ssm parameters in template

                * build set of changes
                    * TODO (????) What's the semantics here?
                    * TODO: is this even important?
                        - SRW: yes we have to dispatch to the correct provider method, and
                               we have to return something for `DescribeChangeset`
                               it would make sense if that format was approximately the same
                               though it's more than the resource provider needs.

                * set processed template & update state to AVAILABLE / Failed / ...?

            <- return
        """
        ...

    def execute_changeset(self):
        """
        TODO: test conditional on properties (e.g. conditional on getatt of another resource)

        * set states to IN_PROGRESS
        * hand off to deployer (ASYNC)
            * resolve imports
            * validate rules
            * start deployment process
                * some loop (pluggable)
                    * before passing to the loop here try to completely process the resource
                    * (?) we chose resource X => now what
                    * (?) TODO: figure out what we use to invoke the provider
                    * deploy resource X via provider Y (pluggable)
        <- return

        """
        ...


# State stored in stack
# 0. unknown / void
# 1. CREATE_IN_PROGRESS
# 2. ...
# 3. CREATE_COMPLETED


class Deployer:
    """

    * (hydrated) Stack but actually rich resource graph (DAG) & linked items
    *

    """

    # request token => deployment state container
    state: dict[
        str,
    ]

    provider_executor: ThreadPoolExecutor

    def __init__(self):
        self.provider_executor = ThreadPoolExecutor(thread_name_prefix="provider_executor")

    def deploy(self, stack) -> None:
        # build dependency tree

        # calculate list of changes
        list_of_changes = [
            {
                "resource_type": "AWS::Lambda::Function",
                "desiredState": {},
                # ...
            }
        ]

        while True:
            # select deployable resources (no unresolvable dependencies)

            for res in deployable_resources:

                # TODO: async
                resource_type = res.type

                # detect changes

                # fetch the resource provider
                provider = self.registry.get_provider(resource_type)

                test_payload = {
                    "awsAccountId": account_id,
                    # TODO: identify purpose of bearer token
                    # TODO: check if this is equivalent to the cloud control request token
                    "bearerToken": "6745ef59-5120-a3dd-42fb-ac18d3a53361",  # in CloudTrail visible as "User name" (part of the assumed role ARN)
                    "region": region,
                    # "responseEndpoint": None,
                    "action": action,
                    # TODO: pagination?
                    # "nextToken": None,
                    "resourceType": resource_type,
                    "resourceTypeVersion": "00000000", # sentinel value
                    # "resourceTypeVersion": "00000015",
                    "requestData": {
                        "logicalResourceId": logical_resource_id,

                        # desiredState
                        "resourceProperties": properties,
                        "previousResourceProperties": None,
                        # "typeConfiguration": None,

                        # passed to resource provider handler
                        "callerCredentials": {
                            "accessKeyId": "test",
                            "secretAccessKey": "test",
                            "sessionToken": "IQoJb3JpZ2luX2VjEL///////////wEaCmV1LW5vcnRoLTEiRjBEAiA4nURWUNfs65ZXQ0zc1DWYguk7zHbjCR5bxYtGUW6zLQIgDEYichRZxWMlMpx4FQMS7+ki70Dmrvi5O9n7zkgHWN0q6QII6P//////////ARABGgw2MjE1NjIxNTgwOTAiDIuWUhXXf2pjNPwBqyq9AqU6CA4vlNerjZUj9ZQBRB4wTihrpvL+UnIpuZ7QAIThxuxZtI8xhCizrUzkLnCchcVRo+p/BQ9d1SBIPwjIALBm9feQeJt3gBA7VPPF0xpNNruKpdzyiY28MbWejqBfn4mmSw6DhlGwFSLnCJ/xBvB5c1ZMePyq/vuV2RoNs6LBFbNlfEpsdXUxrDOjhRA5D89tk6NjVALy13O3oD2uhsoTCgX6e5dxDm3QNVl1Dl3FAu8Mb9Yimglfz8gbkFKWKlo8sXTGoEjROwU8marnvSLNRV0YcGB2z2Zh3fkkG4G1PgaOQj0LvJdS9dG7Y5uTV5eYLhMKcVLwz+DJo8Se5nzdPMrIvhTGttA3os2Hp5eJqJD4nL+MkVcvIAGUId9mAsrt2PVOmWayTVmRT41M21BVtkEfAYoWLshgioMZMIaE65wGOpAByedxVha6SdLcRrKfLD/ZtNGsqKHSNT/KtIG70qMMyaGAltNENHHyjp1FU/BrFGygU1zPEacEhFh3QCjVRboWJdoNnMdUrGFEai9Fv4gUcQGaSaPs1VfUdoEBdFK1zK3Vb/5eiDutNjlMhBC3ltQSXG2vfN2jDbuEgqoZkhmUpd04yGBlFU/159QOqqabpID0",
                        },

                        # passed to resource provider for meta-work (logging, ...)
                        "providerCredentials": {
                            "accessKeyId": "test",
                            "secretAccessKey": "test",
                            "sessionToken": "IQoJb3JpZ2luX2VjEL///////////wEaCmV1LW5vcnRoLTEiRzBFAiEA9CyU+KiXC7VddfVOjCNHZPJ5wiQcxxl/utgL41/78k4CIBIfNTXpLYatWLsrmqlZdDKM8DF5bzDuvBgvb14ulzwAKqcCCOj//////////wEQARoMNjIxNTYyMTU4MDkwIgwv2vwpSjXEeWzUytcq+wFvEeCao4TeG17XbbooPFunx4hppa2YtJF+Gehh3FBZPQC8tq2Ta+PsK/WdIqTkibocy6dqCiXQ9okxcVwLLOIdlQbKZP1Gi1CBl9N68vBYJPJY0zKoIJETSpVTp5GbGxgN3pLlEpDFxeMp2P4Y0/NBfI/lbIMja6EMWli1LYy/frGkC4ArOy5BlbcsIgq7YAMe9X9F3s9zBlKHa2bOP6TLUlr34XYquy5ixd1X4j7K8yk7S4NKhh8ud+2t+Cp/RdWDpyxVKr39o88oxjhxdCXt4+6+Dp0Up6A6QLzlfg68n6LhJM4Sn0cKvT6VK7It2KeJiB+mhntnQIVWtjCGhOucBjqPAcCnilLas71nybhqomVYXxN82oRw/GoAO/E6wc3O/4pWxnysc5aBty5d7MJREJbKVNfQTP9DEJvdhSwsH8JjZupofVglVRRE91pk0K2v6cyzBmvtrLslh0oBtuYBsPohctNs4TA9XSnV4+FH+ZEui4w+yB8lTaWR9v523dSJZjFiyGO/JOrpd45MQG39ZhG5",
                        },
                        # 'providerLogGroupName': 'localstack-test-testy-logs',

                        # fixed tags, these are always available when deploying via CFn
                        # TODO: when would this ever change? Does the payload change for different CRUD operations?
                        "systemTags": {
                            "aws:cloudformation:stack-name": stack_name,
                            "aws:cloudformation:stack-id": stack_id,
                            "aws:cloudformation:logical-id": logical_resource_id,
                        },
                        "previousSystemTags": None,

                        # cfn tries to propagate these tags to all included resources
                        "stackTags": None,
                        "previousStackTags": None,
                    },
                    "stackId": stack_id,
                    # context between invocations of the provider (use it to store data temporarily)
                    "callbackContext": None,

                    # "snapshotRequested": None,
                    # "rollback": None,
                    # "driftable": None,
                    # "features": {"preventIdempotentResourceAdoption": True},
                    # TODO: are these used?
                    # "updatePolicy": None,
                    # "creationPolicy": None,
                    # "serviceModelKey": None,
                }


                # TODO: populate payload
                provider_payload = {
                    # meta information
                }
                progress_event = provider.perform_action("CREATE", provider_payload)
                # save progress event
                self.state[progress_event.request_token] = something_based_on_progress_event


class Credentials(TypedDict):
    accessKeyId: str
    secretAccessKey: str
    sessionToken: str

class ResourceProviderPayloadRequestData(TypedDict):
    logicalResourceId: str
    resourceProperties: dict
    previousResourceProperties: dict
    callerCredentials: Credentials
    providerCredentials: Credentials
    systemTags: dict[str,str]
    previousSystemTags: dict[str,str]
    stackTags: dict[str,str]
    previousStackTags: dict[str,str]

class ResourceProviderPayload(TypedDict):
    callbackContext: dict
    stackId: str
    requestData: ResourceProviderPayloadRequestData
    resourceType: str
    resourceTypeVersion: str
    awsAccountId: str
    bearerToken: str
    region: str
    action: str


ResourceProperties = TypeVar("ResourceProperties")

@dataclasses.dataclass
class ResourceRequest(Generic[ResourceProperties]):
    _original_payload: ResourceProviderPayload

    aws_client_factory: ServiceLevelClientFactory
    request_token: str
    stack_name: str
    stack_id: str
    account_id: str
    region_name: str

    # custom_context: dict = dataclasses.field(default=dict)

    desired_state: ResourceProperties
    previous_state: Optional[ResourceProperties] = None

    tags: dict[str,str]
    previous_tags: [str,str]

    logicalResourceId: str

    logger: Logger





def convert_payload(payload: ResourceProviderPayload) -> ResourceRequest:
    client_factory = connect_to(
        aws_access_key_id=payload['requestData']['callerCredentials']['accessKeyId'],
        aws_session_token=payload['requestData']['callerCredentials']['sessionToken'],
        aws_secret_access_key=payload['requestData']['callerCredentials']['secretAccessKey'],
        region_name=payload['region']
    )
    return ResourceRequest(
        _original_payload=payload,
        aws_client_factory=client_factory,
    )



TYPE_NAME = "AWS::SNS::Topic"

sns_topic_schema = {
    "TopicName": "...", # create-only
    "TopicArn": "..." # read-only
    ""
}

@dataclasses.dataclass
class SnsTopicProperties:
    TopicName: str
    TopicArn: str


@ResourceProvider(TYPE_NAME)
class LegacyModelProvider(ResourceProvider):
    def __init__(self):
        ...
    def create(self, request: ResourceRequest[SnsTopicProperties]) -> ProgressEvent:
        if request.desired_state.TopicArn:
            fn_state = request.aws_client_factory.awslambda.get_function(FunctionName=request.desired_state.TopicName)
            if fn_state['Configuration']['State'] == 'Active':
                return ProgressEvent("CREATE_COMPLETE", state={"Arn": "asdfasdfsf"})

        # do something (initate resource creation)
        return ProgressEvent("IN_PROGRESS", state={"TopicArn": "asdfasdfsf"})
        topic = SNSTopic(request.desired_state.copy(), request.region_name)
        topic.get_deploy_templates()
        create = topic.get_deploy_templates()["create"]

        action = build_deployment_action(create)
        result = action(resources, resource_id, stack_name)
        primary_id = get_primary_id_from_result(result)
        result_handler(result) # only identify and set the ID

        # TODO: how and when do we break out of this loop?
        # find max duration and wait time somewhat equivalent to current setup
        while True:
            if topic.fetch_state(primary_id):
                break

        return ProgressEvent("CREATE_COMPLETE", state=topic.props)

        # 1. add defaults (GenericBaseModel.add_defaults(resource, stack_name))
        # (2. deploy )
        # 3. add read-only & primary id (happens in the create call + result_handler + fetch_state(!))
        # ???????? time passed
        # 4. CREATE_COMPLETE


        # 0. Assign physical resource id / ARN
        # 1. GetTopicAttributes
        # 2. if exists:
        #      raise error
        #    else:
        # 3.   CreateTopic
        # 4. GetTopicAttributes
        request.logger.info("Starting to create topic")


        create_response = self.client.sns.create_topic(Name=desiredState.TopicName)
        return ProgressEvent("IN_PROGRESS", state={"TopicName": "a", "TopicArn": "b"})

    def update(self):
        ...

    def delete(self):
        # 1. DeleteTopic
        ...

    # cloud control
    def read(self):
        ...

    def list(self):
        ...


"""
ROLES AND RESPONSIBILITIES

Entities:
- stack
- template
  - user-supplied (raw)
  - hydrated
- resource
- resource provider
    - resource provider adaptors:
        - (internal) generic base model,
        - (internal) new
        - (external) extension
- changeset
- registry
- template (pre-)processor
- template deployer
- internal change set plan (DON'T CALL CHANGESET) - changes? plan?
- CFn provider

Roles:
- stack:
    - behaviourless
    - aggregates current "state"
    - state of a resource
- stackset:
    - behaviourless
    - list of stacks per region
- registry:
    - stores extensions
- resource:
    - status

-

PERSISTENCE

Store tree:
    registry:
        - global[type][version] -> resource provider
        - public[account][region][type][version] -> resource provider
        - private[account][region][type][version] -> resource provider
        - default version for provider

    stacks[account][region]:
        - latest_changeset
        - template (user-provided original, last successful create_stack, execute_changeset, update_stack) TODO: test "successful"
        - processed_template (after create_stack, execute_changeset, update_stack)
        - events: List[StackEvent] (after create_stack, execute_changeset, update_stack)
        - parent stack
        - parameters
        - outputs

        - metadata

        resources[logical_id] -> Resource:
          - deployment status
          - physical id
          - request token
          - callback context

        changesets[id] -> Changeset:
          - changes
          - parameters
          - template
          - status

    resource provider: STATELESS
    template processor: STATELESS
    template deployer: AS STATELESS AS POSSIBLE, STATE MACHINE

"""


class Stack:
    def create_changeset(self, desired_state: ...) -> Changes:
        ...


class Changes:
    def render_changeset(self) -> Changeset:
        pass
