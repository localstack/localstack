import dataclasses
from concurrent.futures import Future, ThreadPoolExecutor

from localstack.aws.connect import connect_to

TYPE_NAME = "AWS::SNS::Topic"

@dataclasses.dataclass
class SnsTopicProperties:
    TopicName: str

@ResourceProvider(TYPE_NAME)
class AwsSnsTopic(ResourceProvider):
    def __init__(self):
        self.client = connect_to()

    def create(self, desiredState: SnsTopicProperties, context) -> ProgressEvent:

        # 0. Assign physical resource id / ARN
        # 1. GetTopicAttributes
        # 2. if exists:
        #      raise error
        #    else:
        # 3.   CreateTopic
        # 4. GetTopicAttributes

        create_response = self.client.sns.create_topic(Name=desiredState.TopicName)
        return ProgressEvent()

        # don't wait, e.g. don't do
        # self.client.awslambda.get_waiter("function_active_v2").wait(FunctionName=desiredState.FunctionName)

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

                # TODO: populate payload
                provider_payload = {
                    # meta information
                }
                progress_event = provider.perform_action("CREATE", provider_payload)
                # save progress event
                self.state[progress_event.request_token] = something_based_on_progress_event


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
