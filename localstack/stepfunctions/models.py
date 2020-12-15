# TODO: This file should be moved to moto!
# This code needs to live in this folder because moto/core/models.py contains this on line 445:
#   service = cls.__module__.split(".")[1]
# i.e., there is a hard constraint on the name of the module
from localstack.utils.aws import aws_stack
from moto.core import BaseModel
from moto.stepfunctions.models import stepfunction_backends


class StateMachine(BaseModel):
    def __init__(self, arn, name, definition=None, role_arn=None):
        super(StateMachine, self).__init__()
        self.arn = arn
        self.name = name
        self.role_arn = role_arn
        self.status = 'ACTIVE'
        self.definition = definition or '{}'

    @classmethod
    def create_from_cloudformation_json(cls, resource_name, cloudformation_json, region_name):
        props = cloudformation_json['Properties']
        name = props.get('StateMachineName') or resource_name
        definition = props.get('DefinitionString')
        role_arn = props.get('RoleArn')
        arn = 'arn:aws:states:' + region_name + ':' + str(aws_stack.get_account_id()) + ':stateMachine:' + name

        state_machine = StateMachine(arn, name, definition=definition, role_arn=role_arn)
        stepfunction_backends[region_name].state_machines.append(state_machine)

        return state_machine

    @classmethod
    def update_from_cloudformation_json(cls, original_resource, new_resource_name, cloudformation_json, region_name):
        props = cloudformation_json.get('Properties', {})
        definition = props.get('DefinitionString')
        role_arn = props.get('RoleArn')

        state_machine = stepfunction_backends[region_name].update_state_machine(
            original_resource.arn, definition=definition, role_arn=role_arn,
        )

        return state_machine

    def update(self, **kwargs):
        for key, value in kwargs.items():
            if value is not None:
                setattr(self, key, value)
