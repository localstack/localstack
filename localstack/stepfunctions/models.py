# TODO: This file should be moved to moto!
# This code needs to live in this folder because moto/core/models.py contains this on line 445:
#   service = cls.__module__.split(".")[1]
# i.e., there is a hard constraint on the name of the module

from moto.core import BaseModel


class StateMachine(BaseModel):

    def __init__(self, name, definition=None, role_arn=None):
        super(StateMachine, self).__init__()
        self.name = name
        self.role_arn = role_arn
        self.status = 'ACTIVE'
        self.definition = definition or '{}'

    @classmethod
    def create_from_cloudformation_json(cls, resource_name, cloudformation_json, region_name):
        props = cloudformation_json['Properties']
        name = props.get('RoleArn') or resource_name
        definition = props.get('DefinitionString')
        role_arn = props.get('RoleArn')
        return StateMachine(name, definition=definition, role_arn=role_arn)
