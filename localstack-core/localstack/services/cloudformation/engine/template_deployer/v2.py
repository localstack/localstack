from typing import Optional

from localstack.services.cloudformation.engine.changes import ChangeConfig
from localstack.services.cloudformation.engine.entities import Stack, StackChangeSet
from localstack.services.cloudformation.engine.template_deployer.base import TemplateDeployerBase


class TemplateDeployer(TemplateDeployerBase):
    def __init__(self, account_id: str, region_name: str, stack: Stack):
        self.account_id = account_id
        self.region_name = region_name
        self.stack = stack

    def construct_changes(
        self,
        existing_stack,
        new_stack,
        initialize: Optional[bool] = False,
        change_set_id=None,
        append_to_changeset: Optional[bool] = False,
        filter_unchanged_resources: Optional[bool] = False,
    ) -> list[ChangeConfig]:
        raise NotImplementedError

    def apply_change_set(self, change_set: StackChangeSet):
        raise NotImplementedError

    def delete_stack(self):
        raise NotImplementedError

    def deploy_stack(self):
        raise NotImplementedError

    def update_stack(self, new_stack: StackChangeSet):
        raise NotImplementedError
