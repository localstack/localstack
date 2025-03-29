from __future__ import annotations

from typing import Final, Optional

import localstack.aws.api.cloudformation as cfn_api
from localstack.services.cloudformation.engine.v2.change_set_model import (
    NodeIntrinsicFunction,
    NodeResource,
    NodeTemplate,
)
from localstack.services.cloudformation.engine.v2.change_set_model_processor import (
    ChangeSetModelProcessor,
    ResolvedEntityDelta,
    ResolvedResource,
)

CHANGESET_KNOWN_AFTER_APPLY: Final[str] = "{{changeSet:KNOWN_AFTER_APPLY}}"


class ChangeSetModelDescriber(ChangeSetModelProcessor):
    _changes: Final[cfn_api.Changes]

    def __init__(self, node_template: NodeTemplate):
        super().__init__(node_template=node_template)
        self._changes = list()

    def get_changes(self) -> cfn_api.Changes:
        self._changes.clear()
        self.process()
        return self._changes

    def visit_node_intrinsic_function_fn_get_att(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> ResolvedEntityDelta:
        delta = super().visit_node_intrinsic_function_fn_get_att(
            node_intrinsic_function=node_intrinsic_function
        )
        if delta.after is not None and delta.after != delta.before:
            # The value needs computing, simulate aws's describe
            # limitation by masking the new value.
            delta.after = CHANGESET_KNOWN_AFTER_APPLY
        return delta

    def _register_resource_change(
        self,
        logical_id: str,
        type_: str,
        before_context: Optional[dict],
        after_context: Optional[dict],
    ) -> None:
        # unchanged: nothing to do.
        if before_context == after_context:
            return

        action = cfn_api.ChangeAction.Modify
        if before_context is None:
            action = cfn_api.ChangeAction.Add
        elif after_context is None:
            action = cfn_api.ChangeAction.Remove

        resource_change = cfn_api.ResourceChange()
        resource_change["Action"] = action
        resource_change["LogicalResourceId"] = logical_id
        resource_change["ResourceType"] = type_
        if before_context is not None:
            resource_change["BeforeContext"] = before_context  # noqa
        if after_context is not None:
            resource_change["AfterContext"] = after_context  # noqa
        self._changes.append(
            cfn_api.Change(Type=cfn_api.ChangeType.Resource, ResourceChange=resource_change)
        )

    def _describe_resource(
        self, name: str, before: Optional[ResolvedResource], after: Optional[ResolvedResource]
    ) -> None:
        if before is not None and after is not None:
            # Case: change on same type.
            if before.resource_type == after.resource_type:
                # Register a Modified if changed.
                self._register_resource_change(
                    logical_id=name,
                    type_=before.resource_type,
                    before_context=before.properties,
                    after_context=after.properties,
                )
            # Case: type migration.
            # TODO: Add test to assert that on type change the resources are replaced.
            else:
                # Register a Removed for the previous type.
                self._register_resource_change(
                    logical_id=name,
                    type_=before.resource_type,
                    before_context=before.properties,
                    after_context=None,
                )
                # Register a Create for the next type.
                self._register_resource_change(
                    logical_id=name,
                    type_=after.resource_type,
                    before_context=None,
                    after_context=after.properties,
                )
        elif before is not None:
            # Case: removal
            self._register_resource_change(
                logical_id=name,
                type_=before.resource_type,
                before_context=before.properties,
                after_context=None,
            )
        elif after is not None:
            # Case: addition
            self._register_resource_change(
                logical_id=name,
                type_=after.resource_type,
                before_context=None,
                after_context=after.properties,
            )

    def visit_node_resource(
        self, node_resource: NodeResource
    ) -> ResolvedEntityDelta[ResolvedResource, ResolvedResource]:
        delta = super().visit_node_resource(node_resource=node_resource)
        self._describe_resource(name=node_resource.name, before=delta.before, after=delta.after)
        return delta
