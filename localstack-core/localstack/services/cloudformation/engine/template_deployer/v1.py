import logging
import traceback
import uuid
from typing import Optional

from localstack import config
from localstack.constants import INTERNAL_AWS_SECRET_ACCESS_KEY
from localstack.services.cloudformation.deployment_utils import (
    get_action_name_for_resource_change,
    remove_none_values,
)
from localstack.services.cloudformation.engine.changes import ChangeConfig, ResourceChange
from localstack.services.cloudformation.engine.entities import Stack, StackChangeSet
from localstack.services.cloudformation.engine.resource_ordering import (
    order_changes,
    order_resources,
)
from localstack.services.cloudformation.engine.template_deployer.base import (
    MOCK_REFERENCE,
    NoStackUpdates,
    TemplateDeployerBase,
    evaluate_resource_condition,
    resolve_outputs,
    resolve_refs_recursively,
)
from localstack.services.cloudformation.engine.template_utils import get_deps_for_resource
from localstack.services.cloudformation.resource_provider import (
    Credentials,
    OperationStatus,
    ProgressEvent,
    ResourceProviderExecutor,
    ResourceProviderPayload,
    get_resource_type,
)
from localstack.services.cloudformation.service_models import DependencyNotYetSatisfied
from localstack.utils.json import clone_safe
from localstack.utils.threads import start_worker_thread

LOG = logging.getLogger(__name__)


class TemplateDeployer(TemplateDeployerBase):
    def __init__(self, account_id: str, region_name: str, stack):
        self.stack = stack
        self.account_id = account_id
        self.region_name = region_name

    @property
    def resources(self):
        return self.stack.resources

    @property
    def mappings(self):
        return self.stack.mappings

    @property
    def stack_name(self):
        return self.stack.stack_name

    # ------------------
    # MAIN ENTRY POINTS
    # ------------------

    def deploy_stack(self):
        self.stack.set_stack_status("CREATE_IN_PROGRESS")
        try:
            self.apply_changes(
                self.stack,
                self.stack,
                initialize=True,
                action="CREATE",
            )
        except Exception as e:
            log_method = LOG.info
            if config.CFN_VERBOSE_ERRORS:
                log_method = LOG.exception
            log_method("Unable to create stack %s: %s", self.stack.stack_name, e)
            self.stack.set_stack_status("CREATE_FAILED")
            raise

    def apply_change_set(self, change_set: StackChangeSet):
        action = (
            "UPDATE"
            if change_set.stack.status in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
            else "CREATE"
        )
        change_set.stack.set_stack_status(f"{action}_IN_PROGRESS")
        # update parameters on parent stack
        change_set.stack.set_resolved_parameters(change_set.resolved_parameters)
        # update conditions on parent stack
        change_set.stack.set_resolved_stack_conditions(change_set.resolved_conditions)

        # update attributes that the stack inherits from the changeset
        change_set.stack.metadata["Capabilities"] = change_set.metadata.get("Capabilities")

        try:
            self.apply_changes(
                change_set.stack,
                change_set,
                action=action,
            )
        except Exception as e:
            LOG.info(
                "Unable to apply change set %s: %s", change_set.metadata.get("ChangeSetName"), e
            )
            change_set.metadata["Status"] = f"{action}_FAILED"
            self.stack.set_stack_status(f"{action}_FAILED")
            raise

    def update_stack(self, new_stack: StackChangeSet):
        self.stack.set_stack_status("UPDATE_IN_PROGRESS")
        # apply changes
        self.apply_changes(self.stack, new_stack, action="UPDATE")
        self.stack.set_time_attribute("LastUpdatedTime")

    # ----------------------------
    # DEPENDENCY RESOLUTION UTILS
    # ----------------------------

    def is_deployed(self, resource):
        return self.stack.resource_states.get(resource["LogicalResourceId"], {}).get(
            "ResourceStatus"
        ) in [
            "CREATE_COMPLETE",
            "UPDATE_COMPLETE",
        ]

    def all_resource_dependencies_satisfied(self, resource) -> bool:
        unsatisfied = self.get_unsatisfied_dependencies(resource)
        return not unsatisfied

    def get_unsatisfied_dependencies(self, resource):
        res_deps = self.get_resource_dependencies(
            resource
        )  # the output here is currently a set of merged IDs from both resources and parameters
        parameter_deps = {d for d in res_deps if d in self.stack.resolved_parameters}
        resource_deps = res_deps.difference(parameter_deps)
        res_deps_mapped = {v: self.stack.resources.get(v) for v in resource_deps}
        return self.get_unsatisfied_dependencies_for_resources(res_deps_mapped, resource)

    def get_unsatisfied_dependencies_for_resources(
        self, resources, depending_resource=None, return_first=True
    ):
        result = {}
        for resource_id, resource in resources.items():
            if not resource:
                raise Exception(
                    f"Resource '{resource_id}' not found in stack {self.stack.stack_name}"
                )
            if not self.is_deployed(resource):
                LOG.debug(
                    "Dependency for resource %s not yet deployed: %s %s",
                    depending_resource,
                    resource_id,
                    resource,
                )
                result[resource_id] = resource
                if return_first:
                    break
        return result

    def get_resource_dependencies(self, resource: dict) -> set[str]:
        """
        Takes a resource and returns its dependencies on other resources via a str -> str mapping
        """
        # Note: using the original, unmodified template here to preserve Ref's ...
        raw_resources = self.stack.template_original["Resources"]
        raw_resource = raw_resources[resource["LogicalResourceId"]]
        return get_deps_for_resource(raw_resource, self.stack.resolved_conditions)

    # -----------------
    # DEPLOYMENT UTILS
    # -----------------

    def init_resource_status(self, resources=None, stack=None, action="CREATE"):
        resources = resources or self.resources
        stack = stack or self.stack
        for resource_id, resource in resources.items():
            stack.set_resource_status(resource_id, f"{action}_IN_PROGRESS")

    def get_change_config(
        self, action: str, resource: dict, change_set_id: Optional[str] = None
    ) -> ChangeConfig:
        result = ChangeConfig(
            **{
                "Type": "Resource",
                "ResourceChange": ResourceChange(
                    **{
                        "Action": action,
                        # TODO(srw): how can the resource not contain a logical resource id?
                        "LogicalResourceId": resource.get("LogicalResourceId"),
                        "PhysicalResourceId": resource.get("PhysicalResourceId"),
                        "ResourceType": resource["Type"],
                        # TODO ChangeSetId is only set for *nested* change sets
                        # "ChangeSetId": change_set_id,
                        "Scope": [],  # TODO
                        "Details": [],  # TODO
                    }
                ),
            }
        )
        if action == "Modify":
            result["ResourceChange"]["Replacement"] = "False"
        return result

    def resource_config_differs(self, resource_new):
        """Return whether the given resource properties differ from the existing config (for stack updates)."""
        # TODO: this is broken for default fields and result_handler property modifications when they're added to the properties in the model
        resource_id = resource_new["LogicalResourceId"]
        resource_old = self.resources[resource_id]
        props_old = resource_old.get("SpecifiedProperties", {})
        props_new = resource_new["Properties"]
        ignored_keys = ["LogicalResourceId", "PhysicalResourceId"]
        old_keys = set(props_old.keys()) - set(ignored_keys)
        new_keys = set(props_new.keys()) - set(ignored_keys)
        if old_keys != new_keys:
            return True
        for key in old_keys:
            if props_old[key] != props_new[key]:
                return True
        old_status = self.stack.resource_states.get(resource_id) or {}
        previous_state = (
            old_status.get("PreviousResourceStatus") or old_status.get("ResourceStatus") or ""
        )
        if old_status and "DELETE" in previous_state:
            return True

    # TODO: ?
    def merge_properties(self, resource_id: str, old_stack, new_stack) -> None:
        old_resources = old_stack.template["Resources"]
        new_resources = new_stack.template["Resources"]
        new_resource = new_resources[resource_id]

        old_resource = old_resources[resource_id] = old_resources.get(resource_id) or {}
        for key, value in new_resource.items():
            if key == "Properties":
                continue
            old_resource[key] = old_resource.get(key, value)
        old_res_props = old_resource["Properties"] = old_resource.get("Properties", {})
        for key, value in new_resource["Properties"].items():
            old_res_props[key] = value

        old_res_props = {
            k: v for k, v in old_res_props.items() if k in new_resource["Properties"].keys()
        }
        old_resource["Properties"] = old_res_props

        # overwrite original template entirely
        old_stack.template_original["Resources"][resource_id] = new_stack.template_original[
            "Resources"
        ][resource_id]

    def construct_changes(
        self,
        existing_stack,
        new_stack,
        # TODO: remove initialize argument from here, and determine action based on resource status
        initialize: Optional[bool] = False,
        change_set_id=None,
        append_to_changeset: Optional[bool] = False,
        filter_unchanged_resources: Optional[bool] = False,
    ) -> list[ChangeConfig]:
        old_resources = existing_stack.template["Resources"]
        new_resources = new_stack.template["Resources"]
        deletes = [val for key, val in old_resources.items() if key not in new_resources]
        adds = [val for key, val in new_resources.items() if initialize or key not in old_resources]
        modifies = [
            val for key, val in new_resources.items() if not initialize and key in old_resources
        ]

        changes = []
        for action, items in (("Remove", deletes), ("Add", adds), ("Modify", modifies)):
            for item in items:
                item["Properties"] = item.get("Properties", {})
                if (
                    not filter_unchanged_resources  # TODO: find out purpose of this
                    or action != "Modify"
                    or self.resource_config_differs(item)
                ):
                    change = self.get_change_config(action, item, change_set_id=change_set_id)
                    changes.append(change)

        # append changes to change set
        if append_to_changeset and isinstance(new_stack, StackChangeSet):
            new_stack.changes.extend(changes)

        return changes

    def apply_changes(
        self,
        existing_stack: Stack,
        new_stack: StackChangeSet,
        change_set_id: Optional[str] = None,
        initialize: Optional[bool] = False,
        action: Optional[str] = None,
    ):
        old_resources = existing_stack.template["Resources"]
        new_resources = new_stack.template["Resources"]
        action = action or "CREATE"
        # TODO: this seems wrong, not every resource here will be in an UPDATE_IN_PROGRESS state? (only the ones that will actually be updated)
        self.init_resource_status(old_resources, action="UPDATE")

        # apply parameter changes to existing stack
        # self.apply_parameter_changes(existing_stack, new_stack)

        # construct changes
        changes = self.construct_changes(
            existing_stack,
            new_stack,
            initialize=initialize,
            change_set_id=change_set_id,
        )

        # check if we have actual changes in the stack, and prepare properties
        contains_changes = False
        for change in changes:
            res_action = change["ResourceChange"]["Action"]
            resource = new_resources.get(change["ResourceChange"]["LogicalResourceId"])
            #  FIXME: we need to resolve refs before diffing to detect if for example a parameter causes the change or not
            #   unfortunately this would currently cause issues because we might not be able to resolve everything yet
            # resource = resolve_refs_recursively(
            #     self.stack_name,
            #     self.resources,
            #     self.mappings,
            #     self.stack.resolved_conditions,
            #     self.stack.resolved_parameters,
            #     resource,
            # )
            if res_action in ["Add", "Remove"] or self.resource_config_differs(resource):
                contains_changes = True
            if res_action in ["Modify", "Add"]:
                # mutating call that overwrites resource properties with new properties and overwrites the template in old stack with new template
                self.merge_properties(resource["LogicalResourceId"], existing_stack, new_stack)
        if not contains_changes:
            raise NoStackUpdates("No updates are to be performed.")

        # merge stack outputs and conditions
        existing_stack.outputs.update(new_stack.outputs)
        existing_stack.conditions.update(new_stack.conditions)

        # TODO: ideally the entire template has to be replaced, but tricky at this point
        existing_stack.template["Metadata"] = new_stack.template.get("Metadata")
        existing_stack.template_body = new_stack.template_body

        # start deployment loop
        return self.apply_changes_in_loop(
            changes, existing_stack, action=action, new_stack=new_stack
        )

    def apply_changes_in_loop(
        self,
        changes: list[ChangeConfig],
        stack: Stack,
        action: Optional[str] = None,
        new_stack=None,
    ):
        def _run(*args):
            status_reason = None
            try:
                self.do_apply_changes_in_loop(changes, stack)
                status = f"{action}_COMPLETE"
            except Exception as e:
                log_method = LOG.debug
                if config.CFN_VERBOSE_ERRORS:
                    log_method = LOG.exception
                log_method(
                    'Error applying changes for CloudFormation stack "%s": %s %s',
                    stack.stack_name,
                    e,
                    traceback.format_exc(),
                )
                status = f"{action}_FAILED"
                status_reason = str(e)
            stack.set_stack_status(status, status_reason)
            if isinstance(new_stack, StackChangeSet):
                new_stack.metadata["Status"] = status
                exec_result = "EXECUTE_FAILED" if "FAILED" in status else "EXECUTE_COMPLETE"
                new_stack.metadata["ExecutionStatus"] = exec_result
                result = "failed" if "FAILED" in status else "succeeded"
                new_stack.metadata["StatusReason"] = status_reason or f"Deployment {result}"

        # run deployment in background loop, to avoid client network timeouts
        return start_worker_thread(_run)

    def prepare_should_deploy_change(
        self, resource_id: str, change: ResourceChange, stack, new_resources: dict
    ) -> bool:
        """
        TODO: document
        """
        resource = new_resources[resource_id]
        res_change = change["ResourceChange"]
        action = res_change["Action"]

        # check resource condition, if present
        if not evaluate_resource_condition(stack.resolved_conditions, resource):
            LOG.debug(
                'Skipping deployment of "%s", as resource condition evaluates to false', resource_id
            )
            return False

        # resolve refs in resource details
        resolve_refs_recursively(
            self.account_id,
            self.region_name,
            stack.stack_name,
            stack.resources,
            stack.mappings,
            stack.resolved_conditions,
            stack.resolved_parameters,
            resource,
        )

        if action in ["Add", "Modify"]:
            is_deployed = self.is_deployed(resource)
            # TODO: Attaching the cached _deployed info here, as we should not change the "Add"/"Modify" attribute
            #  here, which is used further down the line to determine the resource action CREATE/UPDATE. This is a
            #  temporary workaround for now - to be refactored once we introduce proper stack resource state models.
            res_change["_deployed"] = is_deployed
            if not is_deployed:
                return True
            if action == "Add":
                return False
        elif action == "Remove":
            return True
        return True

    # Stack is needed here
    def apply_change(self, change: ChangeConfig, stack: Stack) -> None:
        change_details = change["ResourceChange"]
        action = change_details["Action"]
        resource_id = change_details["LogicalResourceId"]
        resources = stack.resources
        resource = resources[resource_id]

        # TODO: this should not be needed as resources are filtered out if the
        # condition evaluates to False.
        if not evaluate_resource_condition(stack.resolved_conditions, resource):
            return

        # remove AWS::NoValue entries
        resource_props = resource.get("Properties")
        if resource_props:
            resource["Properties"] = remove_none_values(resource_props)

        executor = self.create_resource_provider_executor()
        resource_provider_payload = self.create_resource_provider_payload(
            action, logical_resource_id=resource_id
        )

        resource_provider = executor.try_load_resource_provider(get_resource_type(resource))
        if resource_provider is not None:
            # add in-progress event
            resource_status = f"{get_action_name_for_resource_change(action)}_IN_PROGRESS"
            physical_resource_id = None
            if action in ("Modify", "Remove"):
                previous_state = self.resources[resource_id].get("_last_deployed_state")
                if not previous_state:
                    # TODO: can this happen?
                    previous_state = self.resources[resource_id]["Properties"]
                physical_resource_id = executor.extract_physical_resource_id_from_model_with_schema(
                    resource_model=previous_state,
                    resource_type=resource["Type"],
                    resource_type_schema=resource_provider.SCHEMA,
                )
            stack.add_stack_event(
                resource_id=resource_id,
                physical_res_id=physical_resource_id,
                status=resource_status,
            )

            # perform the deploy
            progress_event = executor.deploy_loop(
                resource_provider, resource, resource_provider_payload
            )
        else:
            resource["PhysicalResourceId"] = MOCK_REFERENCE
            progress_event = ProgressEvent(OperationStatus.SUCCESS, resource_model={})

        # TODO: clean up the surrounding loop (do_apply_changes_in_loop) so that the responsibilities are clearer
        stack_action = get_action_name_for_resource_change(action)
        match progress_event.status:
            case OperationStatus.FAILED:
                stack.set_resource_status(
                    resource_id,
                    f"{stack_action}_FAILED",
                    status_reason=progress_event.message or "",
                )
                # TODO: remove exception raising here?
                # TODO: fix request token
                raise Exception(
                    f'Resource handler returned message: "{progress_event.message}" (RequestToken: 10c10335-276a-33d3-5c07-018b684c3d26, HandlerErrorCode: InvalidRequest){progress_event.error_code}'
                )
            case OperationStatus.SUCCESS:
                stack.set_resource_status(resource_id, f"{stack_action}_COMPLETE")
            case OperationStatus.PENDING:
                # signal to the main loop that we should come back to this resource in the future
                raise DependencyNotYetSatisfied(
                    resource_ids=[], message="Resource dependencies not yet satisfied"
                )
            case OperationStatus.IN_PROGRESS:
                raise Exception("Resource deployment loop should not finish in this state")
            case unknown_status:
                raise Exception(f"Unknown operation status: {unknown_status}")

        # TODO: this is probably already done in executor, try removing this
        resource["Properties"] = progress_event.resource_model

    def create_resource_provider_executor(self) -> ResourceProviderExecutor:
        return ResourceProviderExecutor(
            stack_name=self.stack.stack_name,
            stack_id=self.stack.stack_id,
        )

    def create_resource_provider_payload(
        self, action: str, logical_resource_id: str
    ) -> ResourceProviderPayload:
        # FIXME: use proper credentials
        creds: Credentials = {
            "accessKeyId": self.account_id,
            "secretAccessKey": INTERNAL_AWS_SECRET_ACCESS_KEY,
            "sessionToken": "",
        }
        resource = self.resources[logical_resource_id]

        resource_provider_payload: ResourceProviderPayload = {
            "awsAccountId": self.account_id,
            "callbackContext": {},
            "stackId": self.stack.stack_name,
            "resourceType": resource["Type"],
            "resourceTypeVersion": "000000",
            # TODO: not actually a UUID
            "bearerToken": str(uuid.uuid4()),
            "region": self.region_name,
            "action": action,
            "requestData": {
                "logicalResourceId": logical_resource_id,
                "resourceProperties": resource["Properties"],
                "previousResourceProperties": resource.get("_last_deployed_state"),  # TODO
                "callerCredentials": creds,
                "providerCredentials": creds,
                "systemTags": {},
                "previousSystemTags": {},
                "stackTags": {},
                "previousStackTags": {},
            },
        }
        return resource_provider_payload

    def delete_stack(self):
        if not self.stack:
            return
        self.stack.set_stack_status("DELETE_IN_PROGRESS")
        stack_resources = list(self.stack.resources.values())
        resources = {r["LogicalResourceId"]: clone_safe(r) for r in stack_resources}
        original_resources = self.stack.template_original["Resources"]

        # TODO: what is this doing?
        for key, resource in resources.items():
            resource["Properties"] = resource.get(
                "Properties", clone_safe(resource)
            )  # TODO: why is there a fallback?
            resource["ResourceType"] = get_resource_type(resource)

        def _safe_lookup_is_deleted(r_id):
            """handles the case where self.stack.resource_status(..) fails for whatever reason"""
            try:
                return self.stack.resource_status(r_id).get("ResourceStatus") == "DELETE_COMPLETE"
            except Exception:
                if config.CFN_VERBOSE_ERRORS:
                    LOG.exception("failed to lookup if resource %s is deleted", r_id)
                return True  # just an assumption

        ordered_resource_ids = list(
            order_resources(
                resources=original_resources,
                resolved_conditions=self.stack.resolved_conditions,
                resolved_parameters=self.stack.resolved_parameters,
                reverse=True,
            ).keys()
        )
        for i, resource_id in enumerate(ordered_resource_ids):
            resource = resources[resource_id]
            try:
                # TODO: cache condition value in resource details on deployment and use cached value here
                if not evaluate_resource_condition(
                    self.stack.resolved_conditions,
                    resource,
                ):
                    continue

                executor = self.create_resource_provider_executor()
                resource_provider_payload = self.create_resource_provider_payload(
                    "Remove", logical_resource_id=resource_id
                )
                LOG.debug(
                    'Handling "Remove" for resource "%s" (%s/%s) type "%s"',
                    resource_id,
                    i + 1,
                    len(resources),
                    resource["ResourceType"],
                )
                resource_provider = executor.try_load_resource_provider(get_resource_type(resource))
                if resource_provider is not None:
                    event = executor.deploy_loop(
                        resource_provider, resource, resource_provider_payload
                    )
                else:
                    event = ProgressEvent(OperationStatus.SUCCESS, resource_model={})
                match event.status:
                    case OperationStatus.SUCCESS:
                        self.stack.set_resource_status(resource_id, "DELETE_COMPLETE")
                    case OperationStatus.PENDING:
                        # the resource is still being deleted, specifically the provider has
                        # signalled that the deployment loop should skip this resource this
                        # time and come back to it later, likely due to unmet child
                        # resources still existing because we don't delete things in the
                        # correct order yet.
                        continue
                    case OperationStatus.FAILED:
                        LOG.exception(
                            "Failed to delete resource with id %s. Reason: %s",
                            resource_id,
                            event.message or "unknown",
                        )
                    case OperationStatus.IN_PROGRESS:
                        # the resource provider executor should not return this state, so
                        # this state is a programming error
                        raise Exception(
                            "Programming error: ResourceProviderExecutor cannot return IN_PROGRESS"
                        )
                    case other_status:
                        raise Exception(f"Use of unsupported status found: {other_status}")

            except Exception as e:
                LOG.exception(
                    "Failed to delete resource with id %s. Final exception: %s",
                    resource_id,
                    e,
                )

        # update status
        self.stack.set_stack_status("DELETE_COMPLETE")
        self.stack.set_time_attribute("DeletionTime")

    def do_apply_changes_in_loop(self, changes: list[ChangeConfig], stack: Stack) -> list:
        # apply changes in a retry loop, to resolve resource dependencies and converge to the target state
        changes_done = []
        new_resources = stack.resources

        sorted_changes = order_changes(
            given_changes=changes,
            resources=new_resources,
            resolved_conditions=stack.resolved_conditions,
            resolved_parameters=stack.resolved_parameters,
        )
        for change_idx, change in enumerate(sorted_changes):
            res_change = change["ResourceChange"]
            action = res_change["Action"]
            is_add_or_modify = action in ["Add", "Modify"]
            resource_id = res_change["LogicalResourceId"]

            # TODO: do resolve_refs_recursively once here
            try:
                if is_add_or_modify:
                    should_deploy = self.prepare_should_deploy_change(
                        resource_id, change, stack, new_resources
                    )
                    LOG.debug(
                        'Handling "%s" for resource "%s" (%s/%s) type "%s" (should_deploy=%s)',
                        action,
                        resource_id,
                        change_idx + 1,
                        len(changes),
                        res_change["ResourceType"],
                        should_deploy,
                    )
                    if not should_deploy:
                        stack_action = get_action_name_for_resource_change(action)
                        stack.set_resource_status(resource_id, f"{stack_action}_COMPLETE")
                        continue
                elif action == "Remove":
                    should_remove = self.prepare_should_deploy_change(
                        resource_id, change, stack, new_resources
                    )
                    if not should_remove:
                        continue
                    LOG.debug(
                        'Handling "%s" for resource "%s" (%s/%s) type "%s"',
                        action,
                        resource_id,
                        change_idx + 1,
                        len(changes),
                        res_change["ResourceType"],
                    )
                self.apply_change(change, stack=stack)
                changes_done.append(change)
            except Exception as e:
                status_action = {
                    "Add": "CREATE",
                    "Modify": "UPDATE",
                    "Dynamic": "UPDATE",
                    "Remove": "DELETE",
                }[action]
                stack.add_stack_event(
                    resource_id=resource_id,
                    physical_res_id=new_resources[resource_id].get("PhysicalResourceId"),
                    status=f"{status_action}_FAILED",
                    status_reason=str(e),
                )
                if config.CFN_VERBOSE_ERRORS:
                    LOG.exception("Failed to deploy resource %s, stack deploy failed", resource_id)
                raise

        # clean up references to deleted resources in stack
        deletes = [c for c in changes_done if c["ResourceChange"]["Action"] == "Remove"]
        for delete in deletes:
            stack.template["Resources"].pop(delete["ResourceChange"]["LogicalResourceId"], None)

        # resolve outputs
        stack.resolved_outputs = resolve_outputs(self.account_id, self.region_name, stack)

        return changes_done
