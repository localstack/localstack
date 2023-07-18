import logging
import os
from datetime import time
from typing import Dict, List, Optional

import pytest

from localstack.testing.aws.cloudformation_utils import load_template_file, render_template
from localstack.testing.pytest.fixtures import DeployResult, StackDeployError
from localstack.utils.collections import ensure_list
from localstack.utils.strings import short_uid
from localstack.utils.sync import ShortCircuitWaitException, wait_until

LOG = logging.getLogger(__name__)


@pytest.fixture(scope="class")
def s3_create_bucket_class_scope(s3_resource, aws_client):
    buckets = []

    def factory(**kwargs) -> str:
        if "Bucket" not in kwargs:
            kwargs["Bucket"] = "test-bucket-%s" % short_uid()

        if (
            "CreateBucketConfiguration" not in kwargs
            and aws_client.s3.meta.region_name != "us-east-1"
        ):
            kwargs["CreateBucketConfiguration"] = {
                "LocationConstraint": aws_client.s3.meta.region_name
            }

        aws_client.s3.create_bucket(**kwargs)
        buckets.append(kwargs["Bucket"])
        return kwargs["Bucket"]

    yield factory

    # cleanup
    for bucket in buckets:
        try:
            bucket = s3_resource.Bucket(bucket)
            bucket.objects.all().delete()
            bucket.object_versions.all().delete()
            bucket.delete()
        except Exception as e:
            LOG.debug("error cleaning up bucket %s: %s", bucket, e)


@pytest.fixture(scope="class")
def deploy_cfn_template_class_scope(
    cleanup_stacks_scope_class,
    cleanup_changesets_scope_class,
    is_change_set_created_and_available_scope_class,
    is_change_set_finished_scope_class,
    aws_client,
):
    state = []

    def _deploy(
        *,
        is_update: Optional[bool] = False,
        stack_name: Optional[str] = None,
        change_set_name: Optional[str] = None,
        template: Optional[str] = None,
        template_path: Optional[str | os.PathLike] = None,
        template_mapping: Optional[Dict[str, any]] = None,
        parameters: Optional[Dict[str, str]] = None,
        max_wait: Optional[int] = None,
        role_arn: Optional[str] = None,
    ) -> DeployResult:
        if is_update:
            assert stack_name
        stack_name = stack_name or f"stack-{short_uid()}"
        change_set_name = change_set_name or f"change-set-{short_uid()}"

        if template_path is not None:
            template = load_template_file(template_path)
        template_rendered = render_template(template, **(template_mapping or {}))

        kwargs = dict(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=template_rendered,
            Capabilities=["CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
            ChangeSetType=("UPDATE" if is_update else "CREATE"),
            Parameters=[
                {
                    "ParameterKey": k,
                    "ParameterValue": v,
                }
                for (k, v) in (parameters or {}).items()
            ],
        )
        if role_arn is not None:
            kwargs["RoleARN"] = role_arn

        response = aws_client.cloudformation.create_change_set(**kwargs)

        change_set_id = response["Id"]
        stack_id = response["StackId"]
        state.append({"stack_id": stack_id, "change_set_id": change_set_id})

        assert wait_until(
            is_change_set_created_and_available_scope_class(change_set_id), _max_wait=60
        )
        aws_client.cloudformation.execute_change_set(ChangeSetName=change_set_id)
        wait_result = wait_until(
            is_change_set_finished_scope_class(change_set_id), _max_wait=max_wait or 60
        )

        describe_stack_res = aws_client.cloudformation.describe_stacks(StackName=stack_id)[
            "Stacks"
        ][0]

        if not wait_result:
            events = aws_client.cloudformation.describe_stack_events(StackName=stack_id)[
                "StackEvents"
            ]
            raise StackDeployError(describe_stack_res, events)

        outputs = describe_stack_res.get("Outputs", [])

        mapped_outputs = {o["OutputKey"]: o.get("OutputValue") for o in outputs}

        def _destroy_stack():
            aws_client.cloudformation.delete_stack(StackName=stack_id)

            def _await_stack_delete():
                return (
                    aws_client.cloudformation.describe_stacks(StackName=stack_id)["Stacks"][0][
                        "StackStatus"
                    ]
                    == "DELETE_COMPLETE"
                )

            assert wait_until(_await_stack_delete, _max_wait=max_wait or 60)
            # TODO: fix in localstack. stack should only be in DELETE_COMPLETE state after all resources have been deleted
            time.sleep(2)

        return DeployResult(
            change_set_id, stack_id, stack_name, change_set_name, mapped_outputs, _destroy_stack
        )

    yield _deploy

    for entry in state:
        entry_stack_id = entry.get("stack_id")
        entry_change_set_id = entry.get("change_set_id")
        try:
            entry_change_set_id and cleanup_changesets_scope_class([entry_change_set_id])
            entry_stack_id and cleanup_stacks_scope_class([entry_stack_id])
        except Exception as e:
            LOG.debug(
                f"Failed cleaning up change set {entry_change_set_id=} and stack {entry_stack_id=}: {e}"
            )


@pytest.fixture(scope="class")
def cleanup_stacks_scope_class(aws_client):
    def _cleanup_stacks(stacks: List[str]) -> None:
        stacks = ensure_list(stacks)
        for stack in stacks:
            try:
                aws_client.cloudformation.delete_stack(StackName=stack)
            except Exception:
                LOG.debug(f"Failed to cleanup stack '{stack}'")

    return _cleanup_stacks


@pytest.fixture(scope="class")
def cleanup_changesets_scope_class(aws_client):
    def _cleanup_changesets(changesets: List[str]) -> None:
        changesets = ensure_list(changesets)
        for cs in changesets:
            try:
                aws_client.cloudformation.delete_change_set(ChangeSetName=cs)
            except Exception:
                LOG.debug(f"Failed to cleanup changeset '{cs}'")

    return _cleanup_changesets


@pytest.fixture(scope="class")
def is_change_set_created_and_available_scope_class(aws_client):
    def _is_change_set_created_and_available(change_set_id: str):
        def _inner():
            change_set = aws_client.cloudformation.describe_change_set(ChangeSetName=change_set_id)
            return (
                # TODO: CREATE_FAILED should also not lead to further retries
                change_set.get("Status") == "CREATE_COMPLETE"
                and change_set.get("ExecutionStatus") == "AVAILABLE"
            )

        return _inner

    return _is_change_set_created_and_available


@pytest.fixture(scope="class")
def is_change_set_finished_scope_class(aws_client):
    def _is_change_set_finished(change_set_id: str, stack_name: Optional[str] = None):
        def _inner():
            kwargs = {"ChangeSetName": change_set_id}
            if stack_name:
                kwargs["StackName"] = stack_name

            check_set = aws_client.cloudformation.describe_change_set(**kwargs)

            if check_set.get("ExecutionStatus") == "EXECUTE_FAILED":
                LOG.warning("Change set failed")
                raise ShortCircuitWaitException()

            return check_set.get("ExecutionStatus") == "EXECUTE_COMPLETE"

        return _inner

    return _is_change_set_finished
