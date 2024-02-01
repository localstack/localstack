import json
import logging
from typing import Callable, ParamSpec, TypeVar

import jsonpatch
import pytest
from botocore.exceptions import WaiterError
from localstack_snapshot.snapshots.transformer import SortingTransformer

from localstack.aws.api.cloudcontrol import Operation, OperationStatus
from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer_utility import PATTERN_UUID
from localstack.utils.strings import long_uid, short_uid
from localstack.utils.sync import ShortCircuitWaitException, wait_until

LOG = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def cc_snapshot(snapshot):
    snapshot.add_transformer(snapshot.transform.key_value("Identifier"))
    snapshot.add_transformer(snapshot.transform.key_value("RequestToken"))
    snapshot.add_transformer(snapshot.transform.key_value("NextToken"))
    snapshot.add_transformer(SortingTransformer("ResourceDescriptions", lambda x: x["Identifier"]))


T = TypeVar("T")
P = ParamSpec("P")


@pytest.fixture
def create_resource(aws_client):
    resource_requests = []

    def _create(_: Callable[P, T]) -> Callable[P, T]:
        def _inner_create(*args: P.args, **kwargs: P.kwargs) -> T:
            try:
                result = aws_client.cloudcontrol.create_resource(*args, **kwargs)
                resource_requests.append(result["ProgressEvent"]["RequestToken"])
                return result
            except Exception:
                raise  # TODO

        return _inner_create

    yield _create(aws_client.cloudcontrol.create_resource)

    # cleanup
    for rr in resource_requests:
        try:
            progress_event = aws_client.cloudcontrol.get_resource_request_status(RequestToken=rr)[
                "ProgressEvent"
            ]
            if progress_event["OperationStatus"] in [
                OperationStatus.IN_PROGRESS,
                OperationStatus.PENDING,
            ]:
                aws_client.cloudcontrol.get_waiter("resource_request_success").wait(RequestToken=rr)

            delete_request = aws_client.cloudcontrol.delete_resource(
                TypeName=progress_event["TypeName"], Identifier=progress_event["Identifier"]
            )
            aws_client.cloudcontrol.get_waiter("resource_request_success").wait(
                RequestToken=delete_request["ProgressEvent"]["RequestToken"]
            )
        except Exception:
            LOG.warning(f"Failed to delete resource with request token {rr}")


@pytest.mark.skip("Not Implemented yet")
class TestCloudControlResourceApi:
    @markers.aws.validated
    def test_lifecycle(self, snapshot, create_resource, aws_client):
        """simple create/delete lifecycle for a resource"""

        snapshot.add_transformer(snapshot.transform.regex(PATTERN_UUID, "uuid"))
        waiter = aws_client.cloudcontrol.get_waiter("resource_request_success")

        request_token = long_uid()
        bucket_name = f"cc-test-bucket-{short_uid()}"
        create_response = create_resource(
            TypeName="AWS::S3::Bucket",
            DesiredState=json.dumps({"BucketName": bucket_name}),
            ClientToken=request_token,
            # RoleArn="asdf", # optional, by default uses client session
            # TypeVersionId="asdf", # optional, without it should use the default
        )
        snapshot.match("create_response", create_response)

        waiter.wait(RequestToken=create_response["ProgressEvent"]["RequestToken"])

        # stabilized state
        get_status_response = aws_client.cloudcontrol.get_resource_request_status(
            RequestToken=create_response["ProgressEvent"]["RequestToken"]
        )
        snapshot.match("get_status_response", get_status_response)
        assert get_status_response["ProgressEvent"]["OperationStatus"] == "SUCCESS"
        get_response = aws_client.cloudcontrol.get_resource(
            TypeName="AWS::S3::Bucket",
            Identifier=get_status_response["ProgressEvent"]["Identifier"],
        )
        snapshot.match("get_response", get_response)

        # delete the resource again
        delete_response = aws_client.cloudcontrol.delete_resource(
            TypeName="AWS::S3::Bucket", Identifier=bucket_name
        )
        snapshot.match("delete_response", delete_response)
        waiter.wait(RequestToken=delete_response["ProgressEvent"]["RequestToken"])

        get_request_status_response_postdelete = (
            aws_client.cloudcontrol.get_resource_request_status(
                RequestToken=delete_response["ProgressEvent"]["RequestToken"]
            )
        )
        snapshot.match(
            "get_request_status_response_postdelete", get_request_status_response_postdelete
        )

        # verify bucket is not here anymore
        with pytest.raises(
            aws_client.cloudcontrol.exceptions.ResourceNotFoundException
        ) as res_not_found_exc:
            aws_client.cloudcontrol.get_resource(TypeName="AWS::S3::Bucket", Identifier=bucket_name)
        snapshot.match("res_not_found_exc", res_not_found_exc.value.response)

        # also verify with s3 API
        with pytest.raises(aws_client.s3.exceptions.ClientError):
            aws_client.s3.head_bucket(Bucket=bucket_name)

    @markers.aws.validated
    def test_api_exceptions(self, snapshot, aws_client):
        """
        Test a few edge cases in the API which do not need the creating of resources

        Learnings:
        - all operations care if the type name exists
        - delete_resource does not care if the identifier doesn't exist (!)
        - update handler seems to be written in java and first deserializes the patch document before checking anything else

        """
        nonexisting_identifier = f"localstack-doesnotexist-{short_uid()}"

        # create
        with pytest.raises(aws_client.cloudcontrol.exceptions.TypeNotFoundException) as e:
            aws_client.cloudcontrol.create_resource(
                TypeName="AWS::LocalStack::DoesNotExist", DesiredState=json.dumps({})
            )
        snapshot.match("create_nonexistingtype", e.value.response)

        # delete
        with pytest.raises(aws_client.cloudcontrol.exceptions.TypeNotFoundException) as e:
            aws_client.cloudcontrol.delete_resource(
                TypeName="AWS::LocalStack::DoesNotExist", Identifier=nonexisting_identifier
            )
        snapshot.match("delete_nonexistingtype", e.value.response)

        delete_nonexistingresource = aws_client.cloudcontrol.delete_resource(
            TypeName="AWS::S3::Bucket", Identifier=nonexisting_identifier
        )
        snapshot.match("delete_nonexistingresource", delete_nonexistingresource)

        # get
        with pytest.raises(aws_client.cloudcontrol.exceptions.TypeNotFoundException) as e:
            aws_client.cloudcontrol.get_resource(
                TypeName="AWS::LocalStack::DoesNotExist", Identifier=nonexisting_identifier
            )
        snapshot.match("get_nonexistingtype", e.value.response)

        with pytest.raises(aws_client.cloudcontrol.exceptions.ResourceNotFoundException) as e:
            aws_client.cloudcontrol.get_resource(
                TypeName="AWS::S3::Bucket", Identifier=nonexisting_identifier
            )
        # TODO
        # snapshot.match("get_nonexisting", e.value.response)

        # update
        with pytest.raises(aws_client.cloudcontrol.exceptions.TypeNotFoundException) as e:
            aws_client.cloudcontrol.update_resource(
                TypeName="AWS::LocalStack::DoesNotExist",
                Identifier=nonexisting_identifier,
                PatchDocument=json.dumps([{"op": "replace", "path": "/something", "value": 30}]),
            )
        snapshot.match("update_nonexistingtype", e.value.response)

        with pytest.raises(aws_client.cloudcontrol.exceptions.ClientError) as e:
            aws_client.cloudcontrol.update_resource(
                TypeName="AWS::LocalStack::DoesNotExist",
                Identifier=nonexisting_identifier,
                PatchDocument=json.dumps([]),
            )
        snapshot.match("update_invalidpatchdocument", e.value.response)

        with pytest.raises(aws_client.cloudcontrol.exceptions.ResourceNotFoundException) as e:
            aws_client.cloudcontrol.update_resource(
                TypeName="AWS::S3::Bucket",
                Identifier=nonexisting_identifier,
                PatchDocument=json.dumps([{"op": "replace", "path": "/something", "value": 30}]),
            )
        # TODO
        # snapshot.match("update_nonexisting", e.value.response)

        # list
        with pytest.raises(aws_client.cloudcontrol.exceptions.TypeNotFoundException) as e:
            aws_client.cloudcontrol.list_resources(TypeName="AWS::LocalStack::DoesNotExist")
        snapshot.match("list_nonexistingtype", e.value.response)

    @markers.aws.validated
    def test_list_resources(self, create_resource, snapshot, aws_client):
        # TODO: test if only "terminal" states are included in lists (blocked by cfn registry)
        # TODO: test with custom type-version-id  (blocked by cfn registry)
        # TODO: test empty (blocked by cfn registry)

        bucket_name_prefix = f"cc-test-bucket-{short_uid()}"
        bucket_name_1 = f"{bucket_name_prefix}-1"
        bucket_name_2 = f"{bucket_name_prefix}-2"
        waiter = aws_client.cloudcontrol.get_waiter("resource_request_success")

        create_bucket_1 = create_resource(
            TypeName="AWS::S3::Bucket", DesiredState=json.dumps({"BucketName": bucket_name_1})
        )
        create_bucket_2 = create_resource(
            TypeName="AWS::S3::Bucket", DesiredState=json.dumps({"BucketName": bucket_name_2})
        )
        waiter.wait(RequestToken=create_bucket_1["ProgressEvent"]["RequestToken"])
        waiter.wait(RequestToken=create_bucket_2["ProgressEvent"]["RequestToken"])

        # test pagination
        paginator = aws_client.cloudcontrol.get_paginator("list_resources")

        list_paginated_first = paginator.paginate(
            TypeName="AWS::S3::Bucket", PaginationConfig={"MaxItems": 1}
        ).build_full_result()
        list_paginated_second = paginator.paginate(
            TypeName="AWS::S3::Bucket",
            PaginationConfig={"MaxItems": 1, "StartingToken": list_paginated_first["NextToken"]},
        ).build_full_result()
        list_paginated_all = paginator.paginate(TypeName="AWS::S3::Bucket").build_full_result()

        # verify that MaxItems works as expected
        assert len(list_paginated_first["ResourceDescriptions"]) == 1
        assert len(list_paginated_second["ResourceDescriptions"]) == 1
        # verify that using the NextToken, we actually received a different resource
        assert (
            list_paginated_first["ResourceDescriptions"][0]["Identifier"]
            != list_paginated_second["ResourceDescriptions"][0]["Identifier"]
        )
        # verify that when getting *all* of them, we at least get both
        assert len(list_paginated_all["ResourceDescriptions"]) >= 2

        list_paginated_all["ResourceDescriptions"] = [
            rd
            for rd in list_paginated_all["ResourceDescriptions"]
            if rd["Identifier"]
            in [
                bucket_name_1,
                bucket_name_2,
            ]  # need to filter here since there are probably other buckets in the account as well
        ]
        snapshot.match("list_paginated_all_filtered", list_paginated_all)

        with pytest.raises(aws_client.cloudcontrol.exceptions.TypeNotFoundException) as e:
            aws_client.cloudcontrol.list_resources(TypeName="AWS::DoesNot::Exist")
        snapshot.match("list_typenotfound_exc", e.value.response)

    @pytest.mark.skip(reason="advanced feature, will be added later")
    @markers.aws.validated
    def test_list_resources_with_resource_model(self, create_resource, snapshot, aws_client):
        """
        See: https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations-list.html
        """
        with pytest.raises(aws_client.cloudcontrol.exceptions.InvalidRequestException) as e:
            aws_client.cloudcontrol.list_resources(TypeName="AWS::ApiGateway::Stage")
        snapshot.match("missing_resource_model_exc", e.value.response)

        # TODO: actually set up rest API and AWS::ApiGateway::Stage for a positive sample

    @markers.aws.validated
    def test_double_create_with_client_token(self, create_resource, snapshot, aws_client):
        """
        ClientToken is used to deduplicate requests
        """
        bucket_name_prefix = f"cc-test-bucket-clienttoken-{short_uid()}"
        client_token = long_uid()
        snapshot.add_transformer(snapshot.transform.regex(client_token, "<client-token"))
        create_response = create_resource(
            TypeName="AWS::S3::Bucket",
            DesiredState=json.dumps({"BucketName": f"{bucket_name_prefix}-1"}),
            ClientToken=client_token,
        )
        snapshot.match("create_response", create_response)

        # another create, same token => request fails (even though it's a new desired state now!)
        with pytest.raises(aws_client.cloudcontrol.exceptions.ClientTokenConflictException) as e:
            create_resource(
                TypeName="AWS::S3::Bucket",
                DesiredState=json.dumps({"BucketName": f"{bucket_name_prefix}-2"}),
                ClientToken=client_token,
            )
        snapshot.match("create_response_duplicate_exc", e.value.response)

    @markers.aws.validated
    def test_create_exceptions(self, create_resource, snapshot, aws_client):
        """
        learnings:
        - the create call basically always passes, independent of desired state. The failure only shows up by checking the status
        - the exception to this is when specifying something that isn't included at all in the schema. (extra keys)
        """
        bucket_name = f"localstack-testing-{short_uid()}-1"
        waiter = aws_client.cloudcontrol.get_waiter("resource_request_success")

        create_bucket_response = create_resource(
            TypeName="AWS::S3::Bucket", DesiredState=json.dumps({"BucketName": bucket_name})
        )
        snapshot.match("create_response", create_bucket_response)
        waiter.wait(RequestToken=create_bucket_response["ProgressEvent"]["RequestToken"])

        # 1. duplicate identifier
        create_duplicate_response = create_resource(
            TypeName="AWS::S3::Bucket", DesiredState=json.dumps({"BucketName": bucket_name})
        )
        snapshot.match("create_duplicate_response", create_duplicate_response)
        with pytest.raises(WaiterError):
            waiter.wait(RequestToken=create_duplicate_response["ProgressEvent"]["RequestToken"])

        post_wait_response = aws_client.cloudcontrol.get_resource_request_status(
            RequestToken=create_duplicate_response["ProgressEvent"]["RequestToken"]
        )
        snapshot.match("duplicate_post_wait_response", post_wait_response)
        assert post_wait_response["ProgressEvent"]["OperationStatus"] == OperationStatus.FAILED

        # 2. missing required properties

        # in this case only the BucketName has to be provided
        create_missingproperty_response = create_resource(
            TypeName="AWS::S3::Bucket", DesiredState=json.dumps({})
        )
        snapshot.match("create_missingproperty_response", create_missingproperty_response)
        waiter.wait(RequestToken=create_missingproperty_response["ProgressEvent"]["RequestToken"])
        missing_post_wait_response = aws_client.cloudcontrol.get_resource_request_status(
            RequestToken=create_missingproperty_response["ProgressEvent"]["RequestToken"]
        )
        snapshot.match("missing_post_wait_response", missing_post_wait_response)

        # 3. additional properties not in spec
        with pytest.raises(aws_client.cloudcontrol.exceptions.ClientError) as e:
            create_resource(
                TypeName="AWS::S3::Bucket",
                DesiredState=json.dumps({"BucketName": bucket_name, "BucketSomething": "hello"}),
            )
        snapshot.match("create_extra_property_exc", e.value.response)

    @markers.aws.validated
    def test_create_invalid_desiredstate(self, snapshot, aws_client):
        with pytest.raises(aws_client.cloudcontrol.exceptions.ClientError) as e:
            aws_client.cloudcontrol.create_resource(
                TypeName="AWS::S3::Bucket",
                DesiredState=json.dumps({"DOESNOTEXIST": "invalidvalue"}),
            )
        snapshot.match("create_invalid_state_exc_invalid_field", e.value.response)

        with pytest.raises(aws_client.cloudcontrol.exceptions.ClientError) as e:
            aws_client.cloudcontrol.create_resource(
                TypeName="AWS::S3::Bucket", DesiredState=json.dumps({"BucketName": True})
            )
        snapshot.match("create_invalid_state_exc_invalid_type", e.value.response)

    # TODO: updates
    @markers.aws.validated
    def test_update(self, create_resource, snapshot, aws_client):
        bucket_name = f"localstack-testing-cc-{short_uid()}"
        initial_state = {"BucketName": bucket_name}
        create_response = create_resource(
            TypeName="AWS::S3::Bucket", DesiredState=json.dumps(initial_state)
        )
        waiter = aws_client.cloudcontrol.get_waiter("resource_request_success")
        waiter.wait(RequestToken=create_response["ProgressEvent"]["RequestToken"])

        # add a property that didn't exist before
        second_state = {"BucketName": bucket_name, "Tags": [{"Key": "a", "Value": "123"}]}
        patch = jsonpatch.make_patch(initial_state, second_state).patch
        update_response = aws_client.cloudcontrol.update_resource(
            TypeName="AWS::S3::Bucket",
            Identifier=create_response["ProgressEvent"]["Identifier"],
            PatchDocument=json.dumps(patch),
        )
        waiter.wait(RequestToken=update_response["ProgressEvent"]["RequestToken"])

        # update something that doesn't require a replacement
        third_state = {"BucketName": bucket_name, "Tags": [{"Key": "b", "Value": "234"}]}
        patch = jsonpatch.make_patch(second_state, third_state).patch
        update_response = aws_client.cloudcontrol.update_resource(
            TypeName="AWS::S3::Bucket",
            Identifier=create_response["ProgressEvent"]["Identifier"],
            PatchDocument=json.dumps(patch),
        )
        waiter.wait(RequestToken=update_response["ProgressEvent"]["RequestToken"])

        # try to update something that *DOES* require a replacement
        # this leads to an NotUpdatableException while on cloudformation this would cause a replacement
        final_state = {"BucketName": f"{bucket_name}plus", "Tags": [{"Key": "b", "Value": "234"}]}
        patch = jsonpatch.make_patch(third_state, final_state).patch
        with pytest.raises(aws_client.cloudcontrol.exceptions.NotUpdatableException) as e:
            aws_client.cloudcontrol.update_resource(
                TypeName="AWS::S3::Bucket",
                Identifier=create_response["ProgressEvent"]["Identifier"],
                PatchDocument=json.dumps(patch),
            )
        snapshot.match("update_createonlyproperty_exc", e.value.response)


@pytest.mark.skip("Not Implemented yet")
class TestCloudControlResourceRequestApi:
    @markers.aws.validated
    def test_invalid_request_token_exc(self, snapshot, aws_client):
        """Test behavior of methods when invoked with non-existing RequestToken"""
        with pytest.raises(aws_client.cloudcontrol.exceptions.RequestTokenNotFoundException) as e1:
            aws_client.cloudcontrol.get_resource_request_status(RequestToken="DOESNOTEXIST")
        snapshot.match("get_token_not_found", e1.value.response)

        with pytest.raises(aws_client.cloudcontrol.exceptions.RequestTokenNotFoundException) as e2:
            aws_client.cloudcontrol.cancel_resource_request(RequestToken="DOESNOTEXIST")
        snapshot.match("cancel_token_not_found", e2.value.response)

    @markers.aws.validated
    def test_list_request_status(self, snapshot, create_resource, aws_client):
        """
        This is a bit tricky to test against AWS because these lists are not manually "clearable" and instead are cleared after some time (7 days?)
        To accommodate for this we manually filter the resources here before snapshotting the response list.
        Even with this though we run into issues when paging. So at some point when testing this too much we'll have way too many resource requests in the account. :thisisfine:

        Interesting observation:
        * Some resource requests can have an OperationStatus of 'FAILED',
            even though the resource type doesn't even exist and they do *NOT* have an 'Operation' field for some reason.
            This means when we add a Filter for Operation, even though we have all Fields active, we won't see these entries.

        TODO: test pagination
        TODO: more control over resource states (otherwise this test might turn out to be too flaky)
        """

        bucket_name = f"cc-test-list-bucket-{short_uid()}"

        def filter_response_by_request_token(response, request_tokens):
            """this method mutates the response (!)"""
            response["ResourceRequestStatusSummaries"] = [
                s
                for s in response["ResourceRequestStatusSummaries"]
                if s["RequestToken"] in request_tokens
            ]

        create_bucket_resource = create_resource(
            TypeName="AWS::S3::Bucket", DesiredState=json.dumps({"BucketName": bucket_name})
        )
        bucket_request_token = create_bucket_resource["ProgressEvent"]["RequestToken"]
        snapshot.match("create_bucket_resource", create_bucket_resource)

        # by default no filter should be equal to specifying all OperationStatuses
        paginator = aws_client.cloudcontrol.get_paginator("list_resource_requests")
        list_requests_response_default = paginator.paginate().build_full_result()
        list_requests_response_all = paginator.paginate(
            ResourceRequestStatusFilter={
                "OperationStatuses": [
                    OperationStatus.PENDING,
                    OperationStatus.IN_PROGRESS,
                    OperationStatus.SUCCESS,
                    OperationStatus.FAILED,
                    OperationStatus.CANCEL_IN_PROGRESS,
                    OperationStatus.CANCEL_COMPLETE,
                ],
            }
        ).build_full_result()
        assert len(list_requests_response_default["ResourceRequestStatusSummaries"]) == len(
            list_requests_response_all["ResourceRequestStatusSummaries"]
        )

        list_requests_response_filtered = paginator.paginate(
            ResourceRequestStatusFilter={
                "Operations": [
                    Operation.CREATE,
                ]
            }
        ).build_full_result()
        filter_response_by_request_token(list_requests_response_filtered, [bucket_request_token])
        snapshot.match("list_requests_response_filtered", list_requests_response_filtered)

        # doing the same request but filtering for a different operation, should not find the create bucket operation
        list_requests_response_filtered_update = paginator.paginate(
            ResourceRequestStatusFilter={
                "Operations": [
                    Operation.UPDATE,
                ]
            }
        ).build_full_result()
        filter_response_by_request_token(
            list_requests_response_filtered_update, [bucket_request_token]
        )
        snapshot.match(
            "list_requests_response_filtered_update", list_requests_response_filtered_update
        )

    @pytest.mark.skip(reason="needs a more complicated test setup")
    @markers.aws.validated
    def test_get_request_status(self, snapshot, aws_client):
        """
        Tries to trigger all states ("CANCEL_COMPLETE", "CANCEL_IN_PROGRESS", "FAILED", "IN_PROGRESS", "PENDING", "SUCCESS")

        TODO: write a custom resource that can be controlled for this purpose
            For now we just assume some things on AWS to get a coarse understanding
        """
        # 1. PENDING (this makes use of the fact that only one operation for a resource can run at the same time)
        # 2. IN_PROGRESS (just some resource that is fairly slow to create (even buckets take a while...)
        # 3. SUCCESS - should be clear
        # 4. CANCEL_IN_PROGRESS - same as 2
        # 5. CANCEL_COMPLETE - same as 2
        # 6. FAILED - ? not sure yet ?
        pass

    @markers.aws.validated
    def test_cancel_request(self, snapshot, create_resource, aws_client):
        """
        Creates a resource & immediately cancels the create request

        Observation:
        * Even though the status is "CANCEL_COMPLETE", the bucket might still have been created!
        * There is no rollback, a cancel simply stops the handler from continuing but will not cause it to revert what it did so far.
        * cancel_resource_request is "idempotent" and will not fail when it has already been canceled

        TODO: make this more reliable via custom resource that waits for an event to change state
              would allow us to have finer control over it and properly test non-terminal states
        """
        bucket_name = f"cc-test-bucket-cancel-{short_uid()}"
        create_response = create_resource(
            TypeName="AWS::S3::Bucket", DesiredState=json.dumps({"BucketName": bucket_name})
        )
        snapshot.match("create_response", create_response)

        # this is not 100% reliable, depending on how fast the request above is processed.
        cancel_response = aws_client.cloudcontrol.cancel_resource_request(
            RequestToken=create_response["ProgressEvent"]["RequestToken"]
        )
        assert cancel_response["ProgressEvent"]["OperationStatus"] in [
            OperationStatus.CANCEL_IN_PROGRESS,
            OperationStatus.CANCEL_COMPLETE,
        ]

        def wait_for_cc_canceled(request_token):
            def _wait_for_canceled():
                resp = aws_client.cloudcontrol.get_resource_request_status(
                    RequestToken=request_token
                )
                op_status = resp["ProgressEvent"]["OperationStatus"]
                if op_status in [OperationStatus.FAILED, OperationStatus.SUCCESS]:
                    raise ShortCircuitWaitException()
                return op_status == OperationStatus.CANCEL_COMPLETE

            return _wait_for_canceled

        assert wait_until(wait_for_cc_canceled(cancel_response["ProgressEvent"]["RequestToken"]))
        snapshot.match(
            "cancel_request_status",
            aws_client.cloudcontrol.get_resource_request_status(
                RequestToken=cancel_response["ProgressEvent"]["RequestToken"]
            ),
        )

        cancel_again_response = aws_client.cloudcontrol.cancel_resource_request(
            RequestToken=create_response["ProgressEvent"]["RequestToken"]
        )
        snapshot.match("cancel_again_response", cancel_again_response)
        assert wait_until(
            wait_for_cc_canceled(cancel_again_response["ProgressEvent"]["RequestToken"])
        )

    @pytest.mark.parametrize(
        "desired_state",
        [json.dumps({"BucketName": "<bucket-name>"}), json.dumps({})],
        ids=["SUCCESS", "FAIL"],
    )
    @markers.aws.validated
    def test_cancel_edge_cases(self, create_resource, snapshot, desired_state, aws_client):
        """tests canceling a resource request that is in a SUCCESS or FAILED terminal state"""

        # success
        bucket_name = f"cc-test-bucket-cancel-{short_uid()}"
        create_response = create_resource(
            TypeName="AWS::S3::Bucket",
            DesiredState=desired_state.replace("<bucket-name>", bucket_name),
        )
        snapshot.add_transformer(
            snapshot.transform.regex(
                create_response["ProgressEvent"]["RequestToken"], "<create-request-token>"
            )
        )
        snapshot.match("create_response", create_response)
        try:
            aws_client.cloudcontrol.get_waiter("resource_request_success").wait(
                RequestToken=create_response["ProgressEvent"]["RequestToken"]
            )
        except Exception:
            pass  # just want to make sure it's in a terminal state here

        with pytest.raises(aws_client.cloudcontrol.exceptions.ClientError) as e:
            aws_client.cloudcontrol.cancel_resource_request(
                RequestToken=create_response["ProgressEvent"]["RequestToken"]
            )
        snapshot.match("cancel_in_success_exc", e.value.response)
