import os


# @pytest.mark.skip_snapshot_verify(paths=["$.."])
def test_waitconditionhandle(deploy_cfn_template, snapshot, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/cfn_waitconditionhandle.yaml"
        )
    )
    wait_handle_id = stack.outputs["WaitHandleId"]

    # TODO: more stringent tests
    assert wait_handle_id is not None
    # snapshot.match("waithandle_ref", wait_handle_id)
