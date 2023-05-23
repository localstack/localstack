import logging
import os
import time
import uuid
from threading import Thread
from typing import TYPE_CHECKING

import pytest
import requests

if TYPE_CHECKING:
    try:
        from mypy_boto3_ssm import SSMClient
    except ImportError:
        pass

LOG = logging.getLogger(__name__)

PARAMETER_NAME = "wait-handle-url"


class SignalSuccess(Thread):
    def __init__(self, client: "SSMClient"):
        Thread.__init__(self)
        self.client = client
        self.session = requests.Session()
        self.should_break = False

    def run(self):
        while not self.should_break:
            try:
                LOG.debug("fetching parameter")
                res = self.client.get_parameter(Name=PARAMETER_NAME)
                url = res["Parameter"]["Value"]
                LOG.info(f"signalling url {url}")

                payload = {
                    "Status": "SUCCESS",
                    "Reason": "Wait condition reached",
                    "UniqueId": str(uuid.uuid4()),
                    "Data": "Application has completed configuration.",
                }
                r = self.session.put(url, json=payload)
                LOG.debug(f"status from signalling: {r.status_code}")
                r.raise_for_status()
                LOG.debug("status signalled")
                break
            except self.client.exceptions.ParameterNotFound:
                LOG.warning("parameter not available, trying again")
                time.sleep(5)
            except Exception:
                LOG.exception("got python exception")
                raise

    def stop(self):
        self.should_break = True


@pytest.mark.skip_snapshot_verify(paths=["$..WaitConditionName"])
def test_waitcondition(deploy_cfn_template, snapshot, aws_client):
    """
    Complicated test, since we have a wait condition that must signal
    a successful value to before the stack finishes. We use the
    fact that CFn will deploy the SSM parameter before moving on
    to the wait condition itself, so in a background thread we
    try to set the value to success so that the stack will
    deploy correctly.
    """
    signal_thread = SignalSuccess(aws_client.ssm)
    signal_thread.daemon = True
    signal_thread.start()

    try:
        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/cfn_waitcondition.yaml"
            ),
            parameters={"ParameterName": PARAMETER_NAME},
        )
    finally:
        signal_thread.stop()

    wait_handle_id = stack.outputs["WaitHandleId"]
    wait_condition_name = stack.outputs["WaitConditionRef"]

    # TODO: more stringent tests
    assert wait_handle_id is not None
    # snapshot.match("waithandle_ref", wait_handle_id)
    snapshot.match("waitcondition_ref", {"WaitConditionName": wait_condition_name})
