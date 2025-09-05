import logging
import os
import textwrap
import time
import uuid
from threading import Thread
from typing import TYPE_CHECKING

import requests

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

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
                LOG.info("signalling url %s", url)

                payload = {
                    "Status": "SUCCESS",
                    "Reason": "Wait condition reached",
                    "UniqueId": str(uuid.uuid4()),
                    "Data": "Application has completed configuration.",
                }
                r = self.session.put(url, json=payload)
                LOG.debug("status from signalling: %s", r.status_code)
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


@markers.snapshot.skip_snapshot_verify(paths=["$..WaitConditionName"])
@markers.aws.validated
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
                os.path.dirname(__file__), "../../../templates/cfn_waitcondition.yaml"
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


@markers.aws.validated
def test_create_macro(deploy_cfn_template, create_lambda_function, snapshot, aws_client):
    macro_name = f"macro-{short_uid()}"
    snapshot.add_transformer(snapshot.transform.regex(macro_name, "<macro-name>"))

    function_name = f"macro_lambda_{short_uid()}"

    handler_code = textwrap.dedent(
        """
    def handler(event, context):
        pass
    """
    )

    create_lambda_function(
        func_name=function_name,
        handler_file=handler_code,
        runtime=Runtime.python3_12,
    )

    template_path = os.path.join(os.path.dirname(__file__), "../../../templates/macro_resource.yml")
    assert os.path.isfile(template_path)
    stack = deploy_cfn_template(
        template_path=template_path,
        parameters={
            "FunctionName": function_name,
            "MacroName": macro_name,
        },
    )

    snapshot.match("stack-outputs", stack.outputs)
