import json
import logging
import re

from requests.models import Request

from localstack.services.generic_proxy import ProxyListener
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_responses import set_response_content
from localstack.utils.common import to_str

LOG = logging.getLogger(__name__)

SM_ARN_REGEX = r'(arn:aws:states):([^:]+):([^:]+:(stateMachine|execution)):((([^_]+)_)?([^"]+))'
default_region = "us-east-1"


class ProxyListenerStepFunctions(ProxyListener):
    def forward_request(self, method, path, data, headers):
        if method == "OPTIONS":
            return 200
        data = json.loads(to_str(data or "{}"))
        region_name = aws_stack.get_region()
        if data.get("name"):
            # inject region name as prefix, as StepFunctions is currently not capable of handling multi-region requests
            data["name"] = f"{region_name}_{data['name']}"

        data = json.dumps(data)
        replace = r"\1:%s:\3:\2_\5" % default_region
        data_replaced = re.sub(SM_ARN_REGEX, replace, data)
        return Request(method=method, data=data_replaced, headers=headers)

    def return_response(self, method, path, data, headers, response):
        data = json.loads(to_str(data or "{}"))
        name = data.get("name") or (data.get("stateMachineArn") or "").split(":")[-1]
        target = headers.get("X-Amz-Target", "").split(".")[-1]

        # publish event
        if target == "CreateStateMachine":
            event_publisher.fire_event(
                event_publisher.EVENT_STEPFUNCTIONS_CREATE_SM,
                payload={"m": event_publisher.get_hash(name)},
            )
        elif target == "DeleteStateMachine":
            event_publisher.fire_event(
                event_publisher.EVENT_STEPFUNCTIONS_DELETE_SM,
                payload={"m": event_publisher.get_hash(name)},
            )

        content = to_str(response.content or "") or "{}"
        replace = r"\1:\7:\3:\8"
        content = re.sub(SM_ARN_REGEX, replace, content)
        content = json.loads(content)

        def fix_name(obj):
            if obj.get("name"):
                obj["name"] = re.sub(r"^([^_]+)_(.*)", r"\2", obj["name"])

        fix_name(content)
        machines = content.get("stateMachines")
        if machines:
            region_part = ":%s:" % aws_stack.get_region()
            machines = [sm for sm in machines if region_part in sm["stateMachineArn"]]
            for machine in machines:
                fix_name(machine)
            content["stateMachines"] = machines

        content = json.dumps(content)
        set_response_content(response, content)


# instantiate listener
UPDATE_STEPFUNCTIONS = ProxyListenerStepFunctions()
