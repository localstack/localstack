from moto.cloudwatch.models import cloudwatch_backends

from localstack.services.generic_proxy import ProxyListener
from localstack.utils.aws import aws_stack

# path for backdoor API to receive raw metrics
PATH_GET_RAW_METRICS = "/cloudwatch/metrics/raw"


class ProxyListenerCloudWatch(ProxyListener):
    def forward_request(self, method, path, data, headers):
        # TODO: solve with custom url routing rules for ASF providers
        if path.startswith(PATH_GET_RAW_METRICS):
            result = cloudwatch_backends[aws_stack.get_region()].metric_data
            result = [
                {
                    "ns": r.namespace,
                    "n": r.name,
                    "v": r.value,
                    "t": r.timestamp,
                    "d": [{"n": d.name, "v": d.value} for d in r.dimensions],
                }
                for r in result
            ]
            return {"metrics": result}
        return True


# instantiate listener
UPDATE_CLOUD_WATCH = ProxyListenerCloudWatch()
