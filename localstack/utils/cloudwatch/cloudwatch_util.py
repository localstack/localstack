import json
from datetime import datetime, timedelta
from flask import Response
from localstack import config
from localstack.utils.common import now_utc, make_http_request, to_str
from localstack.utils.aws import aws_stack


# ---------------
# Lambda metrics
# ---------------

def dimension_lambda(kwargs):
    func_name = kwargs.get('func_name')
    if not func_name:
        func_name = kwargs.get('func_arn').split(':function:')[1].split(':')[0]
    return [{
        'Name': 'FunctionName',
        'Value': func_name
    }]


def publish_lambda_metric(metric, value, kwargs):
    # publish metric only if CloudWatch service is available
    if not config.service_port('cloudwatch'):
        return
    cw_client = aws_stack.connect_to_service('cloudwatch')
    cw_client.put_metric_data(Namespace='AWS/Lambda',
        MetricData=[{
            'MetricName': metric,
            'Dimensions': dimension_lambda(kwargs),
            'Timestamp': datetime.now(),
            'Value': value
        }]
    )


def publish_lambda_duration(time_before, kwargs):
    time_after = now_utc()
    publish_lambda_metric('Duration', time_after - time_before, kwargs)


def publish_lambda_error(time_before, kwargs):
    publish_lambda_metric('Invocations', 1, kwargs)
    publish_lambda_metric('Errors', 1, kwargs)


def publish_lambda_result(time_before, result, kwargs):
    if isinstance(result, Response) and result.status_code >= 400:
        return publish_lambda_error(time_before, kwargs)
    publish_lambda_metric('Invocations', 1, kwargs)


# ---------------
# Helper methods
# ---------------


# TODO: this is a backdoor based hack until get_metric_statistics becomes available in moto
def get_metric_statistics(Namespace, MetricName, Dimensions,
        Period=60, StartTime=None, EndTime=None, Statistics=None):
    if not StartTime:
        StartTime = datetime.now() - timedelta(minutes=5)
    if not EndTime:
        EndTime = datetime.now()
    if Statistics is None:
        Statistics = ['Sum']
    cloudwatch_url = aws_stack.get_local_service_url('cloudwatch')
    url = '%s/?Action=GetMetricValues' % cloudwatch_url
    all_metrics = make_http_request(url)
    assert all_metrics.status_code == 200
    datapoints = []
    for datapoint in json.loads(to_str(all_metrics.content)):
        if datapoint['Namespace'] == Namespace and datapoint['Name'] == MetricName:
            dp_dimensions = datapoint['Dimensions']
            all_present = all(m in dp_dimensions for m in Dimensions)
            no_additional = all(m in Dimensions for m in dp_dimensions)
            if all_present and no_additional:
                datapoints.append(datapoint)
    result = {
        'Label': '%s/%s' % (Namespace, MetricName),
        'Datapoints': datapoints
    }
    return result


def publish_result(ns, time_before, result, kwargs):
    if ns == 'lambda':
        publish_lambda_result(time_before, result, kwargs)


def publish_error(ns, time_before, e, kwargs):
    if ns == 'lambda':
        publish_lambda_error(time_before, kwargs)


def cloudwatched(ns):
    """ @cloudwatched(...) decorator for annotating methods to be monitored via CloudWatch """
    def wrapping(func):
        def wrapped(*args, **kwargs):
            time_before = now_utc()
            result = None
            try:
                result = func(*args, **kwargs)
                publish_result(ns, time_before, result, kwargs)
            except Exception as e:
                publish_error(ns, time_before, e, kwargs)
                raise e
            finally:
                # TODO
                # time_after = now_utc()
                pass
            return result
        return wrapped
    return wrapping
