import re
import json
from requests.models import Request, Response
from localstack.utils.common import to_str, now
from localstack.constants import APPLICATION_AMZ_JSON_1_1
from localstack.services.generic_proxy import ProxyListener

subscription_filters = []


def handle_put_subscription_filter(data):
    data = json.loads(data)
    filter_name = data.get('filterName')
    log_group_name = data.get('logGroupName')
    filter_pattern = data.get('filterPattern')
    destination_arn = data.get('destinationArn')
    role_arn = data.get('roleArn')
    creation_time = now()

    subscription_filters.append({
        'filterName': filter_name,
        'logGroupName': log_group_name,
        'filterPattern': filter_pattern,
        'destinationArn': destination_arn,
        'roleArn': role_arn,
        'distribution': 'ByLogStream',
        'creationTime': creation_time,
    }
    )
    response = Response()
    response.status_code = 200
    response._content = ''
    return response


def get_subscription_filters_by_log_group_name(log_group_name):
    filters = []
    for filter in subscription_filters:
        if filter.get('logGroupName') == log_group_name:
            filters.append(filter)
    return filters


def handle_describe_subscription_filters(response_content, log_group_name):
    data = json.loads(response_content)
    existing_filters = data.get('subscriptionFilters')
    subscription_filters = get_subscription_filters_by_log_group_name(log_group_name)
    existing_filters.extend(subscription_filters)
    data['subscriptionFilters'] = existing_filters
    return data


class ProxyListenerCloudWatchLogs(ProxyListener):
    def forward_request(self, method, path, data, headers):
        if method == 'POST' and path == '/':
            if 'nextToken' in to_str(data or ''):
                data = self._fix_next_token_request(data)
                headers['content-length'] = str(len(data))
                return Request(data=data, headers=headers, method=method)

        if method == 'POST' and path == '/' and ('logGroupName' in to_str(data or '')) and \
                ('filterName' in to_str(data or '')):
            return handle_put_subscription_filter(to_str(data))

        return True

    def return_response(self, method, path, data, headers, response):
        # Fix Incorrect response content-type header from cloudwatch logs #1343
        response.headers['content-type'] = APPLICATION_AMZ_JSON_1_1

        if 'nextToken' in to_str(response.content or ''):
            self._fix_next_token_response(response)
            response.headers['content-length'] = str(len(response._content))

        if method == 'POST' and 'subscriptionFilters' in to_str(response.content or ''):
            data = json.loads(data)
            response._content = json.dumps(handle_describe_subscription_filters(to_str(response.content),
                                                                                data.get('logGroupName')))
            response.headers['content-length'] = str(len(response.content))

    @staticmethod
    def _fix_next_token_request(data):
        # Fix for https://github.com/localstack/localstack/issues/1527
        pattern = r'"nextToken":\s*"([0-9]+)"'
        replacement = r'"nextToken": \1'
        return re.sub(pattern, replacement, to_str(data))

    @staticmethod
    def _fix_next_token_response(response):
        # Fix for https://github.com/localstack/localstack/issues/1527
        pattern = r'"nextToken":\s*([0-9]+)'
        replacement = r'"nextToken": "\1"'
        response._content = re.sub(pattern, replacement, to_str(response.content))


# instantiate listener
UPDATE_LOGS = ProxyListenerCloudWatchLogs()
