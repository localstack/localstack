import re
from localstack.utils.aws import aws_stack


def get_rest_api_paths(rest_api_id):
    apigateway = aws_stack.connect_to_service(service_name='apigateway')
    resources = apigateway.get_resources(restApiId=rest_api_id, limit=100)
    resource_map = {}
    for resource in resources['items']:
        path = aws_stack.get_apigateway_path_for_resource(rest_api_id, resource['id'])
        resource_map[path] = resource
    return resource_map


def get_resource_for_path(path, path_map):
    matches = []
    for api_path, details in path_map.items():
        api_path_regex = re.sub(r'\{[^\+]+\+\}', r'[^\?#]+', api_path)
        api_path_regex = re.sub(r'\{[^\}]+\}', r'[^/]+', api_path_regex)
        if re.match(r'^%s$' % api_path_regex, path):
            matches.append((api_path, details))
    if not matches:
        return None
    if len(matches) > 1:
        # check if we have an exact match
        for match in matches:
            if match[0] == path:
                return match
        raise Exception('Ambiguous API path %s - matches found: %s' % (path, matches))
    return matches[0]
