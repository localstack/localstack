from localstack.utils.aws import aws_stack, aws_responses
from localstack.utils.common import replace_response_content, parse_request_data
from localstack.utils.tagging import TaggingService
from localstack.services.generic_proxy import ProxyListener

XMLNS_CLOUDWATCH = ''

TAGS = TaggingService()


class ProxyListenerCloudWatch(ProxyListener):

    def forward_request(self, method, path, data, headers):
        req_data = parse_request_data(method, path, data)
        action = req_data.get('Action')
        if action == 'TagResource':
            arn = req_data.get('ResourceARN')
            tags = aws_stack.extract_tags(req_data)
            TAGS.tag_resource(arn, tags)
            return aws_responses.requests_response_xml(action, {}, xmlns=XMLNS_CLOUDWATCH)
        if action == 'UntagResource':
            arn = req_data.get('ResourceARN')
            tag_names = [v for k, v in req_data.items() if k.startswith('TagKeys.member.')]
            TAGS.untag_resource(arn, tag_names)
            return aws_responses.requests_response_xml(action, {}, xmlns=XMLNS_CLOUDWATCH)
        if action == 'ListTagsForResource':
            arn = req_data.get('ResourceARN')
            tags = TAGS.list_tags_for_resource(arn)
            result = {'Tags': {'member': tags.get('Tags', [])}}
            return aws_responses.requests_response_xml(action, result, xmlns=XMLNS_CLOUDWATCH)
        return True

    def return_response(self, method, path, data, headers, response):
        # Fix Incorrect date format to the correct format
        # the dictionary contains the tag as the key and the value is a
        # tuple (pattern, replacement)
        regexes1 = (r'<{}>([^<]+) ([^<+]+)(\+[^<]*)?</{}>', r'<{}>\1T\2Z</{}>')
        regexes2 = (r'<{}>([^<]+) ([^<+.]+)(\.[^<]*)?</{}>', r'<{}>\1T\2Z</{}>')
        timestamp_tags = {
            'AlarmConfigurationUpdatedTimestamp': regexes1,
            'StateUpdatedTimestamp': regexes1,
            'member': regexes2
        }

        for tag, value in timestamp_tags.items():
            pattern, replacement = value
            self.fix_date_format(response, tag, pattern, replacement)
        response.headers['Content-Length'] = len(response.content)
        return response

    def fix_date_format(self, response, timestamp_tag, pattern, replacement):
        """ Normalize date to correct format"""
        pattern = pattern.format(timestamp_tag, timestamp_tag)
        replacement = replacement.format(timestamp_tag, timestamp_tag)
        replace_response_content(response, pattern, replacement)


# instantiate listener
UPDATE_CLOUD_WATCH = ProxyListenerCloudWatch()
