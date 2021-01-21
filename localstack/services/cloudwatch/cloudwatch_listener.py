from localstack.utils.common import _replace
from localstack.services.generic_proxy import ProxyListener


class ProxyListenerCloudWatch(ProxyListener):

    def return_response(self, method, path, data, headers, response):
        # Fix Incorrect date format to the correct format
        # the dictionary contains the tag as the key and the value is a
        # tuple (pattern, replacement)
        timestamp_tags = {
            'AlarmConfigurationUpdatedTimestamp':
            (r'<{}>([^<]+) ([^<+]+)(\+[^<]*)?</{}>', r'<{}>\1T\2Z</{}>'),
            'StateUpdatedTimestamp':
            (r'<{}>([^<]+) ([^<+]+)(\+[^<]*)?</{}>', r'<{}>\1T\2Z</{}>'),
            'member':
            (r'<{}>([^<]+) ([^<+.]+)(\.[^<]*)?</{}>', r'<{}>\1T\2Z</{}>')

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
        _replace(response, pattern, replacement)


# instantiate listener
UPDATE_CLOUD_WATCH = ProxyListenerCloudWatch()
