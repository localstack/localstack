import gzip
from requests.models import Request
from localstack.utils.common import _replace
from localstack.services.generic_proxy import ProxyListener

GZIP_ENCODING = 'GZIP'
IDENTITY_ENCODING = 'IDENTITY'


class ProxyListenerCloudWatch(ProxyListener):
    def forward_request(self, method, path, data, headers):
        encoding_type = headers.get('content-encoding') or ''
        if encoding_type.upper() == GZIP_ENCODING:
            headers.set('content-encoding', IDENTITY_ENCODING)
            data = gzip.decompress(data)
            return Request(data=data, headers=headers, method=method)

        return True

    def return_response(self, method, path, data, headers, response):
        # Fix Incorrect date format to iso 8601
        timestamp_tags = [
            'AlarmConfigurationUpdatedTimestamp',
            'StateUpdatedTimestamp'
        ]
        for tag in timestamp_tags:
            self.fix_date_format(response, tag)
        response.headers['content-length'] = len(response.content)
        return response

    def fix_date_format(self, response, timestamp_tag):
        """ Normalize date to format '2019-06-13T18:10:09.1234Z' """
        pattern = r'<{}>([^<]+) ([^<+]+)(\+[^<]*)?</{}>'.format(timestamp_tag, timestamp_tag)
        replacement = r'<{}>\1T\2Z</{}>'.format(timestamp_tag, timestamp_tag)
        _replace(response, pattern, replacement)


# instantiate listener
UPDATE_CLOUD_WATCH = ProxyListenerCloudWatch()
