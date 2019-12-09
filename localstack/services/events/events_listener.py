import json
import os
import re
import uuid

from requests.models import Response

from localstack import config
from localstack.constants import TEST_AWS_ACCOUNT_ID, MOTO_ACCOUNT_ID
from localstack.services.generic_proxy import ProxyListener
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str, save_file, TMP_FILES, mkdir

EVENTS_TMP_DIR = os.path.join(config.TMP_FOLDER, 'cw_events')


class ProxyListenerEvents(ProxyListener):

    def forward_request(self, method, path, data, headers):
        action = headers.get('X-Amz-Target')
        if method == 'POST' and path == '/' and action == 'AWSEvents.PutEvents':
            parsed_data = json.loads(to_str(data))
            events_with_added_uuid = list(
                map(lambda event: {'event': event, 'uuid': str(uuid.uuid4())}, parsed_data['Entries']))
            response_string = json.dumps(
                {'Entries': list(map(lambda event: {'EventId': event['uuid']}, events_with_added_uuid))})
            self._create_and_register_temp_dir()
            self._dump_events_to_files(events_with_added_uuid)
            response = Response()
            response.status_code = 200
            response._content = response_string
            return response
        if method == 'OPTIONS':
            return 200
        return True

    def return_response(self, method, path, data, headers, response, request_handler=None):
        if response.content:
            # fix hardcoded account ID in ARNs returned from this API
            self._fix_account_id(response)
            # fix dates returned from this API (fixes an issue with Terraform)
            self._fix_date_format(response)
            # fix content-length header
            response.headers['content-length'] = len(response._content)

    def _create_and_register_temp_dir(self):
        if EVENTS_TMP_DIR not in TMP_FILES:
            mkdir(EVENTS_TMP_DIR)
            TMP_FILES.append(EVENTS_TMP_DIR)

    def _dump_events_to_files(self, events_with_added_uuid):
        for event in events_with_added_uuid:
            save_file(os.path.join(EVENTS_TMP_DIR, event['uuid']), json.dumps(event['event']))

    def _fix_date_format(self, response):
        """ Normalize date to format '2019-06-13T18:10:09.1234Z' """
        pattern = r'<CreateDate>([^<]+) ([^<+]+)(\+[^<]*)?</CreateDate>'
        replacement = r'<CreateDate>\1T\2Z</CreateDate>'
        self._replace(response, pattern, replacement)

    def _fix_account_id(self, response):
        return aws_stack.fix_account_id_in_arns(
            response, existing=MOTO_ACCOUNT_ID, replace=TEST_AWS_ACCOUNT_ID)

    def _replace(self, response, pattern, replacement):
        content = to_str(response.content)
        response._content = re.sub(pattern, replacement, content)


# instantiate listener
UPDATE_EVENTS = ProxyListenerEvents()
