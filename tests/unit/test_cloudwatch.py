import unittest

from requests.models import Response

from localstack.services.cloudwatch.cloudwatch_listener import UPDATE_CLOUD_WATCH


class CloudWatchTest(unittest.TestCase):
    def test_date_format(self):
        request_data = {}
        response = Response()
        response.status_code = 200
        response._content = (
            "<AlarmConfigurationUpdatedTimestamp>"
            "2020-10-15 21:33:48.343646"
            "</AlarmConfigurationUpdatedTimestamp>"
            "<StateUpdatedTimestamp>"
            "2020-10-15 21:33:48.343651"
            "</StateUpdatedTimestamp>"
        )
        response = UPDATE_CLOUD_WATCH.return_response("POST", "/", request_data, {}, response)
        response_content = (
            "<AlarmConfigurationUpdatedTimestamp>"
            "2020-10-15T21:33:48.343646Z"
            "</AlarmConfigurationUpdatedTimestamp>"
            "<StateUpdatedTimestamp>"
            "2020-10-15T21:33:48.343651Z"
            "</StateUpdatedTimestamp>"
        )
        self.assertEqual(response_content, response.content)
