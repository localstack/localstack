import re
from datetime import datetime
from localstack.utils.common import to_str
from localstack.services.generic_proxy import ProxyListener


class ProxyListenerCloudWatch(ProxyListener):

    def return_response(self, method, path, data, headers, response):
        # Fix Incorrect date format to iso 8601
        str_content = to_str(response.content)
        date_tag_regex = '<AlarmConfigurationUpdatedTimestamp>(.*?)</AlarmConfigurationUpdatedTimestamp>'
        replace_str = '<AlarmConfigurationUpdatedTimestamp>%s</AlarmConfigurationUpdatedTimestamp>'
        str_content = self.update_date_format(str_content, date_tag_regex, replace_str)
        date_tag_regex = '<StateUpdatedTimestamp>(.*?)</StateUpdatedTimestamp>'
        replace_str = '<StateUpdatedTimestamp>%s</StateUpdatedTimestamp>'
        str_content = self.update_date_format(str_content, date_tag_regex, replace_str)
        response.headers['content-length'] = len(str_content)
        response._content = str.encode(str_content)

    def update_date_format(self, str_content, date_tag_regex, replace_str):
        search_result = re.compile(date_tag_regex).search(str_content)
        if search_result:
            date = datetime.strptime(search_result.group(1), '%Y-%m-%d %H:%M:%S.%f')
            date_iso = date.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            str_content = str_content.replace(
                replace_str % search_result.group(1),
                replace_str % date_iso
            )
        return str_content


# instantiate listener
UPDATE_CLOUD_WATCH = ProxyListenerCloudWatch()
