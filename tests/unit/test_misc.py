import time
from requests.models import Response
from localstack.utils.aws import aws_stack
from localstack.services.generic_proxy import GenericProxy, ProxyListener
from localstack.utils.common import download, parallelize, TMP_FILES, load_file


def test_environment():
    env = aws_stack.Environment.from_json({'prefix': 'foobar1'})
    assert env.prefix == 'foobar1'
    env = aws_stack.Environment.from_string('foobar2')
    assert env.prefix == 'foobar2'


# This test is not enabled in CI, it is just used for manual
# testing to debug https://github.com/localstack/localstack/issues/213
def run_parallel_download():

    file_length = 10000000

    class DownloadListener(ProxyListener):

        def forward_request(self, method, path, data, headers):
            sleep_time = int(path.replace('/', ''))
            time.sleep(sleep_time)
            response = Response()
            response.status_code = 200
            response._content = ('%s' % sleep_time) * file_length
            return response

    test_port = 12124
    tmp_file_pattern = '/tmp/test.%s'

    proxy = GenericProxy(port=test_port, update_listener=DownloadListener())
    proxy.start()

    def do_download(param):
        tmp_file = tmp_file_pattern % param
        TMP_FILES.append(tmp_file)
        download('http://localhost:%s/%s' % (test_port, param), tmp_file)

    values = (1, 2, 3)
    parallelize(do_download, values)
    proxy.stop()

    for val in values:
        tmp_file = tmp_file_pattern % val
        assert len(load_file(tmp_file)) == file_length
