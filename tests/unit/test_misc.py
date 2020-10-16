import yaml
import time
import asyncio
import datetime
import unittest
import concurrent.futures
from requests.models import Response
from localstack import config
from localstack.utils import async_utils
from localstack.services import infra
from localstack.utils.aws import aws_stack
from localstack.utils.bootstrap import PortMappings
from localstack.services.generic_proxy import GenericProxy, ProxyListener
from localstack.utils.common import download, parallelize, TMP_FILES, load_file, json_safe, now_utc
from localstack.utils.http_utils import parse_chunked_data, create_chunked_data


class TestMisc(unittest.TestCase):

    def test_environment(self):
        env = aws_stack.Environment.from_json({'prefix': 'foobar1'})
        self.assertEqual(env.prefix, 'foobar1')
        env = aws_stack.Environment.from_string('foobar2')
        self.assertEqual(env.prefix, 'foobar2')

    def test_parse_chunked_data(self):
        # See: https://en.wikipedia.org/wiki/Chunked_transfer_encoding
        chunked = '4\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n'
        expected = 'Wikipedia in\r\n\r\nchunks.'

        # test parsing
        parsed = parse_chunked_data(chunked)
        self.assertEqual(parsed.strip(), expected.strip())

        # test roundtrip
        chunked_computed = create_chunked_data(expected)
        parsed = parse_chunked_data(chunked_computed)
        self.assertEqual(parsed.strip(), expected.strip())

    def test_convert_yaml_date_strings(self):
        yaml_source = 'Version: 2012-10-17'
        obj = yaml.safe_load(yaml_source)
        self.assertIn(type(obj['Version']), (datetime.date, str))
        if isinstance(obj['Version'], datetime.date):
            obj = json_safe(obj)
            self.assertEqual(type(obj['Version']), str)
            self.assertEqual(obj['Version'], '2012-10-17')

    def test_timstamp_millis(self):
        t1 = now_utc()
        t2 = now_utc(millis=True)
        self.assertLessEqual(t2 - t1, 1)

    def test_port_mappings(self):
        map = PortMappings()
        map.add(123)
        self.assertEqual(map.to_str(), '-p 123:123')
        map.add(124)
        self.assertEqual(map.to_str(), '-p 123-124:123-124')
        map.add(234)
        self.assertEqual(map.to_str(), '-p 123-124:123-124 -p 234:234')
        map.add(345, 346)
        self.assertEqual(map.to_str(), '-p 123-124:123-124 -p 234:234 -p 345:346')
        map.add([456, 458])
        self.assertEqual(map.to_str(), '-p 123-124:123-124 -p 234:234 -p 345:346 -p 456-458:456-458')

        map = PortMappings()
        map.add([123, 124])
        self.assertEqual(map.to_str(), '-p 123-124:123-124')
        map.add([234, 237], [345, 348])
        self.assertEqual(map.to_str(), '-p 123-124:123-124 -p 234-237:345-348')

    def test_get_service_status(self):
        env = infra.get_services_status()
        self.assertNotEqual(env, None)
        self.assertGreater(len(env), 0)

    def test_update_config_variable(self):
        infra.update_config_variable('foo', 'bar')
        self.assertEquals(config.foo, 'bar')

    def test_async_parallelization(self):
        def handler():
            time.sleep(0.1)
            results.append(1)

        async def run():
            await async_utils.run_sync(handler, thread_pool=thread_pool)

        loop = asyncio.get_event_loop()
        thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=100)
        results = []
        num_items = 1000
        handlers = [run() for i in range(num_items)]
        loop.run_until_complete(asyncio.gather(*handlers))
        self.assertEqual(len(results), num_items)
        thread_pool.shutdown()


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
