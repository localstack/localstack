import time

import pytz
import yaml
import unittest
from datetime import datetime, date
from localstack.utils import common
from localstack.utils.bootstrap import extract_port_flags, PortMappings


class TestCommon(unittest.TestCase):

    def test_first_char_to_lower(self):
        env = common.first_char_to_lower('Foobar')
        self.assertEqual('foobar', env)

    def test_truncate(self):
        env = common.truncate('foobar', 3)
        self.assertEqual('foo...', env)

    def test_isoformat_milliseconds(self):
        env = common.isoformat_milliseconds(datetime(2010, 3, 20, 7, 24, 00, 0))
        self.assertEqual('2010-03-20T07:24:00.000', env)

    def test_base64_to_hex(self):
        env = common.base64_to_hex('Zm9vIGJhcg ==')
        self.assertEqual(b'666f6f20626172', env)

    def test_now(self):
        env = common.now()
        test = time.time()
        self.assertAlmostEqual(test, env, delta=1)

    def test_now_utc(self):
        env = common.now_utc()
        test = datetime.now(pytz.UTC).timestamp()
        self.assertAlmostEqual(test, env, delta=1)

    def test_is_number(self):
        env = common.is_number(5)
        self.assertTrue(env)

    def test_is_ip_address(self):
        env = common.is_ip_address('10.0.0.1')
        self.assertTrue(env)
        env = common.is_ip_address('abcde')
        self.assertFalse(env)

    def test_is_base64(self):
        env = common.is_base64('foobar')
        self.assertIsNone(env)

    def test_mktime(self):
        now = common.mktime(datetime.now())
        self.assertEqual(int(now), int(time.time()))

    def test_mktime_with_tz(self):
        # see https://en.wikipedia.org/wiki/File:1000000000seconds.jpg
        dt = datetime(2001, 9, 9, 1, 46, 40, 0, tzinfo=pytz.utc)
        self.assertEqual(1000000000, int(common.mktime(dt)))

        dt = datetime(2001, 9, 9, 1, 46, 40, 0, tzinfo=pytz.timezone('EST'))
        self.assertEqual(1000000000 + (5 * 60 * 60), int(common.mktime(dt)))  # EST is UTC-5

    def test_mktime_millis_with_tz(self):
        # see https://en.wikipedia.org/wiki/File:1000000000
        dt = datetime(2001, 9, 9, 1, 46, 40, 0, tzinfo=pytz.utc)
        self.assertEqual(1000000000, int(common.mktime(dt, millis=True) / 1000))

        dt = datetime(2001, 9, 9, 1, 46, 40, 0, tzinfo=pytz.timezone('EST'))
        self.assertEqual(1000000000 + (5 * 60 * 60), int(common.mktime(dt, millis=True)) / 1000)  # EST is UTC-5

    def test_mktime_millis(self):
        now = common.mktime(datetime.now(), millis=True)
        self.assertEqual(int(now / 1000), int(time.time()))

    def test_timestamp_millis(self):
        result = common.timestamp_millis(datetime.now())
        self.assertIn('T', result)
        result = common.timestamp_millis(date.today())
        self.assertIn('00:00:00', result)
        self.assertIn('T', result)

    def test_extract_jsonpath(self):
        obj = {'a': {'b': [{'c': 123}, 'foo']}, 'e': 234}
        result = common.extract_jsonpath(obj, '$.a.b')
        self.assertEqual([{'c': 123}, 'foo'], result)
        result = common.extract_jsonpath(obj, '$.a.b.c')
        self.assertFalse(result)
        result = common.extract_jsonpath(obj, '$.foobar')
        self.assertFalse(result)
        result = common.extract_jsonpath(obj, '$.e')
        self.assertEqual(234, result)
        result = common.extract_jsonpath(obj, '$.a.b[0]')
        self.assertEqual({'c': 123}, result)
        result = common.extract_jsonpath(obj, '$.a.b[0].c')
        self.assertEqual(123, result)
        result = common.extract_jsonpath(obj, '$.a.b[1]')
        self.assertEqual('foo', result)

    def test_parse_yaml_nodes(self):
        obj = {'test': yaml.ScalarNode('tag:yaml.org,2002:int', '123')}
        result = common.clone_safe(obj)
        self.assertEqual({'test': 123}, result)
        obj = {'foo': [
            yaml.ScalarNode('tag:yaml.org,2002:str', 'value'),
            yaml.ScalarNode('tag:yaml.org,2002:int', '123'),
            yaml.ScalarNode('tag:yaml.org,2002:float', '1.23'),
            yaml.ScalarNode('tag:yaml.org,2002:bool', 'true')
        ]}
        result = common.clone_safe(obj)
        self.assertEqual({'foo': ['value', 123, 1.23, True]}, result)


class TestCommandLine(unittest.TestCase):

    def test_extract_port_flags(self):
        port_mappings = PortMappings()
        flags = extract_port_flags('foo -p 1234:1234 bar', port_mappings=port_mappings)
        self.assertEqual('foo  bar', flags)
        mapping_str = port_mappings.to_str()
        self.assertEqual('-p 1234:1234', mapping_str)

        port_mappings = PortMappings()
        flags = extract_port_flags('foo -p 1234:1234 bar -p 80-90:81-91 baz', port_mappings=port_mappings)
        self.assertEqual('foo  bar  baz', flags)
        mapping_str = port_mappings.to_str()
        self.assertIn('-p 1234:1234', mapping_str)
        self.assertIn('-p 80-90:81-91', mapping_str)

    def test_overlapping_port_ranges(self):
        port_mappings = PortMappings()
        port_mappings.add(4590)
        port_mappings.add(4591)
        port_mappings.add(4593)
        port_mappings.add(4592)
        port_mappings.add(4593)
        result = port_mappings.to_str()
        # assert that ranges are non-overlapping, i.e., no duplicate ports
        self.assertEqual('-p 4590-4592:4590-4592 -p 4593:4593', result)

    def test_port_ranges_with_bind_host(self):
        port_mappings = PortMappings(bind_host='0.0.0.0')
        port_mappings.add(5000)
        port_mappings.add(5001)
        port_mappings.add(5003)
        result = port_mappings.to_str()
        self.assertEqual('-p 0.0.0.0:5000-5001:5000-5001 -p 0.0.0.0:5003:5003', result)
