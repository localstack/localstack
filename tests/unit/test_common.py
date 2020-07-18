import unittest
from datetime import datetime
from localstack.utils import common
from localstack.utils.bootstrap import extract_port_flags, PortMappings


class TestCommon(unittest.TestCase):

    def test_first_char_to_lower(self):
        env = common.first_char_to_lower('Foobar')
        self.assertEqual(env, 'foobar')

    def test_truncate(self):
        env = common.truncate('foobar', 3)
        self.assertEqual(env, 'foo...')

    def test_isoformat_milliseconds(self):
        env = common.isoformat_milliseconds(datetime(2010, 3, 20, 7, 24, 00, 0))
        self.assertEqual(env, '2010-03-20T07:24:00.000')

    def test_base64_to_hex(self):
        env = common.base64_to_hex('Zm9vIGJhcg ==')
        self.assertEqual(env, b'666f6f20626172')

    def test_now(self):
        env = common.now()
        test = common.mktime(datetime.now())
        self.assertEqual(env, test)

    def test_is_number(self):
        env = common.is_number(5)
        self.assertEqual(env, True)

    def test_is_ip_address(self):
        env = common.is_ip_address('10.0.0.1')
        self.assertEqual(env, True)
        env = common.is_ip_address('abcde')
        self.assertEqual(env, False)

    def test_is_base64(self):
        env = common.is_base64('foobar')
        self.assertEqual(env, None)

    def test_mktime(self):
        env = common.mktime(datetime(2010, 3, 20, 7, 24, 00, 0), True)
        self.assertEqual(env, 1269069840.0)


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
