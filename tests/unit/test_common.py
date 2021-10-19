import io
import itertools
import os
import socket
import threading
import time
import unittest
import zipfile
from datetime import date, datetime

import pytest
import pytz
import yaml

from localstack.utils import common
from localstack.utils.bootstrap import extract_port_flags
from localstack.utils.common import is_empty_dir, mkdir, new_tmp_dir, rm_rf, save_file
from localstack.utils.docker_utils import PortMappings
from localstack.utils.testutil import create_zip_file


class TestCommon(unittest.TestCase):
    def test_first_char_to_lower(self):
        env = common.first_char_to_lower("Foobar")
        self.assertEqual("foobar", env)

    def test_truncate(self):
        env = common.truncate("foobar", 3)
        self.assertEqual("foo...", env)

    def test_isoformat_milliseconds(self):
        env = common.isoformat_milliseconds(datetime(2010, 3, 20, 7, 24, 00, 0))
        self.assertEqual("2010-03-20T07:24:00.000", env)

    def test_base64_to_hex(self):
        env = common.base64_to_hex("Zm9vIGJhcg ==")
        self.assertEqual(b"666f6f20626172", env)

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
        env = common.is_ip_address("10.0.0.1")
        self.assertTrue(env)
        env = common.is_ip_address("abcde")
        self.assertFalse(env)

    def test_is_base64(self):
        env = common.is_base64("foobar")
        self.assertIsNone(env)

    def test_mktime(self):
        now = common.mktime(datetime.now())
        self.assertEqual(int(now), int(time.time()))

    def test_mktime_with_tz(self):
        # see https://en.wikipedia.org/wiki/File:1000000000seconds.jpg
        dt = datetime(2001, 9, 9, 1, 46, 40, 0, tzinfo=pytz.utc)
        self.assertEqual(1000000000, int(common.mktime(dt)))

        dt = datetime(2001, 9, 9, 1, 46, 40, 0, tzinfo=pytz.timezone("EST"))
        self.assertEqual(1000000000 + (5 * 60 * 60), int(common.mktime(dt)))  # EST is UTC-5

    def test_mktime_millis_with_tz(self):
        # see https://en.wikipedia.org/wiki/File:1000000000
        dt = datetime(2001, 9, 9, 1, 46, 40, 0, tzinfo=pytz.utc)
        self.assertEqual(1000000000, int(common.mktime(dt, millis=True) / 1000))

        dt = datetime(2001, 9, 9, 1, 46, 40, 0, tzinfo=pytz.timezone("EST"))
        self.assertEqual(
            1000000000 + (5 * 60 * 60), int(common.mktime(dt, millis=True)) / 1000
        )  # EST is UTC-5

    def test_mktime_millis(self):
        now = common.mktime(datetime.now(), millis=True)
        self.assertEqual(int(now / 1000), int(time.time()))

    def test_timestamp_millis(self):
        result = common.timestamp_millis(datetime.now())
        self.assertIn("T", result)
        result = common.timestamp_millis(date.today())
        self.assertIn("00:00:00", result)
        self.assertIn("T", result)

    def test_extract_jsonpath(self):
        obj = {"a": {"b": [{"c": 123}, "foo"]}, "e": 234}
        result = common.extract_jsonpath(obj, "$.a.b")
        self.assertEqual([{"c": 123}, "foo"], result)
        result = common.extract_jsonpath(obj, "$.a.b.c")
        self.assertFalse(result)
        result = common.extract_jsonpath(obj, "$.foobar")
        self.assertFalse(result)
        result = common.extract_jsonpath(obj, "$.e")
        self.assertEqual(234, result)
        result = common.extract_jsonpath(obj, "$.a.b[0]")
        self.assertEqual({"c": 123}, result)
        result = common.extract_jsonpath(obj, "$.a.b[0].c")
        self.assertEqual(123, result)
        result = common.extract_jsonpath(obj, "$.a.b[1]")
        self.assertEqual("foo", result)

    def test_str_to_bool(self):
        self.assertEqual(True, common.str_to_bool("true"))
        self.assertEqual(True, common.str_to_bool("True"))

        self.assertEqual(False, common.str_to_bool("1"))
        self.assertEqual(False, common.str_to_bool("0"))
        self.assertEqual(False, common.str_to_bool("TRUE"))
        self.assertEqual(False, common.str_to_bool("false"))
        self.assertEqual(False, common.str_to_bool("False"))

        self.assertEqual(0, common.str_to_bool(0))
        self.assertEqual(0, common.str_to_bool(0))

    def test_parse_yaml_nodes(self):
        obj = {"test": yaml.ScalarNode("tag:yaml.org,2002:int", "123")}
        result = common.clone_safe(obj)
        self.assertEqual({"test": 123}, result)
        obj = {
            "foo": [
                yaml.ScalarNode("tag:yaml.org,2002:str", "value"),
                yaml.ScalarNode("tag:yaml.org,2002:int", "123"),
                yaml.ScalarNode("tag:yaml.org,2002:float", "1.23"),
                yaml.ScalarNode("tag:yaml.org,2002:bool", "true"),
            ]
        }
        result = common.clone_safe(obj)
        self.assertEqual({"foo": ["value", 123, 1.23, True]}, result)

    def test_free_tcp_port_blacklist_raises_exception(self):
        blacklist = range(0, 70000)  # blacklist all existing ports
        with self.assertRaises(Exception) as ctx:
            common.get_free_tcp_port(blacklist)

        self.assertIn("Unable to determine free TCP", str(ctx.exception))

    def test_port_can_be_bound(self):
        port = common.get_free_tcp_port()
        self.assertTrue(common.port_can_be_bound(port))

    def test_port_can_be_bound_illegal_port(self):
        self.assertFalse(common.port_can_be_bound(9999999999))

    def test_port_can_be_bound_already_bound(self):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            tcp.bind(("", 0))
            addr, port = tcp.getsockname()
            self.assertFalse(common.port_can_be_bound(port))
        finally:
            tcp.close()

        self.assertTrue(common.port_can_be_bound(port))

    def test_to_unique_item_list(self):
        self.assertListEqual([1, 2, 3], common.to_unique_items_list([1, 1, 2, 2, 3]))
        self.assertListEqual(["a"], common.to_unique_items_list(["a"]))
        self.assertListEqual(["a", "b"], common.to_unique_items_list(["a", "b", "a"]))
        self.assertListEqual(["a", "b"], common.to_unique_items_list("aba"))
        self.assertListEqual([], common.to_unique_items_list([]))

        def comparator_lower(first, second):
            return first.lower() == second.lower()

        self.assertListEqual(["a", "A"], common.to_unique_items_list(["a", "A", "a"]))
        self.assertListEqual(["a"], common.to_unique_items_list(["a", "A", "a"], comparator_lower))
        self.assertListEqual(["a"], common.to_unique_items_list(["a", "A", "a"], comparator_lower))

        def comparator_str_int(first, second):
            return int(first) - int(second)

        self.assertListEqual(
            ["1", "2"], common.to_unique_items_list(["1", "2", "1", "2"], comparator_str_int)
        )

    def test_retry(self):
        exceptions = list()
        count = itertools.count()

        def fn():
            i = next(count)
            e = RuntimeError("exception %d" % i)
            exceptions.append(e)

            if i == 2:
                return "two"

            raise e

        ret = common.retry(fn, retries=3, sleep=0.001)
        self.assertEqual("two", ret)
        self.assertEqual(3, len(exceptions))

    def test_retry_raises_last_exception(self):
        exceptions = list()
        count = itertools.count()

        def fn():
            i = next(count)
            e = RuntimeError("exception %d" % i)
            exceptions.append(e)

            raise e

        with self.assertRaises(RuntimeError) as ctx:
            common.retry(fn, retries=3, sleep=0.001)

        self.assertIs(exceptions[-1], ctx.exception, "did not throw last exception")
        self.assertEqual(4, len(exceptions))

    def test_run(self):
        cmd = "echo 'foobar'"
        result = common.run(cmd)
        self.assertEqual("foobar", result.strip())

    def test_run_with_cache(self):
        cmd = "python3 -c 'import time; print(int(time.time() * 1000))'"
        d1 = float(common.run(cmd))
        d2 = float(common.run(cmd, cache_duration_secs=1))
        d3 = float(common.run(cmd, cache_duration_secs=1))

        self.assertNotEqual(d1, d2)
        self.assertEqual(d2, d3)

    def test_run_with_cache_expiry(self):
        cmd = "python3 -c 'import time; print(int(time.time() * 1000))'"

        d1 = float(common.run(cmd, cache_duration_secs=0.5))
        d2 = float(common.run(cmd, cache_duration_secs=0.5))
        time.sleep(0.8)
        d3 = float(common.run(cmd, cache_duration_secs=0.5))

        self.assertEqual(d1, d2)
        self.assertNotEqual(d2, d3)

    def test_is_command_available(self):
        self.assertTrue(common.is_command_available("python3"))
        self.assertFalse(common.is_command_available("hopefullydoesntexist"))

    def test_camel_to_snake_case(self):
        fn = common.camel_to_snake_case

        self.assertEqual("foo", fn("Foo"))
        self.assertEqual("foobar_ed", fn("FoobarEd"))
        self.assertEqual("foo_bar_ed", fn("FooBarEd"))
        self.assertEqual("foo_bar", fn("Foo_Bar"))
        self.assertEqual("foo__bar", fn("Foo__Bar"))
        self.assertEqual("foo_b_a_r", fn("FooBAR"))

    def test_snake_to_camel_case(self):
        fn = common.snake_to_camel_case

        self.assertEqual("Foo", fn("foo"))
        self.assertEqual("FoobarEd", fn("foobar_ed"))
        self.assertEqual("FooBarEd", fn("foo_bar_ed"))
        self.assertEqual("FooBar", fn("foo_bar"))
        self.assertEqual("FooBar", fn("foo__bar"))
        self.assertEqual("FooBAR", fn("foo_b_a_r"))

    def test_obj_to_xml(self):
        fn = common.obj_to_xml
        # primitive
        self.assertEqual("42", fn(42))
        self.assertEqual("False", fn(False))
        self.assertEqual("a", fn("a"))
        # dict only
        self.assertEqual("<foo>bar</foo>", fn({"foo": "bar"}))
        self.assertEqual("<a>42</a>", fn({"a": 42}))
        self.assertEqual("<a>42</a><foo>bar</foo>", fn({"a": 42, "foo": "bar"}))
        # list of dicts
        self.assertEqual("<a>42</a><a>43</a>", fn([{"a": 42}, {"a": 43}]))
        # dict with lists
        self.assertEqual("<f><a>42</a><a>43</a></f>", fn({"f": [{"a": 42}, {"a": 43}]}))
        # empty types
        self.assertEqual("None", fn(None))
        self.assertEqual("", fn(""))

    def test_parse_json_or_yaml_with_json(self):
        markup = """{"foo": "bar", "why": 42, "mylist": [1,2,3]}"""

        doc = common.parse_json_or_yaml(markup)
        self.assertDictEqual({"foo": "bar", "why": 42, "mylist": [1, 2, 3]}, doc)

    def test_parse_json_or_yaml_with_yaml(self):
        markup = """
        foo: bar
        why: 42
        mylist:
            - 1
            - 2
            - 3
        """
        doc = common.parse_json_or_yaml(markup)
        self.assertDictEqual({"foo": "bar", "why": 42, "mylist": [1, 2, 3]}, doc)

    def test_parse_json_or_yaml_with_invalid_syntax_returns_content(self):
        markup = "<a href='foobar'>baz</a>"
        doc = common.parse_json_or_yaml(markup)
        self.assertEqual(markup, doc)  # FIXME: not sure if this is good behavior

    def test_parse_json_or_yaml_with_empty_string_returns_none(self):
        doc = common.parse_json_or_yaml("")
        self.assertIsNone(doc)

    def test_format_bytes(self):
        fn = common.format_bytes

        self.assertEqual("1B", fn(1))
        self.assertEqual("100B", fn(100))
        self.assertEqual("999B", fn(999))
        self.assertEqual("1KB", fn(1e3))
        self.assertEqual("1MB", fn(1e6))
        self.assertEqual("10MB", fn(1e7))
        self.assertEqual("100MB", fn(1e8))
        self.assertEqual("1GB", fn(1e9))
        self.assertEqual("1TB", fn(1e12))

        # comma values
        self.assertEqual("1.1TB", fn(1e12 + 1e11))
        self.assertEqual("1000TB", fn(1e15))

        # string input
        self.assertEqual("123B", fn("123"))
        # invalid number
        self.assertEqual("n/a", fn("abc"))
        # negative number
        self.assertEqual("n/a", fn(-1))  # TODO: seems we could support this case

    def test_format_number(self):
        fn = common.format_number
        self.assertEqual("12", fn(12, decimals=0))
        self.assertEqual("12", fn(12, decimals=1))
        self.assertEqual("12", fn(12.421, decimals=0))
        self.assertEqual("13", fn(12.521, decimals=0))
        self.assertEqual("12.52", fn(12.521, decimals=2))
        self.assertEqual("12.521", fn(12.521, decimals=3))
        self.assertEqual("12.521", fn(12.521, decimals=4))
        self.assertEqual("-12.521", fn(-12.521, decimals=4))
        self.assertEqual("-1223.4354", fn(-1.2234354123e3, decimals=4))

    def test_cleanup_threads_and_processes_calls_shutdown_hooks(self):
        # TODO: move all run/concurrency related tests into separate class

        started = threading.Event()
        done = threading.Event()

        def run_method(*args, **kwargs):
            started.set()
            func_thread = kwargs["_thread"]
            # thread waits until it is stopped
            func_thread._stop_event.wait()
            done.set()

        common.start_thread(run_method)
        self.assertTrue(started.wait(timeout=2))
        common.cleanup_threads_and_processes()
        self.assertTrue(done.wait(timeout=2))


class TestCommandLine(unittest.TestCase):
    def test_extract_port_flags(self):
        port_mappings = PortMappings()
        flags = extract_port_flags("foo -p 1234:1234 bar", port_mappings=port_mappings)
        self.assertEqual("foo  bar", flags)
        mapping_str = port_mappings.to_str()
        self.assertEqual("-p 1234:1234", mapping_str)

        port_mappings = PortMappings()
        flags = extract_port_flags(
            "foo -p 1234:1234 bar -p 80-90:81-91 baz", port_mappings=port_mappings
        )
        self.assertEqual("foo  bar  baz", flags)
        mapping_str = port_mappings.to_str()
        self.assertIn("-p 1234:1234", mapping_str)
        self.assertIn("-p 80-90:81-91", mapping_str)

    def test_overlapping_port_ranges(self):
        port_mappings = PortMappings()
        port_mappings.add(4590)
        port_mappings.add(4591)
        port_mappings.add(4593)
        port_mappings.add(4592)
        port_mappings.add(4593)
        result = port_mappings.to_str()
        # assert that ranges are non-overlapping, i.e., no duplicate ports
        self.assertEqual("-p 4590-4592:4590-4592 -p 4593:4593", result)

    def test_port_ranges_with_bind_host(self):
        port_mappings = PortMappings(bind_host="0.0.0.0")
        port_mappings.add(5000)
        port_mappings.add(5001)
        port_mappings.add(5003)
        result = port_mappings.to_str()
        self.assertEqual("-p 0.0.0.0:5000-5001:5000-5001 -p 0.0.0.0:5003:5003", result)

    def test_port_ranges_with_bind_host_to_dict(self):
        port_mappings = PortMappings(bind_host="0.0.0.0")
        port_mappings.add(5000, 6000)
        port_mappings.add(5001, 7000)
        port_mappings.add(5003, 8000)
        result = port_mappings.to_dict()
        expected_result = {
            "6000/tcp": ("0.0.0.0", 5000),
            "7000/tcp": ("0.0.0.0", 5001),
            "8000/tcp": ("0.0.0.0", 5003),
        }
        self.assertEqual(expected_result, result)


class TestCommonFileOperations:
    def test_disk_usage(self, tmp_path):
        f1 = tmp_path / "f1.blob"
        f1.write_bytes(b"0" * 100)

        f2 = tmp_path / "f2.blob"
        f2.write_bytes(b"0" * 100)

        # subdir
        f3_dir = tmp_path / "foo"
        f3_dir.mkdir()
        f3 = f3_dir / "f3.blob"
        f3.write_bytes(b"0" * 100)

        # trees
        assert common.disk_usage(tmp_path) == pytest.approx(300, abs=5)
        assert common.disk_usage(f3_dir) == pytest.approx(100, abs=5)

        # single file
        assert common.disk_usage(f3) == pytest.approx(100, abs=5)

        # invalid path
        assert common.disk_usage(tmp_path / "not_in_path") == 0

        # None
        with pytest.raises(TypeError):
            assert common.disk_usage(None) == 0

    def test_replace_in_file(self, tmp_path):
        content = """
        1: {search}
        2: {search}
        3: {sear}
        """
        expected = """
        1: foo
        2: foo
        3: {sear}
        """

        fp = tmp_path / "file.txt"
        fp.write_text(content)

        common.replace_in_file("{search}", "foo", fp)
        assert fp.read_text() == expected

        # try again, nothing should change
        common.replace_in_file("{search}", "foo", fp)
        assert fp.read_text() == expected

    def test_replace_in_file_with_non_existing_path(self, tmp_path):
        fp = tmp_path / "non_existing_file.txt"

        assert not fp.exists()
        common.replace_in_file("foo", "bar", fp)
        assert not fp.exists()

    def test_cp_r(self, tmp_path):
        pytest.skip("this test does not work on python3.7 due to an issue shutil used by cp_r")

        source = tmp_path / "source"
        target = tmp_path / "target"

        f1 = source / "f1.txt"
        f2 = source / "d1" / "f2.txt"
        f3 = source / "d1" / "d2" / "f3.txt"

        source.mkdir()
        target.mkdir()
        f3.parent.mkdir(parents=True)
        f1.write_text("f1")
        f2.write_text("f2")
        f3.write_text("f3")

        common.cp_r(source, target)

        assert (target / "f1.txt").is_file()
        assert (target / "d1" / "f2.txt").is_file()
        assert (target / "d1" / "f2.txt").is_file()
        assert (target / "d1" / "d2" / "f3.txt").is_file()
        assert (target / "d1" / "d2" / "f3.txt").read_text() == "f3"

    def test_is_dir_empty(self):
        tmp_dir = new_tmp_dir()
        assert is_empty_dir(tmp_dir)

        def _check(fname, is_dir):
            test_entry = os.path.join(tmp_dir, fname)
            mkdir(test_entry) if is_dir else save_file(test_entry, "test content")
            assert not is_empty_dir(tmp_dir)
            assert is_empty_dir(tmp_dir, ignore_hidden=True) == (fname == ".hidden")
            rm_rf(test_entry)
            assert is_empty_dir(tmp_dir)

        for name in ["regular", ".hidden"]:
            for is_dir in [True, False]:
                _check(name, is_dir)

    def test_create_archive(self):
        # create archive from empty directory
        tmp_dir = new_tmp_dir()
        content = create_zip_file(tmp_dir, get_content=True)
        zip_obj = zipfile.ZipFile(io.BytesIO(content))
        assert zip_obj.infolist() == []
        rm_rf(tmp_dir)

        # create archive from non-empty directory
        tmp_dir = new_tmp_dir()
        save_file(os.path.join(tmp_dir, "testfile"), "content 123")
        content = create_zip_file(tmp_dir, get_content=True)
        zip_obj = zipfile.ZipFile(io.BytesIO(content))
        assert len(zip_obj.infolist()) == 1
        assert zip_obj.infolist()[0].filename == "testfile"
        rm_rf(tmp_dir)
