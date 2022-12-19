import base64
import io
import itertools
import os
import socket
import threading
import time
import zipfile
from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo

import pytest
import yaml

from localstack import config
from localstack.utils import common
from localstack.utils.archives import unzip
from localstack.utils.common import (
    ExternalServicePortsManager,
    PaginatedList,
    PortNotAvailableException,
    fully_qualified_class_name,
    get_free_tcp_port,
    is_empty_dir,
    load_file,
    mkdir,
    new_tmp_dir,
    rm_rf,
    save_file,
    short_uid,
)
from localstack.utils.objects import Mock
from localstack.utils.strings import base64_decode, to_bytes
from localstack.utils.testutil import create_zip_file


class TestCommon:
    def test_first_char_to_lower(self):
        env = common.first_char_to_lower("Foobar")
        assert env == "foobar"

    def test_truncate(self):
        env = common.truncate("foobar", 3)
        assert env == "foo..."

    def test_isoformat_milliseconds(self):
        env = common.isoformat_milliseconds(datetime(2010, 3, 20, 7, 24, 00, 0))
        assert env == "2010-03-20T07:24:00.000"

    def test_base64_to_hex(self):
        env = common.base64_to_hex("Zm9vIGJhcg ==")
        assert env == b"666f6f20626172"

    def test_base64_decode(self):
        def roundtrip(data):
            encoded = base64.urlsafe_b64encode(to_bytes(data))
            result = base64_decode(encoded)
            assert to_bytes(data) == result

        # simple examples
        roundtrip("test")
        roundtrip(b"test \x64 \x01 \x55")

        # strings that require urlsafe encoding (containing "-" or "/" in base64 encoded form)
        examples = ((b"=@~", b"PUB+"), (b"???", b"Pz8/"))
        for decoded, encoded in examples:
            assert base64.b64encode(decoded) == encoded
            expected = encoded.replace(b"+", b"-").replace(b"/", b"_")
            assert base64.urlsafe_b64encode(decoded) == expected
            roundtrip(decoded)

    def test_now(self):
        env = common.now()
        test = time.time()
        assert test == pytest.approx(env, 1)

    def test_now_utc(self):
        env = common.now_utc()
        test = datetime.now(timezone.utc).timestamp()
        assert test == pytest.approx(env, 1)

    def test_is_number(self):
        assert common.is_number(5)

    def test_is_ip_address(self):
        assert common.is_ip_address("10.0.0.1")
        assert not common.is_ip_address("abcde")

    def test_is_base64(self):
        assert not common.is_base64("foobar")

    def test_mktime(self):
        now = common.mktime(datetime.now())
        assert int(now) == int(time.time())

    def test_mktime_with_tz(self):
        # see https://en.wikipedia.org/wiki/File:1000000000seconds.jpg
        dt = datetime(2001, 9, 9, 1, 46, 40, 0, tzinfo=timezone.utc)
        assert int(common.mktime(dt)) == 1000000000

        dt = datetime(2001, 9, 9, 1, 46, 40, 0, tzinfo=ZoneInfo("EST"))
        assert int(common.mktime(dt)) == 1000000000 + (5 * 60 * 60)  # EST is UTC-5

    def test_mktime_millis_with_tz(self):
        # see https://en.wikipedia.org/wiki/File:1000000000
        dt = datetime(2001, 9, 9, 1, 46, 40, 0, tzinfo=timezone.utc)
        assert int(common.mktime(dt, millis=True) / 1000) == 1000000000

        dt = datetime(2001, 9, 9, 1, 46, 40, 0, tzinfo=ZoneInfo("EST"))
        assert int(common.mktime(dt, millis=True)) / 1000 == 1000000000 + (
            5 * 60 * 60
        )  # EST is UTC-5

    def test_mktime_millis(self):
        now = common.mktime(datetime.now(), millis=True)
        assert int(time.time()) == int(now / 1000)

    def test_timestamp_millis(self):
        result = common.timestamp_millis(datetime.now())
        assert "T" in result
        result = common.timestamp_millis(date.today())
        assert "00:00:00" in result
        assert "T" in result

    def test_extract_jsonpath(self):
        obj = {"a": {"b": [{"c": 123}, "foo"]}, "e": 234}
        result = common.extract_jsonpath(obj, "$.a.b")
        assert result == [{"c": 123}, "foo"]
        result = common.extract_jsonpath(obj, "$.a.b.c")
        assert not result
        result = common.extract_jsonpath(obj, "$.foobar")
        assert not result
        result = common.extract_jsonpath(obj, "$.e")
        assert result == 234
        result = common.extract_jsonpath(obj, "$.a.b[0]")
        assert result == {"c": 123}
        result = common.extract_jsonpath(obj, "$.a.b[0].c")
        assert result == 123
        result = common.extract_jsonpath(obj, "$.a.b[1]")
        assert result == "foo"

    def test_str_to_bool(self):
        assert common.str_to_bool("true") is True
        assert common.str_to_bool("True") is True

        assert common.str_to_bool("1") is False
        assert common.str_to_bool("0") is False
        assert common.str_to_bool("TRUE") is False
        assert common.str_to_bool("false") is False
        assert common.str_to_bool("False") is False

        assert common.str_to_bool(0) == 0

    def test_parse_yaml_nodes(self):
        obj = {"test": yaml.ScalarNode("tag:yaml.org,2002:int", "123")}
        result = common.clone_safe(obj)
        assert result == {"test": 123}
        obj = {
            "foo": [
                yaml.ScalarNode("tag:yaml.org,2002:str", "value"),
                yaml.ScalarNode("tag:yaml.org,2002:int", "123"),
                yaml.ScalarNode("tag:yaml.org,2002:float", "1.23"),
                yaml.ScalarNode("tag:yaml.org,2002:bool", "true"),
            ]
        }
        result = common.clone_safe(obj)
        assert result == {"foo": ["value", 123, 1.23, True]}

    def test_free_tcp_port_blacklist_raises_exception(self):
        blacklist = range(0, 70000)  # blacklist all existing ports
        with pytest.raises(Exception) as ctx:
            common.get_free_tcp_port(blacklist)

        assert "Unable to determine free TCP" in str(ctx.value)

    def test_port_can_be_bound(self):
        port = common.get_free_tcp_port()
        assert common.port_can_be_bound(port)

    def test_port_can_be_bound_illegal_port(self):
        assert not common.port_can_be_bound(9999999999)

    def test_port_can_be_bound_already_bound(self):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            tcp.bind(("", 0))
            addr, port = tcp.getsockname()
            assert not common.port_can_be_bound(port)
        finally:
            tcp.close()

        assert common.port_can_be_bound(port)

    def test_to_unique_item_list(self):
        assert common.to_unique_items_list([1, 1, 2, 2, 3]) == [1, 2, 3]
        assert common.to_unique_items_list(["a"]) == ["a"]
        assert common.to_unique_items_list(["a", "b", "a"]) == ["a", "b"]
        assert common.to_unique_items_list("aba") == ["a", "b"]
        assert common.to_unique_items_list([]) == []

        def comparator_lower(first, second):
            return first.lower() == second.lower()

        assert common.to_unique_items_list(["a", "A", "a"]) == ["a", "A"]
        assert common.to_unique_items_list(["a", "A", "a"], comparator_lower) == ["a"]
        assert common.to_unique_items_list(["a", "A", "a"], comparator_lower) == ["a"]

        def comparator_str_int(first, second):
            return int(first) - int(second)

        assert common.to_unique_items_list(["1", "2", "1", "2"], comparator_str_int) == ["1", "2"]

    def test_retry(self):
        exceptions = []
        count = itertools.count()

        def fn():
            i = next(count)
            e = RuntimeError("exception %d" % i)
            exceptions.append(e)

            if i == 2:
                return "two"

            raise e

        ret = common.retry(fn, retries=3, sleep=0.001)
        assert ret == "two"
        assert len(exceptions) == 3

    def test_retry_raises_last_exception(self):
        exceptions = []
        count = itertools.count()

        def fn():
            i = next(count)
            e = RuntimeError("exception %d" % i)
            exceptions.append(e)

            raise e

        with pytest.raises(RuntimeError) as ctx:
            common.retry(fn, retries=3, sleep=0.001)

        assert exceptions[-1] is ctx.value
        assert len(exceptions) == 4

    def test_run(self):
        cmd = "echo 'foobar'"
        result = common.run(cmd)
        assert result.strip() == "foobar"

    def test_is_command_available(self):
        assert common.is_command_available("python3")
        assert not common.is_command_available("hopefullydoesntexist")

    def test_camel_to_snake_case(self):
        fn = common.camel_to_snake_case

        assert fn("Foo") == "foo"
        assert fn("FoobarEd") == "foobar_ed"
        assert fn("FooBarEd") == "foo_bar_ed"
        assert fn("Foo_Bar") == "foo_bar"
        assert fn("Foo__Bar") == "foo__bar"
        assert fn("FooBAR") == "foo_bar"
        assert fn("HTTPRequest") == "http_request"
        assert fn("HTTP_Request") == "http_request"
        assert fn("VerifyHTTPRequest") == "verify_http_request"
        assert fn("IsHTTP") == "is_http"
        assert fn("IsHTTP2Request") == "is_http2_request"

    def test_snake_to_camel_case(self):
        fn = common.snake_to_camel_case

        assert fn("foo") == "Foo"
        assert fn("foobar_ed") == "FoobarEd"
        assert fn("foo_bar_ed") == "FooBarEd"
        assert fn("foo_bar") == "FooBar"
        assert fn("foo__bar") == "FooBar"
        assert fn("foo_b_a_r") == "FooBAR"

    def test_obj_to_xml(self):
        fn = common.obj_to_xml
        # primitive
        assert fn(42) == "42"
        assert fn(False) == "False"
        assert fn("a") == "a"
        # dict only
        assert fn({"foo": "bar"}) == "<foo>bar</foo>"
        assert fn({"a": 42}) == "<a>42</a>"
        assert fn({"a": 42, "foo": "bar"}) == "<a>42</a><foo>bar</foo>"
        # list of dicts
        assert fn([{"a": 42}, {"a": 43}]) == "<a>42</a><a>43</a>"
        # dict with lists
        assert fn({"f": [{"a": 42}, {"a": 43}]}) == "<f><a>42</a><a>43</a></f>"
        # empty types
        assert fn(None) == "None"
        assert fn("") == ""

    def test_parse_json_or_yaml_with_json(self):
        markup = """{"foo": "bar", "why": 42, "mylist": [1,2,3]}"""

        doc = common.parse_json_or_yaml(markup)
        assert doc == {"foo": "bar", "why": 42, "mylist": [1, 2, 3]}

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
        assert doc == {"foo": "bar", "why": 42, "mylist": [1, 2, 3]}

    def test_parse_json_or_yaml_with_invalid_syntax_returns_content(self):
        markup = "<a href='foobar'>baz</a>"
        doc = common.parse_json_or_yaml(markup)
        assert doc == markup  # FIXME: not sure if this is good behavior

    def test_parse_json_or_yaml_with_empty_string_returns_none(self):
        doc = common.parse_json_or_yaml("")
        assert doc is None

    def test_format_bytes(self):
        fn = common.format_bytes

        assert fn(1) == "1B"
        assert fn(100) == "100B"
        assert fn(999) == "999B"
        assert fn(1e3) == "1KB"
        assert fn(1e6) == "1MB"
        assert fn(1e7) == "10MB"
        assert fn(1e8) == "100MB"
        assert fn(1e9) == "1GB"
        assert fn(1e12) == "1TB"

        # comma values
        assert fn(1e12 + 1e11) == "1.1TB"
        assert fn(1e15) == "1000TB"

        # string input
        assert fn("123") == "123B"
        # invalid number
        assert fn("abc") == "n/a"
        # negative number
        assert fn(-1) == "n/a"  # TODO: seems we could support this case

    def test_format_number(self):
        fn = common.format_number
        assert fn(12, decimals=0) == "12"
        assert fn(12, decimals=1) == "12"
        assert fn(12.421, decimals=0) == "12"
        assert fn(12.521, decimals=0) == "13"
        assert fn(12.521, decimals=2) == "12.52"
        assert fn(12.521, decimals=3) == "12.521"
        assert fn(12.521, decimals=4) == "12.521"
        assert fn(-12.521, decimals=4) == "-12.521"
        assert fn(-1.2234354123e3, decimals=4) == "-1223.4354"

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
        assert started.wait(timeout=2)
        common.cleanup_threads_and_processes()
        assert done.wait(timeout=2)

    def test_proxy_map(self):
        old_http_proxy = config.OUTBOUND_HTTP_PROXY
        old_https_proxy = config.OUTBOUND_HTTPS_PROXY
        config.OUTBOUND_HTTP_PROXY = "http://localhost"
        config.OUTBOUND_HTTPS_PROXY = "https://localhost"
        assert common.get_proxies() == {
            "http": config.OUTBOUND_HTTP_PROXY,
            "https": config.OUTBOUND_HTTPS_PROXY,
        }
        config.OUTBOUND_HTTP_PROXY = ""
        assert common.get_proxies() == {"https": config.OUTBOUND_HTTPS_PROXY}
        config.OUTBOUND_HTTPS_PROXY = ""
        assert common.get_proxies() == {}
        config.OUTBOUND_HTTP_PROXY = old_http_proxy
        config.OUTBOUND_HTTPS_PROXY = old_https_proxy

    def test_fully_qualified_class_name(self):
        assert fully_qualified_class_name(Mock) == "localstack.utils.objects.Mock"


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

    def test_unzip_bad_crc(self):
        """Test unzipping of files with incorrect CRC codes - usually works with native `unzip` command,
        but seems to fail with zipfile module under certain Python versions (extracts 0-bytes files)"""

        # base64-encoded zip file with a single entry with incorrect CRC (created by Node.js 18 / Serverless)
        zip_base64 = """
        UEsDBBQAAAAIAAAAIQAAAAAAJwAAAAAAAAAjAAAAbm9kZWpzL25vZGVfbW9kdWxlcy9sb2Rhc2gvaW5k
        ZXguanPLzU8pzUnVS60oyC8qKVawVShKLSzNLErVUNfTz8lPSSzOUNe0BgBQSwECLQMUAAAACAAAACEA
        AAAAACcAAAAAAAAAIwAAAAAAAAAAACAApIEAAAAAbm9kZWpzL25vZGVfbW9kdWxlcy9sb2Rhc2gvaW5k
        ZXguanNQSwUGAAAAAAEAAQBRAAAAaAAAAAAA
        """
        tmp_dir = new_tmp_dir()
        zip_file = os.path.join(tmp_dir, "test.zip")
        save_file(zip_file, base64.b64decode(zip_base64))
        unzip(zip_file, tmp_dir)
        content = load_file(os.path.join(tmp_dir, "nodejs", "node_modules", "lodash", "index.js"))
        assert content.strip() == "module.exports = require('./lodash');"
        rm_rf(tmp_dir)


def test_save_load_file(tmp_path):
    file_name = tmp_path / ("normal_permissions_%s" % short_uid())
    content = "some_content_%s" % short_uid()
    more_content = "some_more_content_%s" % short_uid()

    save_file(file_name, content)
    assert content == load_file(file_name)
    save_file(file_name, more_content, append=True)
    assert content + more_content == load_file(file_name)


def test_save_load_file_with_permissions(tmp_path):
    file_name = tmp_path / ("special_permissions_%s" % short_uid())
    content = "some_content_%s" % short_uid()
    more_content = "some_more_content_%s" % short_uid()
    permissions = 0o600

    save_file(file_name, content, permissions=permissions)
    assert permissions == os.stat(file_name).st_mode & 0o777
    assert content == load_file(file_name)
    save_file(file_name, more_content, append=True)
    assert permissions == os.stat(file_name).st_mode & 0o777
    assert content + more_content == load_file(file_name)


def test_save_load_file_with_changing_permissions(tmp_path):
    file_name = tmp_path / ("changing_permissions_%s" % short_uid())
    content = "some_content_%s" % short_uid()
    more_content = "some_more_content_%s" % short_uid()
    permissions = 0o600

    save_file(file_name, content)
    assert permissions != os.stat(file_name).st_mode & 0o777
    assert content == load_file(file_name)
    # setting the permissions on append should not change the permissions
    save_file(file_name, more_content, append=True, permissions=permissions)
    assert permissions != os.stat(file_name).st_mode & 0o777
    assert content + more_content == load_file(file_name)
    # overwriting the file also will not change the permissions
    save_file(file_name, content, permissions=permissions)
    assert permissions != os.stat(file_name).st_mode & 0o777
    assert content == load_file(file_name)


@pytest.fixture()
def external_service_ports_manager():
    previous_start = config.EXTERNAL_SERVICE_PORTS_START
    previous_end = config.EXTERNAL_SERVICE_PORTS_END
    # Limit the range to only contain a single port
    config.EXTERNAL_SERVICE_PORTS_START = get_free_tcp_port()
    config.EXTERNAL_SERVICE_PORTS_END = config.EXTERNAL_SERVICE_PORTS_START + 1
    yield ExternalServicePortsManager()
    config.EXTERNAL_SERVICE_PORTS_END = previous_end
    config.EXTERNAL_SERVICE_PORTS_START = previous_start


class TestExternalServicePortsManager:
    def test_reserve_port_within_range(
        self, external_service_ports_manager: ExternalServicePortsManager
    ):
        port = external_service_ports_manager.reserve_port(config.EXTERNAL_SERVICE_PORTS_START)
        assert port == config.EXTERNAL_SERVICE_PORTS_START

    def test_reserve_port_outside_range(
        self, external_service_ports_manager: ExternalServicePortsManager
    ):
        with pytest.raises(PortNotAvailableException):
            external_service_ports_manager.reserve_port(config.EXTERNAL_SERVICE_PORTS_START + 1)

    def test_reserve_any_port_within_range(
        self, external_service_ports_manager: ExternalServicePortsManager
    ):
        port = external_service_ports_manager.reserve_port()
        assert port == config.EXTERNAL_SERVICE_PORTS_START

    def test_reserve_port_all_reserved(
        self, external_service_ports_manager: ExternalServicePortsManager
    ):
        external_service_ports_manager.reserve_port()
        with pytest.raises(PortNotAvailableException):
            external_service_ports_manager.reserve_port()

    def test_reserve_same_port_twice(
        self, external_service_ports_manager: ExternalServicePortsManager
    ):
        external_service_ports_manager.reserve_port(config.EXTERNAL_SERVICE_PORTS_START)
        with pytest.raises(PortNotAvailableException):
            external_service_ports_manager.reserve_port(config.EXTERNAL_SERVICE_PORTS_START)

    def test_reserve_custom_expiry(
        self, external_service_ports_manager: ExternalServicePortsManager
    ):
        external_service_ports_manager.reserve_port(config.EXTERNAL_SERVICE_PORTS_START, duration=1)
        with pytest.raises(PortNotAvailableException):
            external_service_ports_manager.reserve_port(config.EXTERNAL_SERVICE_PORTS_START)
        time.sleep(1)
        external_service_ports_manager.reserve_port(config.EXTERNAL_SERVICE_PORTS_START)

    def test_check_is_port_reserved(
        self, external_service_ports_manager: ExternalServicePortsManager
    ):
        assert not external_service_ports_manager.is_port_reserved(
            config.EXTERNAL_SERVICE_PORTS_START
        )
        external_service_ports_manager.reserve_port(config.EXTERNAL_SERVICE_PORTS_START)
        assert external_service_ports_manager.is_port_reserved(config.EXTERNAL_SERVICE_PORTS_START)


@pytest.fixture()
def paginated_list():
    yield PaginatedList([{"Id": i, "Filter": i.upper()} for i in ["a", "b", "c", "d", "e"]])


class TestPaginatedList:
    def test_list_smaller_than_max(self, paginated_list):
        page, next_token = paginated_list.get_page(lambda i: i["Id"], page_size=6)
        assert len(page) == 5
        assert next_token is None

    def test_next_token(self, paginated_list):
        page, next_token = paginated_list.get_page(lambda i: i["Id"], page_size=2)
        assert len(page) == 2
        assert next_token == "c"

    def test_continuation(self, paginated_list):
        page, next_token = paginated_list.get_page(lambda i: i["Id"], page_size=2, next_token="c")
        assert len(page) == 2
        assert next_token == "e"

    def test_end(self, paginated_list):
        page, next_token = paginated_list.get_page(lambda i: i["Id"], page_size=2, next_token="e")
        assert len(page) == 1
        assert next_token is None

    def test_filter(self, paginated_list):
        page, next_token = paginated_list.get_page(
            lambda i: i["Id"], page_size=6, filter_function=lambda i: i["Filter"] in ["B", "E"]
        )
        assert len(page) == 2
        ids = [i["Id"] for i in page]
        assert "b" in ids and "e" in ids
        assert "a" not in ids
        assert next_token is None
