import threading
from pathlib import Path

import dns
import pytest

from localstack import config
from localstack.dns.models import AliasTarget, RecordType, SOARecord, TargetRecord
from localstack.dns.server import DnsServer, add_resolv_entry, get_fallback_dns_server
from localstack.utils.net import get_free_udp_port
from localstack.utils.sync import retry


class TestDNSServer:
    @pytest.fixture
    def dns_server(self):
        dns_port = get_free_udp_port()
        upstream_dns = get_fallback_dns_server()
        dns_server = DnsServer(
            port=dns_port, protocols=["udp"], host="127.0.0.1", upstream_dns=upstream_dns
        )
        dns_server.start()
        assert dns_server.wait_is_up(5)
        yield dns_server
        dns_server.shutdown()

    @pytest.fixture
    def query_dns(self, dns_server):
        def _query(name: str, record_type: str) -> dns.message.Message:
            request = dns.message.make_query(name, record_type)

            def _do_query():
                return dns.query.udp(request, "127.0.0.1", port=dns_server.port, timeout=1)

            return retry(_do_query, retries=5)

        return _query

    def test_dns_server_fallback(self, dns_server, query_dns):
        """Test querying an unconfigured DNS server for its upstream requests"""
        answer = query_dns("localhost.localstack.cloud", "A")
        assert answer.answer
        assert "127.0.0.1" in answer.to_text()

    def test_dns_server_add_host_lifecycle(self, dns_server, query_dns):
        """Check dns server host entry lifecycle"""
        # add ipv4 host
        dns_server.add_host("example.org", TargetRecord("122.122.122.122", RecordType.A))
        answer = query_dns("example.org", "A")
        assert answer.answer
        assert "122.122.122.122" in answer.to_text()

        # add ipv6 host
        dns_server.add_host("example.org", TargetRecord("::a1", RecordType.AAAA))
        answer = query_dns("example.org", "AAAA")
        assert answer.answer
        assert "122.122.122.122" not in answer.to_text()
        assert "::a1" in answer.to_text()

        # assert ipv6 is not returned in A request
        answer = query_dns("example.org", "A")
        assert answer.answer
        assert "122.122.122.122" in answer.to_text()
        assert "::a1" not in answer.to_text()

        # delete ipv4 host
        dns_server.delete_host("example.org", TargetRecord("122.122.122.122", RecordType.A))
        answer = query_dns("example.org", "A")
        assert answer.answer
        assert "122.122.122.122" not in answer.to_text()

        # check that ipv6 host is unaffected
        answer = query_dns("example.org", "AAAA")
        assert answer.answer
        assert "122.122.122.122" not in answer.to_text()
        assert "::a1" in answer.to_text()

        # delete ipv6 host
        dns_server.delete_host("example.org", TargetRecord("::a1", RecordType.AAAA))
        answer = query_dns("example.org", "AAAA")
        assert answer.answer
        assert "122.122.122.122" not in answer.to_text()
        assert "::a1" not in answer.to_text()

    def test_dns_server_add_host_lifecycle_with_ids(self, dns_server, query_dns):
        """Check if deletion with and without ids works as expected"""
        # add ipv4 hosts
        dns_server.add_host("example.org", TargetRecord("1.1.1.1", RecordType.A, record_id="1"))
        dns_server.add_host("example.org", TargetRecord("2.2.2.2", RecordType.A, record_id="2"))
        dns_server.add_host("example.org", TargetRecord("3.3.3.3", RecordType.A))
        dns_server.add_host("example.org", TargetRecord("4.4.4.4", RecordType.A))

        # check if all are returned
        answer = query_dns("example.org", "A")
        assert answer.answer
        assert "1.1.1.1" in answer.to_text()
        assert "2.2.2.2" in answer.to_text()
        assert "3.3.3.3" in answer.to_text()
        assert "4.4.4.4" in answer.to_text()

        # delete by id, check if others are still present
        dns_server.delete_host("example.org", TargetRecord("", RecordType.A, record_id="1"))
        answer = query_dns("example.org", "A")
        assert answer.answer
        assert "2.2.2.2" in answer.to_text()
        assert "3.3.3.3" in answer.to_text()
        assert "4.4.4.4" in answer.to_text()
        assert "1.1.1.1" not in answer.to_text()

        # delete without id, check if others are still present
        dns_server.delete_host("example.org", TargetRecord("", RecordType.A))
        answer = query_dns("example.org", "A")
        assert answer.answer
        assert "2.2.2.2" in answer.to_text()
        assert "3.3.3.3" not in answer.to_text()
        assert "4.4.4.4" not in answer.to_text()
        assert "1.1.1.1" not in answer.to_text()

    def test_dns_server_add_multiple_hosts(self, dns_server, query_dns):
        """Test whether the dns server correctly works when multiple hosts are added"""
        # add ipv4 host
        dns_server.add_host(".*.example.org", TargetRecord("122.122.122.122", RecordType.A))
        dns_server.add_host(".*.notmatching.org", TargetRecord("123.123.123.123", RecordType.A))
        answer = query_dns("something.example.org", "A")
        assert answer.answer
        assert "122.122.122.122" in answer.to_text()

        answer = query_dns("something.notmatching.org", "A")
        assert answer.answer
        assert "123.123.123.123" in answer.to_text()

    def test_overriding_with_dns_resolve_ip(self, dns_server, query_dns, monkeypatch):
        monkeypatch.setattr(config, "DNS_RESOLVE_IP", "2.2.2.2")

        dns_server.add_host_pointing_to_localstack("example.org")

        answer = query_dns("example.org", "A")

        assert answer.answer
        assert "2.2.2.2" in answer.to_text()

    def test_dns_server_soa_record_suffix_matching(self, dns_server, query_dns):
        """Check if soa records work with suffix matching"""
        # add ipv4 host
        soa_target = "something.org."
        soa_rname = "noc.something.org."
        dns_server.add_host("example.org", SOARecord(soa_target, soa_rname, RecordType.SOA))
        answer = query_dns("something.example.org", "A")
        assert answer.answer
        assert "something.org." in answer.to_text()
        assert "noc.something.org." in answer.to_text()

    def test_dns_server_subdomain_of_route(self, dns_server, query_dns):
        """Test querying a subdomain of a record entry without a wildcard"""
        # add ipv4 host
        dns_server.add_host("example.org", TargetRecord("127.0.0.1", RecordType.A))
        answer = query_dns("nonexistent.example.org", "A")
        assert not answer.answer
        # should still have authority section
        # TODO uncomment once it is clear why in CI the authority section is missing
        # assert "ns.icann.org." in answer.to_text()
        assert answer.rcode() == dns.rcode.NXDOMAIN

    def test_dns_server_wildcard_matching_with_skip(self, dns_server, query_dns):
        """Test a wildcard matching and the skip bypass"""
        # add ipv4 host
        dns_server.add_host("*.example.org", TargetRecord("122.122.122.122", RecordType.A))
        answer = query_dns("subdomain.example.org", "A")
        assert answer.answer
        assert "122.122.122.122" in answer.to_text()

        dns_server.add_skip("skip.example.org")
        answer = query_dns("skip.example.org", "A")
        assert not answer.answer
        # test if skip does not affect other requests
        answer = query_dns("subdomain.example.org", "A")
        assert answer.answer
        assert "122.122.122.122" in answer.to_text()

    def test_dns_server_specific_name_overrides_wildcard(self, dns_server, query_dns):
        dns_server.add_host("*.example.org", TargetRecord("1.2.3.4", RecordType.A))
        dns_server.add_host("foo.example.org", TargetRecord("5.6.7.8", RecordType.A))

        answer = query_dns("foo.example.org", "A")

        assert answer.answer
        assert "5.6.7.8" in answer.to_text()
        assert "1.2.3.4" not in answer.to_text()

    def test_redirect_to_localstack_lifecycle(self, dns_server, query_dns):
        """Test adding records pointing to LS at all times"""
        dns_server.add_host_pointing_to_localstack("*.example.org")
        answer = query_dns("subdomain.example.org", "A")
        assert answer.answer
        assert "127.0.0.1" in answer.to_text()

        # delete host pointing to localstack again
        dns_server.delete_host_pointing_to_localstack("*.example.org")
        answer = query_dns("subdomain.example.org", "A")
        assert not answer.answer
        assert "127.0.0.1" not in answer.to_text()

    def test_skip_lifecycle(self, dns_server, query_dns):
        """Test adding and removing skip patterns"""
        # add ipv4 host
        dns_server.add_host("*.example.org", TargetRecord("122.122.122.122", RecordType.A))
        answer = query_dns("subdomain.example.org", "A")
        assert answer.answer
        assert "122.122.122.122" in answer.to_text()

        # add skip and check if it works
        dns_server.add_skip("skip.example.org")
        answer = query_dns("skip.example.org", "A")
        assert not answer.answer

        # delete skip again
        dns_server.delete_skip("skip.example.org")
        answer = query_dns("skip.example.org", "A")
        assert answer.answer
        assert "122.122.122.122" in answer.to_text()

    def test_redirect_to_localstack_with_skip(self, dns_server, query_dns):
        """Test to-localstack redirects with skip patterns for certain names"""
        # add ipv4 host
        dns_server.add_host_pointing_to_localstack("*.example.org")
        answer = query_dns("subdomain.example.org", "A")
        assert answer.answer
        assert "127.0.0.1" in answer.to_text()

        dns_server.add_skip("skip.example.org")
        answer = query_dns("skip.example.org", "A")
        assert not answer.answer
        # test if skip does not affect other requests
        answer = query_dns("subdomain.example.org", "A")
        assert answer.answer
        assert "127.0.0.1" in answer.to_text()

    def test_dns_server_clear(self, dns_server, query_dns):
        """Check if a clear call resets all added entries in the dns server"""
        dns_server.add_host(
            "*.subdomain.example.org", TargetRecord("122.122.122.122", RecordType.A)
        )
        answer = query_dns("sub.subdomain.example.org", "A")
        assert answer.answer
        assert "122.122.122.122" in answer.to_text()

        dns_server.add_skip("skip.subdomain.example.org")
        answer = query_dns("skip.subdomain.example.org", "A")
        assert not answer.answer
        # test if skip does not affect other requests
        answer = query_dns("sub.subdomain.example.org", "A")
        assert answer.answer
        assert "122.122.122.122" in answer.to_text()

        # add alias
        dns_server.add_alias(
            source_name="name.example.org",
            record_type=RecordType.A,
            target=AliasTarget(target="sub.subdomain.example.org"),
        )
        answer = query_dns("name.example.org", "A")
        assert answer.answer
        assert "122.122.122.122" in answer.to_text()

        # clear
        dns_server.clear()
        answer = query_dns("subdomain.example.org", "A")
        assert not answer.answer
        answer = query_dns("skip.example.org", "A")
        assert not answer.answer
        answer = query_dns("name.example.org", "A")
        assert not answer.answer

    def test_dns_server_alias_lifecycle(self, dns_server, query_dns):
        """Test adding and deleting aliases"""
        dns_server.add_host("example.org", TargetRecord("122.122.122.122", RecordType.A))
        dns_server.add_alias(
            source_name="foo.something.org",
            record_type=RecordType.A,
            target=AliasTarget(target="example.org"),
        )
        answer = query_dns("foo.something.org", "A")
        assert answer.answer
        assert "122.122.122.122" in answer.to_text()

        # delete alias and try again
        dns_server.delete_alias(
            source_name="foo.something.org", record_type=RecordType.A, target=AliasTarget(target="")
        )
        answer = query_dns("foo.something.org", "A")
        assert not answer.answer

        # check if add_host is still available
        answer = query_dns("example.org", "A")
        assert answer.answer
        assert "122.122.122.122" in answer.to_text()

    def test_dns_server_add_alias_lifecycle_with_ids(self, dns_server, query_dns):
        """Check if deletion with and without ids works as expected"""
        # add ipv4 hosts
        dns_server.add_host("target1.example.org", TargetRecord("1.1.1.1", RecordType.A))
        dns_server.add_host("target2.example.org", TargetRecord("2.2.2.2", RecordType.A))
        dns_server.add_host("target3.example.org", TargetRecord("3.3.3.3", RecordType.A))
        dns_server.add_host("target4.example.org", TargetRecord("4.4.4.4", RecordType.A))
        dns_server.add_alias(
            source_name="alias1.example.org",
            record_type=RecordType.A,
            target=AliasTarget(target="target1.example.org", alias_id="1"),
        )
        dns_server.add_alias(
            source_name="alias1.example.org",
            record_type=RecordType.A,
            target=AliasTarget(target="target2.example.org"),
        )
        dns_server.add_alias(
            source_name="alias1.example.org",
            record_type=RecordType.A,
            target=AliasTarget(target="target3.example.org"),
        )
        dns_server.add_alias(
            source_name="alias1.example.org",
            record_type=RecordType.A,
            target=AliasTarget(target="target4.example.org", alias_id="4"),
        )
        answer = query_dns("alias1.example.org", "A")
        assert answer.answer
        assert "1.1.1.1" in answer.to_text()

        dns_server.delete_alias(
            source_name="alias1.example.org",
            record_type=RecordType.A,
            target=AliasTarget(target="", alias_id="1"),
        )
        answer = query_dns("alias1.example.org", "A")
        assert answer.answer
        assert "2.2.2.2" in answer.to_text()

        dns_server.delete_alias(
            source_name="alias1.example.org",
            record_type=RecordType.A,
            target=AliasTarget(target=""),
        )
        answer = query_dns("alias1.example.org", "A")
        assert answer.answer
        assert "4.4.4.4" in answer.to_text()

    def test_dns_server_alias_health_checks(self, dns_server, query_dns):
        """Check if aliases work correctly with their health checks"""
        # add ipv4 hosts
        dns_server.add_host("target1.example.org", TargetRecord("1.1.1.1", RecordType.A))
        dns_server.add_host("target2.example.org", TargetRecord("2.2.2.2", RecordType.A))
        error = threading.Event()

        def health_check():
            nonlocal error
            return not error.is_set()

        dns_server.add_alias(
            source_name="alias1.example.org",
            record_type=RecordType.A,
            target=AliasTarget(target="target1.example.org", health_check=health_check),
        )
        dns_server.add_alias(
            source_name="alias1.example.org",
            record_type=RecordType.A,
            target=AliasTarget(target="target2.example.org"),
        )
        answer = query_dns("alias1.example.org", "A")
        assert answer.answer
        assert "1.1.1.1" in answer.to_text()

        # make health check failing
        error.set()
        answer = query_dns("alias1.example.org", "A")
        assert answer.answer
        assert "2.2.2.2" in answer.to_text()

        # make health check pass again
        error.clear()
        answer = query_dns("alias1.example.org", "A")
        assert answer.answer
        assert "1.1.1.1" in answer.to_text()

    def test_delete_operations_of_nonexistent_entries(self, dns_server):
        """Test that delete operations return a value error if the record/pattern does not exist"""
        with pytest.raises(ValueError):
            dns_server.delete_host("example.org", TargetRecord("122.122.122.122", RecordType.A))

        with pytest.raises(ValueError):
            dns_server.delete_host_pointing_to_localstack("*.example.org")

        with pytest.raises(ValueError):
            dns_server.delete_skip("skip.example.org")

        with pytest.raises(ValueError):
            dns_server.delete_alias(
                source_name="foo.something.org",
                record_type=RecordType.A,
                target=AliasTarget(target=""),
            )


class TestDnsUtils:
    def test_resolv_conf_overwriting(self, tmp_path: Path, monkeypatch):
        from localstack.dns import server

        monkeypatch.setattr(server, "in_docker", lambda: True)

        file = tmp_path.joinpath("resolv.conf")
        with file.open("w") as outfile:
            print("nameserver 127.0.0.11", file=outfile)

        add_resolv_entry(file)

        with file.open() as infile:
            new_contents = infile.read()

        assert "nameserver 127.0.0.1" in new_contents.splitlines()

    def test_no_resolv_conf_overwriting_on_host(self, tmp_path: Path, monkeypatch):
        from localstack.dns import server

        monkeypatch.setattr(server, "in_docker", lambda: False)

        file = tmp_path.joinpath("resolv.conf")
        with file.open("w") as outfile:
            print("nameserver 127.0.0.11", file=outfile)

        add_resolv_entry(file)

        with file.open() as infile:
            new_contents = infile.read()

        assert "nameserver 127.0.0.1" not in new_contents.splitlines()
        assert "nameserver 127.0.0.11" in new_contents.splitlines()
