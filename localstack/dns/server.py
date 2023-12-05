import argparse
import copy
import logging
import os
import re
import textwrap
import threading
from datetime import datetime
from functools import cache
from ipaddress import IPv4Address, IPv4Interface
from pathlib import Path
from socket import AddressFamily
from typing import Iterable, Literal, Tuple

import dns.flags
import dns.message
import dns.query
import psutil
from cachetools import TTLCache, cached
from dns.exception import Timeout
from dnslib import (
    AAAA,
    CNAME,
    MX,
    NS,
    QTYPE,
    RCODE,
    RD,
    RDMAP,
    RR,
    SOA,
    TXT,
    A,
    DNSHeader,
    DNSLabel,
    DNSQuestion,
    DNSRecord,
)
from dnslib.server import DNSHandler, DNSServer
from psutil._common import snicaddr

# Note: avoid adding additional imports here, to avoid import issues when running the CLI
from localstack import config
from localstack.constants import LOCALHOST_HOSTNAME, LOCALHOST_IP
from localstack.dns.models import (
    AliasTarget,
    DnsServerProtocol,
    DynamicRecord,
    NameRecord,
    RecordType,
    SOARecord,
    TargetRecord,
)
from localstack.services.edge import run_module_as_sudo
from localstack.utils import iputils
from localstack.utils.net import Port, port_can_be_bound
from localstack.utils.platform import in_docker
from localstack.utils.serving import Server
from localstack.utils.strings import to_bytes, to_str
from localstack.utils.sync import sleep_forever

EPOCH = datetime(1970, 1, 1)
SERIAL = int((datetime.utcnow() - EPOCH).total_seconds())

DEFAULT_FALLBACK_DNS_SERVER = "8.8.8.8"
FALLBACK_DNS_LOCK = threading.RLock()
VERIFICATION_DOMAIN = config.DNS_VERIFICATION_DOMAIN

RCODE_REFUSED = 5

DNS_SERVER: "DnsServerProtocol" = None

REQUEST_TIMEOUT_SECS = 7

TYPE_LOOKUP = {
    A: QTYPE.A,
    AAAA: QTYPE.AAAA,
    CNAME: QTYPE.CNAME,
    MX: QTYPE.MX,
    NS: QTYPE.NS,
    SOA: QTYPE.SOA,
    TXT: QTYPE.TXT,
}

LOG = logging.getLogger(__name__)

THREAD_LOCAL = threading.local()

# Type of the value given by DNSHandler.client_address
# in the form (ip, port) e.g. ("127.0.0.1", 58291)
ClientAddress = Tuple[str, int]

psutil_cache = TTLCache(maxsize=100, ttl=10)


@cached(cache=psutil_cache)
def list_network_interface_details() -> dict[str, list[snicaddr]]:
    return psutil.net_if_addrs()


class Record:
    def __init__(self, rdata_type, *args, **kwargs):
        rtype = kwargs.get("rtype")
        rname = kwargs.get("rname")
        ttl = kwargs.get("ttl")

        if isinstance(rdata_type, RD):
            # actually an instance, not a type
            self._rtype = TYPE_LOOKUP[rdata_type.__class__]
            rdata = rdata_type
        else:
            self._rtype = TYPE_LOOKUP[rdata_type]
            if rdata_type == SOA and len(args) == 2:
                # add sensible times to SOA
                args += (
                    (
                        SERIAL,  # serial number
                        60 * 60 * 1,  # refresh
                        60 * 60 * 3,  # retry
                        60 * 60 * 24,  # expire
                        60 * 60 * 1,  # minimum
                    ),
                )
            rdata = rdata_type(*args)

        if rtype:
            self._rtype = rtype
        self._rname = rname
        self.kwargs = dict(rdata=rdata, ttl=self.sensible_ttl() if ttl is None else ttl, **kwargs)

    def try_rr(self, q):
        if q.qtype == QTYPE.ANY or q.qtype == self._rtype:
            return self.as_rr(q.qname)

    def as_rr(self, alt_rname):
        return RR(rname=self._rname or alt_rname, rtype=self._rtype, **self.kwargs)

    def sensible_ttl(self):
        if self._rtype in (QTYPE.NS, QTYPE.SOA):
            return 60 * 60 * 24
        else:
            return 300

    @property
    def is_soa(self):
        return self._rtype == QTYPE.SOA

    def __str__(self):
        return f"{QTYPE[self._rtype]}({self.kwargs})"

    def __repr__(self):
        return self.__str__()


class RecordConverter:
    """
    Handles returning the correct DNS record for the stored name_record.

    Particularly, if the record is a DynamicRecord, then perform dynamic IP address lookup.
    """

    def __init__(self, request: DNSRecord, client_address: ClientAddress):
        self.request = request
        self.client_address = client_address

    def to_record(self, name_record: NameRecord) -> Record:
        """
        :param name_record: Internal representation of the name entry
        :return: Record type for the associated name record
        """
        match name_record:
            case TargetRecord(target=target, record_type=record_type):
                return Record(RDMAP.get(record_type.name), target)
            case SOARecord(m_name=m_name, r_name=r_name, record_type=_):
                return Record(SOA, m_name, r_name)
            case DynamicRecord(record_type=record_type):
                # Marker indicating that the target of the domain name lookup should be resolved
                # dynamically at query time to the most suitable LocalStack container IP address
                ip = self._determine_best_ip()
                # TODO: be more dynamic with IPv6
                if record_type == RecordType.AAAA:
                    ip = "::1"
                return Record(RDMAP.get(record_type.name), ip)
            case _:
                raise NotImplementedError(f"Record type '{type(name_record)}' not implemented")

    def _determine_best_ip(self) -> str:
        client_ip, _ = self.client_address
        # allow for overriding if required
        if config.DNS_RESOLVE_IP != LOCALHOST_IP:
            return config.DNS_RESOLVE_IP

        # Look up best matching ip address for the client
        interfaces = self._fetch_interfaces()
        for interface in interfaces:
            subnet = interface.network
            ip_address = IPv4Address(client_ip)
            if ip_address in subnet:
                # check if the request has come from the gateway or not. If so
                # assume the request has come from the host, and return
                # 127.0.0.1
                if config.is_in_docker and self._is_gateway(ip_address):
                    return LOCALHOST_IP

                return str(interface.ip)

        # no best solution found
        LOG.warning(
            f"could not determine subnet-matched IP address for {self.request.q.qname}, falling back to {LOCALHOST_IP}"
        )
        return LOCALHOST_IP

    @staticmethod
    def _is_gateway(ip: IPv4Address) -> bool:
        """
        Look up the gateways that this contianer has, and return True if the
        supplied ip address is in that list.
        """
        return ip == iputils.get_default_gateway()

    @staticmethod
    def _fetch_interfaces() -> Iterable[IPv4Interface]:
        interfaces = list_network_interface_details()
        for _, addresses in interfaces.items():
            for address in addresses:
                if address.family != AddressFamily.AF_INET:
                    # TODO: IPv6
                    continue

                # argument is of the form e.g. 127.0.0.1/255.0.0.0
                net = IPv4Interface(f"{address.address}/{address.netmask}")
                yield net


class NonLoggingHandler(DNSHandler):
    """Subclass of DNSHandler that avoids logging to stdout on error"""

    def handle(self, *args, **kwargs):
        try:
            THREAD_LOCAL.client_address = self.client_address
            THREAD_LOCAL.server = self.server
            THREAD_LOCAL.request = self.request
            return super(NonLoggingHandler, self).handle(*args, **kwargs)
        except Exception:
            pass


NAME_PATTERNS_POINTING_TO_LOCALSTACK = [
    f".*{LOCALHOST_HOSTNAME}",
]


def exclude_from_resolution(domain_regex: str):
    """
    Excludes the given domain pattern from being resolved to LocalStack.
    Currently only works in docker, since in host mode dns is started as separate process
    :param domain_regex: Domain regex string
    """
    if DNS_SERVER:
        DNS_SERVER.add_skip(domain_regex)


def revert_exclude_from_resolution(domain_regex: str):
    """
    Reverts the exclusion of the given domain pattern
    :param domain_regex: Domain regex string
    """
    try:
        if DNS_SERVER:
            DNS_SERVER.delete_skip(domain_regex)
    except ValueError:
        pass


def _should_delete_zone(record_to_delete: NameRecord, record_to_check: NameRecord):
    """
    Helper function to check if we should delete the record_to_check from the list we are iterating over
    :param record_to_delete: Record which we got from the delete request
    :param record_to_check: Record to be checked if it should be included in the records after delete
    :return:
    """
    if record_to_delete == record_to_check:
        return True
    return (
        record_to_delete.record_type == record_to_check.record_type
        and record_to_delete.record_id == record_to_check.record_id
    )


def _should_delete_alias(alias_to_delete: AliasTarget, alias_to_check: AliasTarget):
    """
    Helper function to check if we should delete the alias_to_check from the list we are iterating over
    :param alias_to_delete: Alias which we got from the delete request
    :param alias_to_check: Alias to be checked if it should be included in the records after delete
    :return:
    """
    return alias_to_delete.alias_id == alias_to_check.alias_id


class NoopLogger:
    """
    Necessary helper class to avoid logging of any dns records by dnslib
    """

    def __init__(self, *args, **kwargs):
        pass

    def log_pass(self, *args, **kwargs):
        pass

    def log_prefix(self, *args, **kwargs):
        pass

    def log_recv(self, *args, **kwargs):
        pass

    def log_send(self, *args, **kwargs):
        pass

    def log_request(self, *args, **kwargs):
        pass

    def log_reply(self, *args, **kwargs):
        pass

    def log_truncated(self, *args, **kwargs):
        pass

    def log_error(self, *args, **kwargs):
        pass

    def log_data(self, *args, **kwargs):
        pass


class Resolver(DnsServerProtocol):
    # Upstream DNS server
    upstream_dns: str
    # List of patterns which will be skipped for local resolution and always forwarded to upstream
    skip_patterns: list[str]
    # Dict of zones: (domain name or pattern) -> list[dns records]
    zones: dict[str, list[NameRecord]]
    # Alias map (source_name, record_type) => target_name (target name then still has to be resolved!)
    aliases: dict[tuple[DNSLabel, RecordType], list[AliasTarget]]
    # Lock to prevent issues due to concurrent modifications
    lock: threading.RLock

    def __init__(self, upstream_dns: str):
        self.upstream_dns = upstream_dns
        self.skip_patterns = []
        self.zones = {}
        self.aliases = {}
        self.lock = threading.RLock()

    def resolve(self, request: DNSRecord, handler: DNSHandler) -> DNSRecord | None:
        """
        Resolve a given request, by either checking locally registered records, or forwarding to the defined
        upstream DNS server.

        :param request: DNS Request
        :param handler: Unused.
        :return: DNS Reply
        """
        reply = request.reply()
        found = False

        try:
            if not self._skip_local_resolution(request):
                found = self._resolve_name(request, reply, handler.client_address)
        except Exception as e:
            LOG.info("Unable to get DNS result: %s", e)

        if found:
            return reply

        # If we did not find a matching record in our local zones, we forward to our upstream dns
        try:
            req_parsed = dns.message.from_wire(bytes(request.pack()))
            r = dns.query.udp(req_parsed, self.upstream_dns, timeout=REQUEST_TIMEOUT_SECS)
            result = self._map_response_dnspython_to_dnslib(r)
            return result
        except Exception as e:
            LOG.info(
                "Unable to get DNS result from upstream server %s for domain %s: %s",
                self.upstream_dns,
                str(request.q.qname),
                e,
            )

        # if we cannot reach upstream dns, return SERVFAIL
        if not reply.rr and reply.header.get_rcode == RCODE.NOERROR:
            # setting this return code will cause commands like 'host' to try the next nameserver
            reply.header.set_rcode(RCODE.SERVFAIL)
            return None

        return reply

    def _skip_local_resolution(self, request) -> bool:
        """
        Check whether we should skip local resolution for the given request, and directly contact upstream

        :param request: DNS Request
        :return: Whether the request local resolution should be skipped
        """
        request_name = to_str(str(request.q.qname))
        for p in self.skip_patterns:
            if re.match(p, request_name):
                return True
        return False

    def _resolve_alias(
        self, request: DNSRecord, reply: DNSRecord, client_address: ClientAddress
    ) -> bool:
        if request.q.qtype in (QTYPE.A, QTYPE.AAAA, QTYPE.CNAME):
            key = (DNSLabel(to_bytes(request.q.qname)), RecordType[QTYPE[request.q.qtype]])
            # check if we have aliases defined for our given qname/qtype pair
            if aliases := self.aliases.get(key):
                for alias in aliases:
                    # if there is no health check, or the healthcheck is successful, we will consider this alias
                    # take the first alias passing this check
                    if not alias.health_check or alias.health_check():
                        request_copy: DNSRecord = copy.deepcopy(request)
                        request_copy.q.qname = alias.target
                        # check if we can resolve the alias
                        found = self._resolve_name_from_zones(request_copy, reply, client_address)
                        if found:
                            LOG.debug(
                                "Found entry for AliasTarget '%s' ('%s')", request.q.qname, alias
                            )
                            # change the replaced rr-DNS names back to the original request
                            for rr in reply.rr:
                                rr.set_rname(request.q.qname)
                        else:
                            reply.header.set_rcode(RCODE.REFUSED)
                        return True
        return False

    def _resolve_name(
        self, request: DNSRecord, reply: DNSRecord, client_address: ClientAddress
    ) -> bool:
        if alias_found := self._resolve_alias(request, reply, client_address):
            LOG.debug("Alias found: %s", request.q.qname)
            return alias_found
        return self._resolve_name_from_zones(request, reply, client_address)

    def _resolve_name_from_zones(
        self, request: DNSRecord, reply: DNSRecord, client_address: ClientAddress
    ) -> bool:
        found = False

        converter = RecordConverter(request, client_address)

        # check for direct (not regex based) response
        zone = self.zones.get(request.q.qname)
        if zone is not None:
            for zone_records in zone:
                rr = converter.to_record(zone_records).try_rr(request.q)
                if rr:
                    found = True
                    reply.add_answer(rr)
        else:
            # no direct zone so look for an SOA record for a higher level zone
            for zone_label, zone_records in self.zones.items():
                # try regex match
                pattern = re.sub(r"(^|[^.])\*", ".*", str(zone_label))
                if re.match(pattern, str(request.q.qname)):
                    for record in zone_records:
                        rr = converter.to_record(record).try_rr(request.q)
                        if rr:
                            found = True
                            reply.add_answer(rr)
                # try suffix match
                elif request.q.qname.matchSuffix(to_bytes(zone_label)):
                    try:
                        soa_record = next(r for r in zone_records if converter.to_record(r).is_soa)
                    except StopIteration:
                        continue
                    else:
                        found = True
                        reply.add_answer(converter.to_record(soa_record).as_rr(zone_label))
                        break
        return found

    def _parse_section(self, section: str) -> list[RR]:
        result = []
        for line in section.split("\n"):
            line = line.strip()
            if line:
                if line.startswith(";"):
                    # section ended, stop parsing
                    break
                else:
                    result += RR.fromZone(line)
        return result

    def _map_response_dnspython_to_dnslib(self, response):
        """Map response object from dnspython to dnslib (looks like we cannot
        simply export/import the raw messages from the wire)"""
        flags = dns.flags.to_text(response.flags)

        def flag(f):
            return 1 if f.upper() in flags else 0

        questions = []
        for q in response.question:
            questions.append(DNSQuestion(qname=str(q.name), qtype=q.rdtype, qclass=q.rdclass))

        result = DNSRecord(
            DNSHeader(
                qr=flag("qr"), aa=flag("aa"), ra=flag("ra"), id=response.id, rcode=response.rcode()
            ),
            q=questions[0],
        )

        # extract answers
        answer_parts = str(response).partition(";ANSWER")
        result.add_answer(*self._parse_section(answer_parts[2]))
        # extract authority information
        authority_parts = str(response).partition(";AUTHORITY")
        result.add_auth(*self._parse_section(authority_parts[2]))
        return result

    def add_host(self, name: str, record: NameRecord):
        LOG.debug("Adding host %s with record %s", name, record)
        with self.lock:
            self.zones.setdefault(name, [])
            self.zones[name].append(record)

    def delete_host(self, name: str, record: NameRecord):
        LOG.debug("Deleting host %s with record %s", name, record)
        with self.lock:
            if not self.zones.get(name):
                raise ValueError("Could not find entry %s for name %s in zones", record, name)
            self.zones.setdefault(name, [])
            current_zones = self.zones[name]
            self.zones[name] = [
                zone for zone in self.zones[name] if not _should_delete_zone(record, zone)
            ]
            if self.zones[name] == current_zones:
                raise ValueError("Could not find entry %s for name %s in zones", record, name)
            # if we deleted the last entry, clean up
            if not self.zones[name]:
                del self.zones[name]

    def add_alias(self, source_name: str, record_type: RecordType, target: AliasTarget):
        LOG.debug("Adding alias %s with record type %s target %s", source_name, record_type, target)
        label = (DNSLabel(to_bytes(source_name)), record_type)
        with self.lock:
            self.aliases.setdefault(label, [])
            self.aliases[label].append(target)

    def delete_alias(self, source_name: str, record_type: RecordType, target: AliasTarget):
        LOG.debug(
            "Deleting alias %s with record type %s",
            source_name,
            record_type,
        )
        label = (DNSLabel(to_bytes(source_name)), record_type)
        with self.lock:
            if not self.aliases.get(label):
                raise ValueError(
                    "Could not find entry %s for name %s, record type %s in aliases",
                    target,
                    source_name,
                    record_type,
                )
            self.aliases.setdefault(label, [])
            current_aliases = self.aliases[label]
            self.aliases[label] = [
                alias for alias in self.aliases[label] if not _should_delete_alias(target, alias)
            ]
            if self.aliases[label] == current_aliases:
                raise ValueError(
                    "Could not find entry %s for name %s, record_type %s in aliases",
                    target,
                    source_name,
                    record_type,
                )
            # if we deleted the last entry, clean up
            if not self.aliases[label]:
                del self.aliases[label]

    def add_host_pointing_to_localstack(self, name: str):
        LOG.debug("Adding host %s pointing to LocalStack", name)
        self.add_host(name, DynamicRecord(record_type=RecordType.A))
        if config.DNS_RESOLVE_IP == config.LOCALHOST_IP:
            self.add_host(name, DynamicRecord(record_type=RecordType.AAAA))

    def delete_host_pointing_to_localstack(self, name: str):
        LOG.debug("Deleting host %s pointing to LocalStack", name)
        self.delete_host(name, DynamicRecord(record_type=RecordType.A))
        if config.DNS_RESOLVE_IP == config.LOCALHOST_IP:
            self.delete_host(name, DynamicRecord(record_type=RecordType.AAAA))

    def add_skip(self, skip_pattern: str):
        LOG.debug("Adding skip pattern %s", skip_pattern)
        self.skip_patterns.append(skip_pattern)

    def delete_skip(self, skip_pattern: str):
        LOG.debug("Deleting skip pattern %s", skip_pattern)
        self.skip_patterns.remove(skip_pattern)

    def clear(self):
        LOG.debug("Clearing DNS zones")
        self.skip_patterns.clear()
        self.zones.clear()
        self.aliases.clear()


class DnsServer(Server, DnsServerProtocol):
    servers: list[DNSServer]
    resolver: Resolver | None

    def __init__(
        self,
        port: int,
        protocols: list[Literal["udp", "tcp"]],
        upstream_dns: str,
        host: str = "0.0.0.0",
    ) -> None:
        super().__init__(port, host)
        self.resolver = Resolver(upstream_dns=upstream_dns)
        self.protocols = protocols
        self.servers = []
        self.handler_class = NonLoggingHandler

    def _get_servers(self) -> list[DNSServer]:
        servers = []
        for protocol in self.protocols:
            # TODO add option to use normal logger instead of NoopLogger for verbose debug mode
            servers.append(
                DNSServer(
                    self.resolver,
                    handler=self.handler_class,
                    logger=NoopLogger(),
                    port=self.port,
                    address=self.host,
                    tcp=protocol == "tcp",
                )
            )
        return servers

    @property
    def protocol(self):
        return "udp"

    def health(self):
        """
        Runs a health check on the server. The default implementation performs is_port_open on the server URL.
        """
        try:
            request = dns.message.make_query("localhost.localstack.cloud", "A")
            answers = dns.query.udp(request, "127.0.0.1", port=self.port, timeout=0.5).answer
            return len(answers) > 0
        except Exception:
            return False

    def do_run(self):
        self.servers = self._get_servers()
        for server in self.servers:
            server.start_thread()
        LOG.debug("DNS Server started")
        for server in self.servers:
            server.thread.join()

    def do_shutdown(self):
        for server in self.servers:
            server.stop()

    def add_host(self, name: str, record: NameRecord):
        self.resolver.add_host(name, record)

    def delete_host(self, name: str, record: NameRecord):
        self.resolver.delete_host(name, record)

    def add_alias(self, source_name: str, record_type: RecordType, target: AliasTarget):
        self.resolver.add_alias(source_name, record_type, target)

    def delete_alias(self, source_name: str, record_type: RecordType, target: AliasTarget):
        self.resolver.delete_alias(source_name, record_type, target)

    def add_host_pointing_to_localstack(self, name: str):
        self.resolver.add_host_pointing_to_localstack(name)

    def delete_host_pointing_to_localstack(self, name: str):
        self.resolver.delete_host_pointing_to_localstack(name)

    def add_skip(self, skip_pattern: str):
        self.resolver.add_skip(skip_pattern)

    def delete_skip(self, skip_pattern: str):
        self.resolver.delete_skip(skip_pattern)

    def clear(self):
        self.resolver.clear()


class SeparateProcessDNSServer(Server, DnsServerProtocol):
    def __init__(
        self,
        port: int = 53,
        host: str = "0.0.0.0",
    ) -> None:
        super().__init__(port, host)

    @property
    def protocol(self):
        return "udp"

    def health(self):
        """
        Runs a health check on the server. The default implementation performs is_port_open on the server URL.
        """
        try:
            request = dns.message.make_query("localhost.localstack.cloud", "A")
            answers = dns.query.udp(request, "127.0.0.1", port=self.port, timeout=0.5).answer
            return len(answers) > 0
        except Exception:
            return False

    def do_start_thread(self):
        # For host mode
        env_vars = {}
        for env_var in config.CONFIG_ENV_VARS:
            if env_var.startswith("DNS_"):
                value = os.environ.get(env_var, None)
                if value is not None:
                    env_vars[env_var] = value

        # note: running in a separate process breaks integration with Route53 (to be fixed for local dev mode!)
        thread = run_module_as_sudo(
            "localstack.dns.server",
            asynchronous=True,
            env_vars=env_vars,
            arguments=["-p", str(self.port)],
        )
        return thread


def get_fallback_dns_server():
    return config.DNS_SERVER or get_available_dns_server()


@cache
def get_available_dns_server():
    #  TODO check if more loop-checks are necessary than just not using our own DNS server
    with FALLBACK_DNS_LOCK:
        resolver = dns.resolver.Resolver()
        # we do not want to include localhost here, or a loop might happen
        candidates = [r for r in resolver.nameservers if r != "127.0.0.1"]
        result = None
        candidates.append(DEFAULT_FALLBACK_DNS_SERVER)
        for ns in candidates:
            resolver.nameservers = [ns]
            try:
                try:
                    answer = resolver.resolve(VERIFICATION_DOMAIN, "a", lifetime=3)
                    answer = [
                        res.to_text() for answers in answer.response.answer for res in answers.items
                    ]
                except Timeout:
                    answer = None
                if not answer:
                    continue
                result = ns
                break
            except Exception:
                pass

        if result:
            LOG.debug("Determined fallback dns: %s", result)
        else:
            LOG.info(
                "Unable to determine fallback DNS. Please check if '%s' is reachable by your configured DNS servers"
                "DNS fallback will be disabled.",
                VERIFICATION_DOMAIN,
            )
        return result


# ###### LEGACY METHODS ######
def add_resolv_entry(file_path: Path | str = Path("/etc/resolv.conf")):
    # never overwrite the host configuration without the user's permission
    if not in_docker():
        LOG.warning("Incorrectly attempted to alter host networking config")
        return

    LOG.debug("Overwriting container DNS server to point to localhost")
    content = textwrap.dedent(
        """
    # The following line is required by LocalStack
    nameserver 127.0.0.1
    """
    )
    file_path = Path(file_path)
    try:
        with file_path.open("w") as outfile:
            print(content, file=outfile)
    except Exception:
        LOG.warning(
            "Could not update container DNS settings", exc_info=LOG.isEnabledFor(logging.DEBUG)
        )


def setup_network_configuration():
    # check if DNS is disabled
    if not config.use_custom_dns():
        return

    # add entry to /etc/resolv.conf
    if in_docker():
        add_resolv_entry()


def start_server(upstream_dns: str, host: str, port: int = config.DNS_PORT):
    global DNS_SERVER

    if DNS_SERVER:
        # already started - bail
        LOG.debug("DNS servers are already started. Avoid starting again.")
        return

    LOG.debug("Starting DNS servers (tcp/udp port %s on %s)..." % (port, host))
    dns_server = DnsServer(port, protocols=["tcp", "udp"], host=host, upstream_dns=upstream_dns)

    for name in NAME_PATTERNS_POINTING_TO_LOCALSTACK:
        dns_server.add_host_pointing_to_localstack(name)
    if config.LOCALSTACK_HOST.host != LOCALHOST_HOSTNAME:
        dns_server.add_host_pointing_to_localstack(f".*{config.LOCALSTACK_HOST.host}")

    # support both DNS_NAME_PATTERNS_TO_RESOLVE_UPSTREAM and DNS_LOCAL_NAME_PATTERNS
    # until the next major version change
    # TODO(srw): remove the usage of DNS_LOCAL_NAME_PATTERNS
    skip_local_resolution = " ".join(
        [
            config.DNS_NAME_PATTERNS_TO_RESOLVE_UPSTREAM,
            config.DNS_LOCAL_NAME_PATTERNS,
        ]
    ).strip()
    if skip_local_resolution:
        for skip_pattern in re.split(r"[,;\s]+", skip_local_resolution):
            dns_server.add_skip(skip_pattern)

    dns_server.start()
    if not dns_server.wait_is_up(timeout=5):
        LOG.warning("DNS server did not come up within 5 seconds.")
        dns_server.shutdown()
        return
    DNS_SERVER = dns_server
    LOG.debug("DNS server startup finished.")


def stop_servers():
    if DNS_SERVER:
        DNS_SERVER.shutdown()


def start_dns_server_as_sudo(port: int):
    global DNS_SERVER
    LOG.debug(
        "Starting the DNS on its privileged port (%s) needs root permissions. Trying to start DNS with sudo.",
        config.DNS_PORT,
    )

    dns_server = SeparateProcessDNSServer(port)
    dns_server.start()

    if not dns_server.wait_is_up(timeout=5):
        LOG.warning("DNS server did not come up within 5 seconds.")
        dns_server.shutdown()
        return

    DNS_SERVER = dns_server
    LOG.debug("DNS server startup finished (as sudo).")


def start_dns_server(port: int, asynchronous: bool = False, standalone: bool = False):
    if DNS_SERVER:
        # already started - bail
        LOG.error("DNS servers are already started. Avoid starting again.")
        return

    # check if DNS server is disabled
    if not config.use_custom_dns():
        LOG.debug("Not starting DNS. DNS_ADDRESS=%s", config.DNS_ADDRESS)
        return

    upstream_dns = get_fallback_dns_server()
    if not upstream_dns:
        LOG.warning("Error starting the DNS server: No upstream dns server found.")
        return

    # host to bind the DNS server to. In docker we always want to bind to "0.0.0.0"
    host = config.DNS_ADDRESS
    if in_docker():
        host = "0.0.0.0"

    if port_can_be_bound(Port(port, "udp"), address=host):
        start_server(port=port, host=host, upstream_dns=upstream_dns)
        if not asynchronous:
            sleep_forever()
        return

    if standalone:
        LOG.debug("Already in standalone mode and port binding still fails.")
        return

    start_dns_server_as_sudo(port)


def get_dns_server() -> DnsServerProtocol:
    return DNS_SERVER


def is_server_running() -> bool:
    return DNS_SERVER is not None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", required=False, default=53, type=int)
    args = parser.parse_args()

    start_dns_server(asynchronous=False, port=args.port, standalone=True)
