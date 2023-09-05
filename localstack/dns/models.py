import dataclasses
from enum import Enum, auto
from typing import Callable, Protocol


class RecordType(Enum):
    A = auto()
    AAAA = auto()
    CNAME = auto()
    TXT = auto()
    MX = auto()
    SOA = auto()
    NS = auto()
    SRV = auto()


@dataclasses.dataclass(frozen=True)
class NameRecord:
    """
    Dataclass of a stored record
    """

    record_type: RecordType
    record_id: str | None = None


@dataclasses.dataclass(frozen=True)
class _TargetRecordBase:
    """
    Dataclass of a stored record
    """

    target: str


@dataclasses.dataclass(frozen=True)
class TargetRecord(NameRecord, _TargetRecordBase):
    pass


@dataclasses.dataclass(frozen=True)
class _SOARecordBase:
    m_name: str
    r_name: str


@dataclasses.dataclass(frozen=True)
class SOARecord(NameRecord, _SOARecordBase):
    pass


@dataclasses.dataclass(frozen=True)
class AliasTarget:
    target: str
    alias_id: str | None = None
    health_check: Callable[[], bool] | None = None


@dataclasses.dataclass(frozen=True)
class _DynamicRecordBase:
    """
    Dataclass of a record that is dynamically determined at query time to return the IP address
    of the LocalStack container
    """

    record_type: RecordType


@dataclasses.dataclass(frozen=True)
class DynamicRecord(NameRecord, _DynamicRecordBase):
    pass


# TODO decide if we need the whole concept of multiple zones in our DNS implementation
class DnsServerProtocol(Protocol):
    def add_host(self, name: str, record: NameRecord) -> None:
        """
        Add a host resolution to the DNS server.
        This will resolve the given host to the record provided, if it matches.

        :param name: Name pattern to add resolution for. Can be arbitrary regex.
        :param record: Record, consisting of a record type, an optional record id, and the attached data.
            Has to be a subclass of a NameRecord, not a NameRecord itself to contain some data.
        """
        pass

    def delete_host(self, name: str, record: NameRecord) -> None:
        """
        Deletes a host resolution from the DNS server.
        Only the name, the record type, and optionally the given record id will be used to find entries to delete.
        All matching entries will be deleted.

        :param name: Name pattern, identically to the one registered with `add_host`
        :param record: Record, ideally identically to the one registered with add_host but only record_type and
            record_id have to match to find the record.

        :raises ValueError: If no record that was previously registered with `add_host` was found which matches the provided record
        """
        pass

    def add_host_pointing_to_localstack(self, name: str) -> None:
        """
        Add a dns name which should be pointing to LocalStack when resolved.

        :param name: Name which should be pointing to LocalStack when resolved
        """
        pass

    def delete_host_pointing_to_localstack(self, name: str) -> None:
        """
        Removes a dns name from pointing to LocalStack

        :param name: Name to be removed
        :raises ValueError: If the host pointing to LocalStack was not previously registered using `add_host_pointing_to_localstack`
        """
        pass

    def add_alias(self, source_name: str, record_type: RecordType, target: AliasTarget) -> None:
        """
        Adds an alias to the DNS, with an optional healthcheck callback.
        When a request which matches `source_name` comes in, the DNS will check the aliases, and if the healthcheck
        (if provided) succeeds, the resolution result for the `target_name` will be returned instead.
        If multiple aliases are registered for the same source_name record_type tuple, and no health checks interfere,
        the server will process requests with the first added alias

        :param source_name: Alias name
        :param record_type: Record type of the alias
        :param target: Target of the alias
        """
        pass

    def delete_alias(self, source_name: str, record_type: RecordType, target: AliasTarget) -> None:
        """
        Removes an alias from the DNS.
        Only the name, the record type, and optionally the given alias id will be used to find entries to delete.
        All matching entries will be deleted.

        :param source_name: Alias name
        :param record_type: Record type of the alias to remove
        :param target: Target of the alias. Only relevant data for deletion will be its id.
        :raises ValueError: If the alias was not previously registered using `add_alias`
        """
        pass

    # TODO: support regex or wildcard?
    # need to update when custom cloudpod destination is enabled
    # has standard list of skips: localstack.services.dns_server.SKIP_PATTERNS
    def add_skip(self, skip_pattern: str) -> None:
        """
        Add a skip pattern to the DNS server.

        A skip pattern will prevent the DNS server from resolving a matching request against it's internal zones or
        aliases, and will directly contact an upstream DNS for resolution.

        This is usually helpful if AWS endpoints are overwritten by internal entries, but we have to reach AWS for
        some reason. (Often used for cloudpods or installers).

        :param skip_pattern: Skip pattern to add. Can be a valid regex.
        """
        pass

    def delete_skip(self, skip_pattern: str) -> None:
        """
        Removes a skip pattern from the DNS server.

        :param skip_pattern: Skip pattern to remove
        :raises ValueError: If the skip pattern was not previously registered using `add_skip`
        """
        pass

    def clear(self):
        """
        Removes all runtime configurations.
        """
        pass
