from plux import Plugin

from .core import StateVisitor


class SnapshotPersistencePlugin(Plugin):
    """
    A plugin for the snapshot persistence mechanism, which allows you to return custom visitors for saving or loading
    state, if the service has a particular logic.
    """

    namespace: str = "localstack.persistence.snapshot"
    """Plugin namespace"""

    name: str
    """Name of the plugin corresponds to the name of the service this plugin is loaded for. To be set by the Plugin."""

    def create_load_snapshot_visitor(self, service: str, data_dir: str) -> StateVisitor:
        raise NotImplementedError

    def create_save_snapshot_visitor(self, service: str, data_dir: str) -> StateVisitor:
        raise NotImplementedError
