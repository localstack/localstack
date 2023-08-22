import zipfile

from plugin import Plugin

from .core import Decoder, Encoder, StateVisitor


class PodsPersistencePlugin(Plugin):
    """
    A plugin for the pods persistence mechanism, which allows you to return custom visitors for saving or loading
    pods state, if the service has a particular logic.
    """

    namespace: str = "localstack.persistence.pods"
    """Plugin namespace"""

    name: str
    """Name of the plugin corresponds to the name of the service this plugin is loaded for. To be set by the Plugin."""

    def create_create_pod_visitor(
        self, pod_archive: zipfile.ZipFile, encoder: Encoder = None
    ) -> StateVisitor:
        raise NotImplementedError

    def create_inject_pod_visitor(
        self, pod_archive: zipfile.ZipFile, decoder: Decoder = None
    ) -> StateVisitor:
        raise NotImplementedError
