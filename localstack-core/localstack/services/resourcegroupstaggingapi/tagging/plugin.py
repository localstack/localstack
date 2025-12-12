import logging

from plux import Plugin, PluginManager

from localstack.aws.api import RequestContext
from localstack.utils.objects import singleton_factory

LOG = logging.getLogger(__name__)

TAGGING_PLUGIN_NAMESPACE = "localstack.service.tagging.plugins"


class TaggingPlugin(Plugin):
    """
    The plugin is to be used to expose the inherited service plugins to the Resource Groups Tagging API.
    This will allow supported service resources to be tagged via this API by calling the individual service
    implementations of `tag_<resource>` or `untag_<resource>` whilst obeying IAM restrictions.
    """

    namespace = TAGGING_PLUGIN_NAMESPACE

    def tag_resource(
        self, context: RequestContext, resource_arn: str, tags: dict[str, str]
    ) -> None:
        """
        Tags the resource using the service's built in tagging functionality.

        :param context: The context of the original tagging operation. This is to enforce IAM restrictions.
        :param resource_arn: The ARN of the resource which is being tagged.
        :param tags: The tags to apply to the resource.
        :return: None
        """
        pass

    def untag_resource(
        self, context: RequestContext, resource_arn: str, tag_keys: list[str]
    ) -> None:
        """
        Untags a resource using the service's built in un-tagging functionality.

        :param context: The context of the original un-tagging operation. This is to enforce IAM restrictions.
        :param resource_arn: The ARN of the resource which is being untagged.
        :param tag_keys: The tag keys to remove from the resource's tags.
        :return: None
        """
        pass


class TaggingPluginManager(PluginManager[TaggingPlugin]):
    def __init__(self):
        super().__init__(TAGGING_PLUGIN_NAMESPACE)

    @staticmethod
    @singleton_factory
    def get() -> "TaggingPluginManager":
        """
        Returns a singleton instance of the TaggingPluginManager.
        """
        return TaggingPluginManager()

    def get_plugin(self, service: str) -> TaggingPlugin | None:
        """
        Get the Tagging Plugin for a specific service.

        :param service: The service the TaggingPlugin will be returned for.
        :return: TaggingPlugin for a specific service, or None if it doesn't exist.
        """
        try:
            return self.load(service)
        except ValueError:
            return None
