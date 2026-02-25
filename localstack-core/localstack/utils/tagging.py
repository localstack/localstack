from dataclasses import dataclass, field
from warnings import deprecated


@deprecated("`TaggingService` is deprecated. Please use the `RGTAPlugin`/`Tags` system.")
class TaggingService:
    key_field: str
    value_field: str

    tags: dict[str, dict[str, str]]

    def __init__(self, key_field: str = "Key", value_field: str = "Value"):
        """
        :param key_field: the field name representing the tag key as used by botocore specs
        :param value_field: the field name representing the tag value as used by botocore specs
        """
        self.key_field = key_field
        self.value_field = value_field

        self.tags = {}

    def list_tags_for_resource(self, arn: str, root_name: str | None = None):
        root_name = root_name or "Tags"

        result = []
        if arn in self.tags:
            for k, v in self.tags[arn].items():
                result.append({self.key_field: k, self.value_field: v})
        return {root_name: result}

    def tag_resource(self, arn: str, tags: list[dict[str, str]]):
        if not tags:
            return
        if arn not in self.tags:
            self.tags[arn] = {}
        for t in tags:
            self.tags[arn][t[self.key_field]] = t[self.value_field]

    def untag_resource(self, arn: str, tag_names: list[str]):
        tags = self.tags.get(arn, {})
        for name in tag_names:
            tags.pop(name, None)

    def del_resource(self, arn: str):
        if arn in self.tags:
            del self.tags[arn]

    def __delitem__(self, arn: str):
        self.del_resource(arn)


ResourceARN = str
TagKey = str
TagValue = str
TagMap = dict[TagKey, TagValue]


@dataclass
class Tags:
    """
    This dataclass provides utilities for performing resource tagging. Tags for resources are stored on
    the service provider's store within this `Tags` dataclass with ResourceARN mapped against a dictionary
    containing tags in the form TagKey:TagValue to remain agnostic to the service's tag format.

    The `Tags` dataclass supports updating / creating tags, deleting tags, and removing the
    resource from the tag dictionary (_tags). It's important that when a resource is deleted to remove this
    resource ARN from the store using the `delete_all_tags` method::

        store = get_store(account_id, region)
        store.TAGS.delete_all_tags(my_resource_arn)

    Do not use the `Tags` dataclass to determine the existence of a resource. For this, use ``connect_to`` or
    direct Moto Backend introspection. It's important that resources do not exist within _tags unless they
    currently have tags or have had tags in the past and the resource exists. The resource ARN should not exist within
    _tags if the resource has been deleted.

    This distinction is important to maintain parity with the Resource Groups Tagging API (RGTA) which will tap into
    supported service's `Tags` dataclass within it's store.
    """

    _tags: dict[ResourceARN, TagMap] = field(default_factory=dict)

    def update_tags(self, arn: ResourceARN, tags: TagMap) -> None:
        """
        Updates the tags of the specified resource.

        :param arn: The ARN of the resource to tag.
        :param tags: A mapping of tag keys to tag values or an array of tag objects.
        :return: None
        """
        stored_tags = self._tags.setdefault(arn, {})

        for k, v in tags.items():
            stored_tags[k] = v

    def get_tags(self, arn: ResourceARN) -> TagMap:
        """
        Retrieves the tags for a specified resource.

        The tags are returned as a flat map of tag key/value pairs, e.g.::
            {
                "Environment": "Production",
                "Owner": "LocalStack",
            }

        :param arn: The ARN of the resource you want to retrieve tags for.
        :return: A dictionary copy of tag keys to tag values for the resource.
        """
        if arn not in self._tags:
            return {}
        return self._tags[arn].copy()

    def delete_tags(self, arn: ResourceARN, keys: list[TagKey]) -> None:
        """
        Deletes the tag on the resource specified by the provided tag keys.

        :param arn: The ARN of the resource to remove tags for.
        :param keys: An array of tag keys to remove from the resource.
        :return: None
        """
        if tags := self._tags.get(arn):
            for key in keys:
                tags.pop(key, None)

    def delete_all_tags(self, arn: ResourceARN) -> None:
        """
        Removes all the tags for a resource and removes it from the internal tagging store.
        To be used once a resource is deleted or when you wish to remove all a resources tags.

        :param arn: The ARN of the resource to remove from the store.
        :return: None
        """
        self._tags.pop(arn, None)

    def get_resource_tag_map(self) -> dict[ResourceARN, TagMap]:
        """
        Retrieves the entire mapping between Resource ARNs and their tags.

        This should not be used to retrieve tags for a single resource and should instead use the
        `Tags.get_tags(resource_arn)`. It should only be used in scenarios where visibility into the
        entire internal tag store is required such as with the Resource Groups Tagging API (RGTA).

        :return: A mapping between Resource ARN and tags.
        """

        return self._tags.copy()


#
# Tagging operations for various services return tags in one of two formats:
#
# - Tag list: A list of dicts, each dict containing the fields 'Key' and 'Value' and appropriate tag key value pairs.
#   Some services, like S3, use the fields 'key' and 'value'::
#
#         [
#             {
#                 "Key": "Environment",
#                 "Value": "Production",
#             },
#             {
#                 "Key": "Owner",
#                 "Value": "LocalStack",
#             }
#         ]
#
# - Tag map: a direct mapping of tag keys to tag values.::
#
#         {
#             "Environment": "Production",
#             "Owner": "LocalStack",
#         }
#


def tag_list_to_map(
    tag_list: list[dict[str, str]], key_field: str = "Key", value_field: str = "Value"
) -> dict[str, str]:
    """
    Convert a tag list to a tag map::

        >> tag_list_to_map([{"Key": "temperature", "Value": "warm"}])
        {"temperature": "warm"}

    """
    return {tag[key_field]: tag[value_field] for tag in tag_list}


def tag_map_to_list(
    tag_map: dict[str, str], key_field: str = "Key", value_field: str = "Value"
) -> list[dict[str, str]]:
    """
    Convert a tag map to a tag list::

        >> tag_map_to_list({"temperature": "warm"})
        [{"Key": "temperature", "Value": "warm"}]

    """
    return [{key_field: key, value_field: value} for key, value in tag_map.items()]
