from localstack.aws.api.resourcegroupstaggingapi import ResourceARN, TagList, TagMap
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


class ResourceGroupsTaggingApiStore(BaseStore):
    # Maps ARNs to a dictionary of TagKey:TagValue
    tags: dict[ResourceARN, TagMap] = LocalAttribute(default=dict)

    def update_tags(self, arn: ResourceARN, tags: TagMap | TagList) -> None:
        """
        Updates the tags of the specified resource.

        :param arn: The ARN of the resource to tag.
        :param tags: A mapping of tag keys to tag values or an array of tag objects.
        :return: None
        """
        formatted_tags = (
            {tag["Key"]: tag["Value"] for tag in tags} if isinstance(tags, TagList) else tags
        )

        if arn not in formatted_tags:
            self.tags[arn] = {}

        for k, v in formatted_tags.items():
            self.tags[arn][k] = v

    def get_tags(self, arn: ResourceARN) -> TagMap:
        """
        Retrieves the tags for a specified resource.

        :param arn: The ARN of the resource you want to retrieve tags for.
        :return: A mapping of tag keys to tag values for the resource.
        """
        return self.tags[arn] if arn in self.tags else {}

    def delete_tags(self, arn: ResourceARN, keys: list[str]) -> None:
        """
        Deletes the tag on the resource specified by the provided tag keys.

        :param arn: The ARN of the resource to remove tags for.
        :param keys: An array of tag keys to remove from the resource.
        :return: None
        """
        if arn in self.tags:
            for key in keys:
                self.tags[arn].pop(key, None)

    def delete_all_tags(self, arn: ResourceARN) -> None:
        """
        Removes all the tags for a resource and removes it from the tagging store.
        To be used once a resource is deleted or when you wish to remove all a resources tags.

        :param arn: The ARN of the resource to remove from the store.
        :return: None
        """
        self.tags.pop(arn, None)


resourcegroupstaggingapi_stores = AccountRegionBundle(
    "resourcegroupstaggingapi", ResourceGroupsTaggingApiStore
)


def get_tagging_store(account_id: str, region: str) -> ResourceGroupsTaggingApiStore:
    return resourcegroupstaggingapi_stores[account_id][region]
