from typing import Dict, List, Optional


class TaggingService:
    def __init__(self, key_field: str = None, value_field: str = None):
        """
        :param key_field: the field name representing the tag key as used by botocore specs
        :param value_field: the field name representing the tag value as used by botocore specs
        """
        self.key_field = key_field or "Key"
        self.value_field = value_field or "Value"

        self.tags = {}

    def list_tags_for_resource(self, arn: str, root_name: Optional[str] = None):
        root_name = root_name or "Tags"

        result = []
        if arn in self.tags:
            for k, v in self.tags[arn].items():
                result.append({self.key_field: k, self.value_field: v})
        return {root_name: result}

    def tag_resource(self, arn: str, tags: List[Dict[str, str]]):
        if not tags:
            return
        if arn not in self.tags:
            self.tags[arn] = {}
        for t in tags:
            self.tags[arn][t[self.key_field]] = t[self.value_field]

    def untag_resource(self, arn: str, tag_names: List[str]):
        tags = self.tags.get(arn, {})
        for name in tag_names:
            tags.pop(name, None)

    def del_resource(self, arn: str):
        if arn in self.tags:
            del self.tags[arn]

    def __delitem__(self, arn: str):
        self.del_resource(arn)
