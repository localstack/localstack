from typing import Dict, List, Optional


class TaggingService:
    def __init__(self):
        self.tags = {}

    def list_tags_for_resource(self, arn: str, root_name: Optional[str] = None):
        root_name = root_name or "Tags"
        result = []
        if arn in self.tags:
            for k, v in self.tags[arn].items():
                result.append({"Key": k, "Value": v})
        return {root_name: result}

    def tag_resource(self, arn: str, tags: List[Dict[str, str]]):
        if not tags:
            return
        if arn not in self.tags:
            self.tags[arn] = {}
        for t in tags:
            self.tags[arn][t["Key"]] = t["Value"]

    def untag_resource(self, arn: str, tag_names: List[str]):
        tags = self.tags.get(arn, {})
        for name in tag_names:
            tags.pop(name, None)
