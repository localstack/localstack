class TaggingService(object):

    def __init__(self):
        self.tags = {}

    def list_tags_for_resource(self, arn):
        result = []
        if arn in self.tags:
            for k, v in self.tags[arn].items():
                result.append({'Key': k, 'Value': v})
        return {'Tags': result}

    def tag_resource(self, arn, tags):
        if arn not in self.tags:
            self.tags[arn] = {}
        for t in tags:
            self.tags[arn][t['Key']] = t['Value']

    def untag_resource(self, arn, tag_names):
        tags = self.tags.get(arn, {})
        for name in tag_names:
            tags.pop(name, None)
