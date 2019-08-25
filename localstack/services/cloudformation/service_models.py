class StepFunctionsActivity(object):

    def __init__(self, **params):
        self.params = params

    @classmethod
    def create_from_cloudformation_json(cls, resource_name, cloudformation_json, region_name):
        props = cloudformation_json['Properties']
        return StepFunctionsActivity(**props)
