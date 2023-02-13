import json

from localstack.services.stepfunctions.asl.component.component import Component


class Result(Component):
    def __init__(self, result_obj: json):
        self.result_obj: json = result_obj
