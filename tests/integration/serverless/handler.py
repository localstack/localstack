import json


def processKinesis(event, *args):
    print("!processKinesis", json.dumps(event))
