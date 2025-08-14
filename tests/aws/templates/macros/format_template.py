"""
This macro takes the incoming fragment (i.e. the sibling nodes of the `Fn::Transform` call,
and for every string it calls .format on the string with the arguments taken from the parameters.

For example:

Transform: ThisMacroName
Properties:
  Value:
    Type: String
Resources:
  MyResource:
    Type: AWS::SSM::Parameter
    Properties:
      Type: String
      Value: "my value is {Value}"

deployed with ParameterKey=Value,ParameterValue=test will result in the final template:

Properties:
  Value:
    Type: String
Resources:
  MyResource:
    Type: AWS::SSM::Parameter
    Properties:
      Type: String
      Value: "my value is test"
"""


def handler(event, context):
    parameters = event["templateParameterValues"]
    fragment = walk(event["fragment"], parameters)

    resp = {"requestId": event["requestId"], "status": "success", "fragment": fragment}

    return resp


def walk(node, context):
    if isinstance(node, dict):
        return {k: walk(v, context) for k, v in node.items()}
    elif isinstance(node, list):
        return [walk(elem, context) for elem in node]
    elif isinstance(node, str):
        return node.format(**context)
    else:
        return node
