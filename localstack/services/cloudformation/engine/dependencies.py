from dataclasses import dataclass
from typing import Any

from jsonpath_ng import parse

LogicalResourceId = str

AttributePath = str
"JSONPath for the attribute"

Resource = dict
"Collection of resource attributes"


@dataclass(frozen=True)
class Dependency:
    """
    Maps a requesting resource attribute (`requesting_resource` + `requesting_path`) to a target resource.

    For example:

    ```yaml
    Resources:
      Queue:
        Type: AWS::SQS::Queue
        Properties:
          QueueName: my-queue

      Parameter:
        Type: AWS::SSM::Parameter
        Properties:
          Type: String
          Value:
            Fn::GetAtt:
              - Queue
              - QueueName
    ```

    When the queue name resolves to a value, then mapping the Resources.Parameter.Properties.Value -> Queue.QueueName

    ```python
    dep = Dependency(
        target="Queue",
        target_path="Properties.QueueName",
        requesting_resource="Parameter",
        requesting_path="Properties.Value",
    )
    ```

    will resolve the parameter value to the `QueueName` of the queue.

    """

    target: LogicalResourceId
    requesting_resource: LogicalResourceId

    target_path: AttributePath
    requesting_path: AttributePath

    # TODO: return new resources?
    def resolve(self, resources: dict[str, Resource]):
        target = resources[self.target]
        requesting_resource = resources[self.requesting_resource]

        value = self.resolve_value(target)
        self.set_value(requesting_resource, value)

    # TODO: Any -> proper types
    def resolve_value(self, target: Resource) -> Any:
        path_expr = parse(self.target_path)
        # TODO: robustness
        return path_expr.find(target)[0].value

    def set_value(self, resource: Resource, value: Any):
        path_expr = parse(self.requesting_path)
        path_expr.update(resource, value)
