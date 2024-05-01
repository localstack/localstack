from __future__ import annotations

from dataclasses import dataclass, field
from typing import NotRequired, TypeAlias, TypedDict

jsonpath: TypeAlias = str


class RawTemplate(TypedDict):
    Resources: dict

    AWSTemplateVersion: NotRequired[dict]
    Parameters: NotRequired[dict]
    Conditions: NotRequired[dict]
    Outputs: NotRequired[dict]


@dataclass(frozen=True)
class Dependency:
    source_logical_id: str
    target_logical_id: str
    field_location: jsonpath | None = None


def hydrate_template(raw_template: RawTemplate) -> HydratedTemplate:
    resources = raw_template["Resources"]
    dependencies = []
    for source_logical_resource_id, resource in resources.items():
        properties = resource.get("Properties", {}) or {}
        for key, prop in properties.items():
            # !Ref
            if isinstance(prop, dict) and "Ref" in prop:
                ref_target = prop["Ref"]
                assert isinstance(ref_target, str)
                dependency = Dependency(
                    source_logical_id=source_logical_resource_id,
                    target_logical_id=ref_target,
                )
                dependencies.append(dependency)
                continue

            # Fn::GetAtt
            if isinstance(prop, dict) and "Fn::GetAtt" in prop:
                target_def = prop["Fn::GetAtt"]
                assert isinstance(target_def, list)
                assert len(target_def) == 2
                target_logical_id = target_def[0]
                jsonpath = f"$.{target_def[1]}"
                dependency = Dependency(
                    source_logical_id=source_logical_resource_id,
                    target_logical_id=target_logical_id,
                    field_location=jsonpath,
                )
                dependencies.append(dependency)
                continue

    return HydratedTemplate(dependencies=dependencies)


@dataclass
class HydratedTemplate:
    dependencies: list[Dependency] = field(default_factory=list)


class Engine:
    def __init__(self, hydrated_template: HydratedTemplate):
        self.template = hydrated_template

    def deploy(self):
        pass


if __name__ == "__main__":
    template = {
        "Resources": {
            "Topic": {
                "Type": "AWS::SNS::Topic",
            },
            "Parameter": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name": "myparam",
                    "Value": {
                        "Ref": "Topic",
                    },
                },
            },
            "Parameter2": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name": "myparam",
                    "Value": {
                        "Fn::GetAtt": ["Topic", "TopicName"],
                    },
                },
            },
        },
    }

    hydrated_template = hydrate_template(template)
    assert hydrated_template.dependencies == [
        # ref
        Dependency(source_logical_id="Parameter", target_logical_id="Topic"),
        # getatt
        Dependency(
            source_logical_id="Parameter2", target_logical_id="Topic", field_location="$.TopicName"
        ),
    ]
