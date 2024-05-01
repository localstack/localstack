from localstack.services.cloudformation.enginev2 import (
    Dependency,
    Engine,
    RawTemplate,
    hydrate_template,
)


def test_hydration():
    template: RawTemplate = {
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
    assert set(hydrated_template.dependencies) == {
        # ref
        Dependency(source_logical_id="Parameter", target_logical_id="Topic"),
        # getatt
        Dependency(
            source_logical_id="Parameter2", target_logical_id="Topic", field_location="$.TopicName"
        ),
    }
    engine = Engine(hydrated_template)
    assert list(engine._deployable_resource_ids()) == ["Topic"]
