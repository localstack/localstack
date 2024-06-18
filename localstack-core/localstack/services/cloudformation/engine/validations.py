"""
Provide validations for use within the CFn engine
"""

from typing import Protocol

from localstack.aws.api import CommonServiceException


class ValidationError(CommonServiceException):
    """General validation error type (defined in the AWS docs, but not part of the botocore spec)"""

    def __init__(self, message=None):
        super().__init__("ValidationError", message=message, sender_fault=True)


class TemplateValidationStep(Protocol):
    """
    Base class for static analysis of the template
    """

    def __call__(self, template: dict):
        """
        Execute a specific validation on the template
        """


def outputs_have_values(template: dict):
    outputs: dict[str, dict] = template.get("Outputs", {})

    for output_name, output_defn in outputs.items():
        if "Value" not in output_defn:
            raise ValidationError(
                "Template format error: Every Outputs member must contain a Value object"
            )

        if output_defn["Value"] is None:
            key = f"/Outputs/{output_name}/Value"
            raise ValidationError(f"[{key}] 'null' values are not allowed in templates")


# TODO: this would need to be split into different validations pre- and post- transform
def resources_top_level_keys(template: dict):
    """
    Validate that each resource
    - there is a resources key
    - includes the `Properties` key
    - does not include any other keys that should not be there
    """
    resources = template.get("Resources")
    if resources is None:
        raise ValidationError(
            "Template format error: At least one Resources member must be defined."
        )

    allowed_keys = {
        "Type",
        "Properties",
        "DependsOn",
        "CreationPolicy",
        "DeletionPolicy",
        "Metadata",
        "UpdatePolicy",
        "UpdateReplacePolicy",
        "Condition",
    }
    for resource_id, resource in resources.items():
        if "Type" not in resource:
            raise ValidationError(
                f"Template format error: [/Resources/{resource_id}] Every Resources object must contain a Type member."
            )

        # check for invalid keys
        for key in resource:
            if key not in allowed_keys:
                raise ValidationError(f"Invalid template resource property '{key}'")


DEFAULT_TEMPLATE_VALIDATIONS: list[TemplateValidationStep] = [
    # FIXME: disabled for now due to the template validation not fitting well with the template that we use here.
    #  We don't have access to a "raw" processed template here and it's questionable if we should have it at all,
    #  since later transformations can again introduce issues.
    #   => Reevaluate this when reworking how we mutate the template dict in the provider
    # outputs_have_values,
    # resources_top_level_keys,
]
