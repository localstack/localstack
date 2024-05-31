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


DEFAULT_TEMPLATE_VALIDATIONS: list[TemplateValidationStep] = [
    outputs_have_values,
]
