from enum import StrEnum
from typing import TypedDict

from localstack.aws.api.ses import Address, Destination, Subject, TemplateData, TemplateName


class SentEmailBody(TypedDict):
    html_part: str | None
    text_part: str


class SentEmail(TypedDict, total=False):
    Id: str
    Region: str
    Timestamp: str
    Destination: Destination
    RawData: str
    Source: Address
    Subject: Subject
    Template: TemplateName
    TemplateData: TemplateData
    Body: SentEmailBody


class EmailType(StrEnum):
    TEMPLATED = "templated"
    RAW = "raw"
    EMAIL = "email"
