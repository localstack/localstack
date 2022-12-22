from typing import TypedDict

from localstack.aws.api.ses import Address, Destination, Subject, TemplateData, TemplateName


class SentEmailBody(TypedDict):
    html_part: str
    text_part: str


class SentEmail(TypedDict):
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
