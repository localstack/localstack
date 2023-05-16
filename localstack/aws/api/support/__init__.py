import sys
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AfterTime = str
AttachmentId = str
AttachmentSetId = str
AvailabilityErrorMessage = str
BeforeTime = str
Boolean = bool
CaseId = str
CaseStatus = str
CategoryCode = str
CategoryName = str
CcEmailAddress = str
Code = str
CommunicationBody = str
Display = str
DisplayId = str
Double = float
EndTime = str
ErrorMessage = str
ExpiryTime = str
FileName = str
IncludeCommunications = bool
IncludeResolvedCases = bool
IssueType = str
Language = str
MaxResults = int
NextToken = str
Result = bool
ServiceCode = str
ServiceName = str
SeverityCode = str
SeverityLevelCode = str
SeverityLevelName = str
StartTime = str
Status = str
String = str
Subject = str
SubmittedBy = str
TimeCreated = str
Type = str
ValidatedCategoryCode = str
ValidatedCommunicationBody = str
ValidatedDateTime = str
ValidatedIssueTypeString = str
ValidatedLanguageAvailability = str
ValidatedServiceCode = str


class AttachmentIdNotFound(ServiceException):
    code: str = "AttachmentIdNotFound"
    sender_fault: bool = False
    status_code: int = 400


class AttachmentLimitExceeded(ServiceException):
    code: str = "AttachmentLimitExceeded"
    sender_fault: bool = False
    status_code: int = 400


class AttachmentSetExpired(ServiceException):
    code: str = "AttachmentSetExpired"
    sender_fault: bool = False
    status_code: int = 400


class AttachmentSetIdNotFound(ServiceException):
    code: str = "AttachmentSetIdNotFound"
    sender_fault: bool = False
    status_code: int = 400


class AttachmentSetSizeLimitExceeded(ServiceException):
    code: str = "AttachmentSetSizeLimitExceeded"
    sender_fault: bool = False
    status_code: int = 400


class CaseCreationLimitExceeded(ServiceException):
    code: str = "CaseCreationLimitExceeded"
    sender_fault: bool = False
    status_code: int = 400


class CaseIdNotFound(ServiceException):
    code: str = "CaseIdNotFound"
    sender_fault: bool = False
    status_code: int = 400


class DescribeAttachmentLimitExceeded(ServiceException):
    code: str = "DescribeAttachmentLimitExceeded"
    sender_fault: bool = False
    status_code: int = 400


class InternalServerError(ServiceException):
    code: str = "InternalServerError"
    sender_fault: bool = False
    status_code: int = 400


class ThrottlingException(ServiceException):
    code: str = "ThrottlingException"
    sender_fault: bool = False
    status_code: int = 400


Data = bytes


class Attachment(TypedDict, total=False):
    fileName: Optional[FileName]
    data: Optional[Data]


Attachments = List[Attachment]


class AddAttachmentsToSetRequest(ServiceRequest):
    attachmentSetId: Optional[AttachmentSetId]
    attachments: Attachments


class AddAttachmentsToSetResponse(TypedDict, total=False):
    attachmentSetId: Optional[AttachmentSetId]
    expiryTime: Optional[ExpiryTime]


CcEmailAddressList = List[CcEmailAddress]


class AddCommunicationToCaseRequest(ServiceRequest):
    caseId: Optional[CaseId]
    communicationBody: CommunicationBody
    ccEmailAddresses: Optional[CcEmailAddressList]
    attachmentSetId: Optional[AttachmentSetId]


class AddCommunicationToCaseResponse(TypedDict, total=False):
    result: Optional[Result]


class AttachmentDetails(TypedDict, total=False):
    attachmentId: Optional[AttachmentId]
    fileName: Optional[FileName]


AttachmentSet = List[AttachmentDetails]


class Communication(TypedDict, total=False):
    caseId: Optional[CaseId]
    body: Optional[ValidatedCommunicationBody]
    submittedBy: Optional[SubmittedBy]
    timeCreated: Optional[TimeCreated]
    attachmentSet: Optional[AttachmentSet]


CommunicationList = List[Communication]


class RecentCaseCommunications(TypedDict, total=False):
    communications: Optional[CommunicationList]
    nextToken: Optional[NextToken]


class CaseDetails(TypedDict, total=False):
    caseId: Optional[CaseId]
    displayId: Optional[DisplayId]
    subject: Optional[Subject]
    status: Optional[Status]
    serviceCode: Optional[ServiceCode]
    categoryCode: Optional[CategoryCode]
    severityCode: Optional[SeverityCode]
    submittedBy: Optional[SubmittedBy]
    timeCreated: Optional[TimeCreated]
    recentCommunications: Optional[RecentCaseCommunications]
    ccEmailAddresses: Optional[CcEmailAddressList]
    language: Optional[Language]


CaseIdList = List[CaseId]
CaseList = List[CaseDetails]


class Category(TypedDict, total=False):
    code: Optional[CategoryCode]
    name: Optional[CategoryName]


CategoryList = List[Category]


class DateInterval(TypedDict, total=False):
    startDateTime: Optional[ValidatedDateTime]
    endDateTime: Optional[ValidatedDateTime]


DatesWithoutSupportList = List[DateInterval]


class SupportedHour(TypedDict, total=False):
    startTime: Optional[StartTime]
    endTime: Optional[EndTime]


SupportedHoursList = List[SupportedHour]
CommunicationTypeOptions = TypedDict(
    "CommunicationTypeOptions",
    {
        "type": Optional[Type],
        "supportedHours": Optional[SupportedHoursList],
        "datesWithoutSupport": Optional[DatesWithoutSupportList],
    },
    total=False,
)
CommunicationTypeOptionsList = List[CommunicationTypeOptions]


class CreateCaseRequest(ServiceRequest):
    subject: Subject
    serviceCode: Optional[ServiceCode]
    severityCode: Optional[SeverityCode]
    categoryCode: Optional[CategoryCode]
    communicationBody: CommunicationBody
    ccEmailAddresses: Optional[CcEmailAddressList]
    language: Optional[Language]
    issueType: Optional[IssueType]
    attachmentSetId: Optional[AttachmentSetId]


class CreateCaseResponse(TypedDict, total=False):
    caseId: Optional[CaseId]


class DescribeAttachmentRequest(ServiceRequest):
    attachmentId: AttachmentId


class DescribeAttachmentResponse(TypedDict, total=False):
    attachment: Optional[Attachment]


class DescribeCasesRequest(ServiceRequest):
    caseIdList: Optional[CaseIdList]
    displayId: Optional[DisplayId]
    afterTime: Optional[AfterTime]
    beforeTime: Optional[BeforeTime]
    includeResolvedCases: Optional[IncludeResolvedCases]
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]
    language: Optional[Language]
    includeCommunications: Optional[IncludeCommunications]


class DescribeCasesResponse(TypedDict, total=False):
    cases: Optional[CaseList]
    nextToken: Optional[NextToken]


class DescribeCommunicationsRequest(ServiceRequest):
    caseId: CaseId
    beforeTime: Optional[BeforeTime]
    afterTime: Optional[AfterTime]
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class DescribeCommunicationsResponse(TypedDict, total=False):
    communications: Optional[CommunicationList]
    nextToken: Optional[NextToken]


class DescribeCreateCaseOptionsRequest(ServiceRequest):
    issueType: IssueType
    serviceCode: ServiceCode
    language: Language
    categoryCode: CategoryCode


class DescribeCreateCaseOptionsResponse(TypedDict, total=False):
    languageAvailability: Optional[ValidatedLanguageAvailability]
    communicationTypes: Optional[CommunicationTypeOptionsList]


ServiceCodeList = List[ServiceCode]


class DescribeServicesRequest(ServiceRequest):
    serviceCodeList: Optional[ServiceCodeList]
    language: Optional[Language]


class Service(TypedDict, total=False):
    code: Optional[ServiceCode]
    name: Optional[ServiceName]
    categories: Optional[CategoryList]


ServiceList = List[Service]


class DescribeServicesResponse(TypedDict, total=False):
    services: Optional[ServiceList]


class DescribeSeverityLevelsRequest(ServiceRequest):
    language: Optional[Language]


class SeverityLevel(TypedDict, total=False):
    code: Optional[SeverityLevelCode]
    name: Optional[SeverityLevelName]


SeverityLevelsList = List[SeverityLevel]


class DescribeSeverityLevelsResponse(TypedDict, total=False):
    severityLevels: Optional[SeverityLevelsList]


class DescribeSupportedLanguagesRequest(ServiceRequest):
    issueType: ValidatedIssueTypeString
    serviceCode: ValidatedServiceCode
    categoryCode: ValidatedCategoryCode


class SupportedLanguage(TypedDict, total=False):
    code: Optional[Code]
    language: Optional[Language]
    display: Optional[Display]


SupportedLanguagesList = List[SupportedLanguage]


class DescribeSupportedLanguagesResponse(TypedDict, total=False):
    supportedLanguages: Optional[SupportedLanguagesList]


StringList = List[String]


class DescribeTrustedAdvisorCheckRefreshStatusesRequest(ServiceRequest):
    checkIds: StringList


Long = int


class TrustedAdvisorCheckRefreshStatus(TypedDict, total=False):
    checkId: String
    status: String
    millisUntilNextRefreshable: Long


TrustedAdvisorCheckRefreshStatusList = List[TrustedAdvisorCheckRefreshStatus]


class DescribeTrustedAdvisorCheckRefreshStatusesResponse(TypedDict, total=False):
    statuses: TrustedAdvisorCheckRefreshStatusList


class DescribeTrustedAdvisorCheckResultRequest(ServiceRequest):
    checkId: String
    language: Optional[String]


class TrustedAdvisorResourceDetail(TypedDict, total=False):
    status: String
    region: Optional[String]
    resourceId: String
    isSuppressed: Optional[Boolean]
    metadata: StringList


TrustedAdvisorResourceDetailList = List[TrustedAdvisorResourceDetail]


class TrustedAdvisorCostOptimizingSummary(TypedDict, total=False):
    estimatedMonthlySavings: Double
    estimatedPercentMonthlySavings: Double


class TrustedAdvisorCategorySpecificSummary(TypedDict, total=False):
    costOptimizing: Optional[TrustedAdvisorCostOptimizingSummary]


class TrustedAdvisorResourcesSummary(TypedDict, total=False):
    resourcesProcessed: Long
    resourcesFlagged: Long
    resourcesIgnored: Long
    resourcesSuppressed: Long


class TrustedAdvisorCheckResult(TypedDict, total=False):
    checkId: String
    timestamp: String
    status: String
    resourcesSummary: TrustedAdvisorResourcesSummary
    categorySpecificSummary: TrustedAdvisorCategorySpecificSummary
    flaggedResources: TrustedAdvisorResourceDetailList


class DescribeTrustedAdvisorCheckResultResponse(TypedDict, total=False):
    result: Optional[TrustedAdvisorCheckResult]


class DescribeTrustedAdvisorCheckSummariesRequest(ServiceRequest):
    checkIds: StringList


class TrustedAdvisorCheckSummary(TypedDict, total=False):
    checkId: String
    timestamp: String
    status: String
    hasFlaggedResources: Optional[Boolean]
    resourcesSummary: TrustedAdvisorResourcesSummary
    categorySpecificSummary: TrustedAdvisorCategorySpecificSummary


TrustedAdvisorCheckSummaryList = List[TrustedAdvisorCheckSummary]


class DescribeTrustedAdvisorCheckSummariesResponse(TypedDict, total=False):
    summaries: TrustedAdvisorCheckSummaryList


class DescribeTrustedAdvisorChecksRequest(ServiceRequest):
    language: String


class TrustedAdvisorCheckDescription(TypedDict, total=False):
    id: String
    name: String
    description: String
    category: String
    metadata: StringList


TrustedAdvisorCheckList = List[TrustedAdvisorCheckDescription]


class DescribeTrustedAdvisorChecksResponse(TypedDict, total=False):
    checks: TrustedAdvisorCheckList


class RefreshTrustedAdvisorCheckRequest(ServiceRequest):
    checkId: String


class RefreshTrustedAdvisorCheckResponse(TypedDict, total=False):
    status: TrustedAdvisorCheckRefreshStatus


class ResolveCaseRequest(ServiceRequest):
    caseId: Optional[CaseId]


class ResolveCaseResponse(TypedDict, total=False):
    initialCaseStatus: Optional[CaseStatus]
    finalCaseStatus: Optional[CaseStatus]


class SupportApi:

    service = "support"
    version = "2013-04-15"

    @handler("AddAttachmentsToSet")
    def add_attachments_to_set(
        self,
        context: RequestContext,
        attachments: Attachments,
        attachment_set_id: AttachmentSetId = None,
    ) -> AddAttachmentsToSetResponse:
        raise NotImplementedError

    @handler("AddCommunicationToCase")
    def add_communication_to_case(
        self,
        context: RequestContext,
        communication_body: CommunicationBody,
        case_id: CaseId = None,
        cc_email_addresses: CcEmailAddressList = None,
        attachment_set_id: AttachmentSetId = None,
    ) -> AddCommunicationToCaseResponse:
        raise NotImplementedError

    @handler("CreateCase")
    def create_case(
        self,
        context: RequestContext,
        subject: Subject,
        communication_body: CommunicationBody,
        service_code: ServiceCode = None,
        severity_code: SeverityCode = None,
        category_code: CategoryCode = None,
        cc_email_addresses: CcEmailAddressList = None,
        language: Language = None,
        issue_type: IssueType = None,
        attachment_set_id: AttachmentSetId = None,
    ) -> CreateCaseResponse:
        raise NotImplementedError

    @handler("DescribeAttachment")
    def describe_attachment(
        self, context: RequestContext, attachment_id: AttachmentId
    ) -> DescribeAttachmentResponse:
        raise NotImplementedError

    @handler("DescribeCases")
    def describe_cases(
        self,
        context: RequestContext,
        case_id_list: CaseIdList = None,
        display_id: DisplayId = None,
        after_time: AfterTime = None,
        before_time: BeforeTime = None,
        include_resolved_cases: IncludeResolvedCases = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        language: Language = None,
        include_communications: IncludeCommunications = None,
    ) -> DescribeCasesResponse:
        raise NotImplementedError

    @handler("DescribeCommunications")
    def describe_communications(
        self,
        context: RequestContext,
        case_id: CaseId,
        before_time: BeforeTime = None,
        after_time: AfterTime = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> DescribeCommunicationsResponse:
        raise NotImplementedError

    @handler("DescribeCreateCaseOptions")
    def describe_create_case_options(
        self,
        context: RequestContext,
        issue_type: IssueType,
        service_code: ServiceCode,
        language: Language,
        category_code: CategoryCode,
    ) -> DescribeCreateCaseOptionsResponse:
        raise NotImplementedError

    @handler("DescribeServices")
    def describe_services(
        self,
        context: RequestContext,
        service_code_list: ServiceCodeList = None,
        language: Language = None,
    ) -> DescribeServicesResponse:
        raise NotImplementedError

    @handler("DescribeSeverityLevels")
    def describe_severity_levels(
        self, context: RequestContext, language: Language = None
    ) -> DescribeSeverityLevelsResponse:
        raise NotImplementedError

    @handler("DescribeSupportedLanguages")
    def describe_supported_languages(
        self,
        context: RequestContext,
        issue_type: ValidatedIssueTypeString,
        service_code: ValidatedServiceCode,
        category_code: ValidatedCategoryCode,
    ) -> DescribeSupportedLanguagesResponse:
        raise NotImplementedError

    @handler("DescribeTrustedAdvisorCheckRefreshStatuses")
    def describe_trusted_advisor_check_refresh_statuses(
        self, context: RequestContext, check_ids: StringList
    ) -> DescribeTrustedAdvisorCheckRefreshStatusesResponse:
        raise NotImplementedError

    @handler("DescribeTrustedAdvisorCheckResult")
    def describe_trusted_advisor_check_result(
        self, context: RequestContext, check_id: String, language: String = None
    ) -> DescribeTrustedAdvisorCheckResultResponse:
        raise NotImplementedError

    @handler("DescribeTrustedAdvisorCheckSummaries")
    def describe_trusted_advisor_check_summaries(
        self, context: RequestContext, check_ids: StringList
    ) -> DescribeTrustedAdvisorCheckSummariesResponse:
        raise NotImplementedError

    @handler("DescribeTrustedAdvisorChecks")
    def describe_trusted_advisor_checks(
        self, context: RequestContext, language: String
    ) -> DescribeTrustedAdvisorChecksResponse:
        raise NotImplementedError

    @handler("RefreshTrustedAdvisorCheck")
    def refresh_trusted_advisor_check(
        self, context: RequestContext, check_id: String
    ) -> RefreshTrustedAdvisorCheckResponse:
        raise NotImplementedError

    @handler("ResolveCase")
    def resolve_case(self, context: RequestContext, case_id: CaseId = None) -> ResolveCaseResponse:
        raise NotImplementedError
