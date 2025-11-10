from typing import TypedDict

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
    fileName: FileName | None
    data: Data | None


Attachments = list[Attachment]


class AddAttachmentsToSetRequest(ServiceRequest):
    attachmentSetId: AttachmentSetId | None
    attachments: Attachments


class AddAttachmentsToSetResponse(TypedDict, total=False):
    attachmentSetId: AttachmentSetId | None
    expiryTime: ExpiryTime | None


CcEmailAddressList = list[CcEmailAddress]


class AddCommunicationToCaseRequest(ServiceRequest):
    caseId: CaseId | None
    communicationBody: CommunicationBody
    ccEmailAddresses: CcEmailAddressList | None
    attachmentSetId: AttachmentSetId | None


class AddCommunicationToCaseResponse(TypedDict, total=False):
    result: Result | None


class AttachmentDetails(TypedDict, total=False):
    attachmentId: AttachmentId | None
    fileName: FileName | None


AttachmentSet = list[AttachmentDetails]


class Communication(TypedDict, total=False):
    caseId: CaseId | None
    body: ValidatedCommunicationBody | None
    submittedBy: SubmittedBy | None
    timeCreated: TimeCreated | None
    attachmentSet: AttachmentSet | None


CommunicationList = list[Communication]


class RecentCaseCommunications(TypedDict, total=False):
    communications: CommunicationList | None
    nextToken: NextToken | None


class CaseDetails(TypedDict, total=False):
    caseId: CaseId | None
    displayId: DisplayId | None
    subject: Subject | None
    status: Status | None
    serviceCode: ServiceCode | None
    categoryCode: CategoryCode | None
    severityCode: SeverityCode | None
    submittedBy: SubmittedBy | None
    timeCreated: TimeCreated | None
    recentCommunications: RecentCaseCommunications | None
    ccEmailAddresses: CcEmailAddressList | None
    language: Language | None


CaseIdList = list[CaseId]
CaseList = list[CaseDetails]


class Category(TypedDict, total=False):
    code: CategoryCode | None
    name: CategoryName | None


CategoryList = list[Category]


class DateInterval(TypedDict, total=False):
    startDateTime: ValidatedDateTime | None
    endDateTime: ValidatedDateTime | None


DatesWithoutSupportList = list[DateInterval]


class SupportedHour(TypedDict, total=False):
    startTime: StartTime | None
    endTime: EndTime | None


SupportedHoursList = list[SupportedHour]


class CommunicationTypeOptions(TypedDict, total=False):
    type: Type | None
    supportedHours: SupportedHoursList | None
    datesWithoutSupport: DatesWithoutSupportList | None


CommunicationTypeOptionsList = list[CommunicationTypeOptions]


class CreateCaseRequest(ServiceRequest):
    subject: Subject
    serviceCode: ServiceCode | None
    severityCode: SeverityCode | None
    categoryCode: CategoryCode | None
    communicationBody: CommunicationBody
    ccEmailAddresses: CcEmailAddressList | None
    language: Language | None
    issueType: IssueType | None
    attachmentSetId: AttachmentSetId | None


class CreateCaseResponse(TypedDict, total=False):
    caseId: CaseId | None


class DescribeAttachmentRequest(ServiceRequest):
    attachmentId: AttachmentId


class DescribeAttachmentResponse(TypedDict, total=False):
    attachment: Attachment | None


class DescribeCasesRequest(ServiceRequest):
    caseIdList: CaseIdList | None
    displayId: DisplayId | None
    afterTime: AfterTime | None
    beforeTime: BeforeTime | None
    includeResolvedCases: IncludeResolvedCases | None
    nextToken: NextToken | None
    maxResults: MaxResults | None
    language: Language | None
    includeCommunications: IncludeCommunications | None


class DescribeCasesResponse(TypedDict, total=False):
    cases: CaseList | None
    nextToken: NextToken | None


class DescribeCommunicationsRequest(ServiceRequest):
    caseId: CaseId
    beforeTime: BeforeTime | None
    afterTime: AfterTime | None
    nextToken: NextToken | None
    maxResults: MaxResults | None


class DescribeCommunicationsResponse(TypedDict, total=False):
    communications: CommunicationList | None
    nextToken: NextToken | None


class DescribeCreateCaseOptionsRequest(ServiceRequest):
    issueType: IssueType
    serviceCode: ServiceCode
    language: Language
    categoryCode: CategoryCode


class DescribeCreateCaseOptionsResponse(TypedDict, total=False):
    languageAvailability: ValidatedLanguageAvailability | None
    communicationTypes: CommunicationTypeOptionsList | None


ServiceCodeList = list[ServiceCode]


class DescribeServicesRequest(ServiceRequest):
    serviceCodeList: ServiceCodeList | None
    language: Language | None


class Service(TypedDict, total=False):
    code: ServiceCode | None
    name: ServiceName | None
    categories: CategoryList | None


ServiceList = list[Service]


class DescribeServicesResponse(TypedDict, total=False):
    services: ServiceList | None


class DescribeSeverityLevelsRequest(ServiceRequest):
    language: Language | None


class SeverityLevel(TypedDict, total=False):
    code: SeverityLevelCode | None
    name: SeverityLevelName | None


SeverityLevelsList = list[SeverityLevel]


class DescribeSeverityLevelsResponse(TypedDict, total=False):
    severityLevels: SeverityLevelsList | None


class DescribeSupportedLanguagesRequest(ServiceRequest):
    issueType: ValidatedIssueTypeString
    serviceCode: ValidatedServiceCode
    categoryCode: ValidatedCategoryCode


class SupportedLanguage(TypedDict, total=False):
    code: Code | None
    language: Language | None
    display: Display | None


SupportedLanguagesList = list[SupportedLanguage]


class DescribeSupportedLanguagesResponse(TypedDict, total=False):
    supportedLanguages: SupportedLanguagesList | None


StringList = list[String]


class DescribeTrustedAdvisorCheckRefreshStatusesRequest(ServiceRequest):
    checkIds: StringList


Long = int


class TrustedAdvisorCheckRefreshStatus(TypedDict, total=False):
    checkId: String
    status: String
    millisUntilNextRefreshable: Long


TrustedAdvisorCheckRefreshStatusList = list[TrustedAdvisorCheckRefreshStatus]


class DescribeTrustedAdvisorCheckRefreshStatusesResponse(TypedDict, total=False):
    statuses: TrustedAdvisorCheckRefreshStatusList


class DescribeTrustedAdvisorCheckResultRequest(ServiceRequest):
    checkId: String
    language: String | None


class TrustedAdvisorResourceDetail(TypedDict, total=False):
    status: String
    region: String | None
    resourceId: String
    isSuppressed: Boolean | None
    metadata: StringList


TrustedAdvisorResourceDetailList = list[TrustedAdvisorResourceDetail]


class TrustedAdvisorCostOptimizingSummary(TypedDict, total=False):
    estimatedMonthlySavings: Double
    estimatedPercentMonthlySavings: Double


class TrustedAdvisorCategorySpecificSummary(TypedDict, total=False):
    costOptimizing: TrustedAdvisorCostOptimizingSummary | None


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
    result: TrustedAdvisorCheckResult | None


class DescribeTrustedAdvisorCheckSummariesRequest(ServiceRequest):
    checkIds: StringList


class TrustedAdvisorCheckSummary(TypedDict, total=False):
    checkId: String
    timestamp: String
    status: String
    hasFlaggedResources: Boolean | None
    resourcesSummary: TrustedAdvisorResourcesSummary
    categorySpecificSummary: TrustedAdvisorCategorySpecificSummary


TrustedAdvisorCheckSummaryList = list[TrustedAdvisorCheckSummary]


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


TrustedAdvisorCheckList = list[TrustedAdvisorCheckDescription]


class DescribeTrustedAdvisorChecksResponse(TypedDict, total=False):
    checks: TrustedAdvisorCheckList


class RefreshTrustedAdvisorCheckRequest(ServiceRequest):
    checkId: String


class RefreshTrustedAdvisorCheckResponse(TypedDict, total=False):
    status: TrustedAdvisorCheckRefreshStatus


class ResolveCaseRequest(ServiceRequest):
    caseId: CaseId | None


class ResolveCaseResponse(TypedDict, total=False):
    initialCaseStatus: CaseStatus | None
    finalCaseStatus: CaseStatus | None


class SupportApi:
    service: str = "support"
    version: str = "2013-04-15"

    @handler("AddAttachmentsToSet")
    def add_attachments_to_set(
        self,
        context: RequestContext,
        attachments: Attachments,
        attachment_set_id: AttachmentSetId | None = None,
        **kwargs,
    ) -> AddAttachmentsToSetResponse:
        raise NotImplementedError

    @handler("AddCommunicationToCase")
    def add_communication_to_case(
        self,
        context: RequestContext,
        communication_body: CommunicationBody,
        case_id: CaseId | None = None,
        cc_email_addresses: CcEmailAddressList | None = None,
        attachment_set_id: AttachmentSetId | None = None,
        **kwargs,
    ) -> AddCommunicationToCaseResponse:
        raise NotImplementedError

    @handler("CreateCase")
    def create_case(
        self,
        context: RequestContext,
        subject: Subject,
        communication_body: CommunicationBody,
        service_code: ServiceCode | None = None,
        severity_code: SeverityCode | None = None,
        category_code: CategoryCode | None = None,
        cc_email_addresses: CcEmailAddressList | None = None,
        language: Language | None = None,
        issue_type: IssueType | None = None,
        attachment_set_id: AttachmentSetId | None = None,
        **kwargs,
    ) -> CreateCaseResponse:
        raise NotImplementedError

    @handler("DescribeAttachment")
    def describe_attachment(
        self, context: RequestContext, attachment_id: AttachmentId, **kwargs
    ) -> DescribeAttachmentResponse:
        raise NotImplementedError

    @handler("DescribeCases")
    def describe_cases(
        self,
        context: RequestContext,
        case_id_list: CaseIdList | None = None,
        display_id: DisplayId | None = None,
        after_time: AfterTime | None = None,
        before_time: BeforeTime | None = None,
        include_resolved_cases: IncludeResolvedCases | None = None,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        language: Language | None = None,
        include_communications: IncludeCommunications | None = None,
        **kwargs,
    ) -> DescribeCasesResponse:
        raise NotImplementedError

    @handler("DescribeCommunications")
    def describe_communications(
        self,
        context: RequestContext,
        case_id: CaseId,
        before_time: BeforeTime | None = None,
        after_time: AfterTime | None = None,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
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
        **kwargs,
    ) -> DescribeCreateCaseOptionsResponse:
        raise NotImplementedError

    @handler("DescribeServices")
    def describe_services(
        self,
        context: RequestContext,
        service_code_list: ServiceCodeList | None = None,
        language: Language | None = None,
        **kwargs,
    ) -> DescribeServicesResponse:
        raise NotImplementedError

    @handler("DescribeSeverityLevels")
    def describe_severity_levels(
        self, context: RequestContext, language: Language | None = None, **kwargs
    ) -> DescribeSeverityLevelsResponse:
        raise NotImplementedError

    @handler("DescribeSupportedLanguages")
    def describe_supported_languages(
        self,
        context: RequestContext,
        issue_type: ValidatedIssueTypeString,
        service_code: ValidatedServiceCode,
        category_code: ValidatedCategoryCode,
        **kwargs,
    ) -> DescribeSupportedLanguagesResponse:
        raise NotImplementedError

    @handler("DescribeTrustedAdvisorCheckRefreshStatuses")
    def describe_trusted_advisor_check_refresh_statuses(
        self, context: RequestContext, check_ids: StringList, **kwargs
    ) -> DescribeTrustedAdvisorCheckRefreshStatusesResponse:
        raise NotImplementedError

    @handler("DescribeTrustedAdvisorCheckResult")
    def describe_trusted_advisor_check_result(
        self, context: RequestContext, check_id: String, language: String | None = None, **kwargs
    ) -> DescribeTrustedAdvisorCheckResultResponse:
        raise NotImplementedError

    @handler("DescribeTrustedAdvisorCheckSummaries")
    def describe_trusted_advisor_check_summaries(
        self, context: RequestContext, check_ids: StringList, **kwargs
    ) -> DescribeTrustedAdvisorCheckSummariesResponse:
        raise NotImplementedError

    @handler("DescribeTrustedAdvisorChecks")
    def describe_trusted_advisor_checks(
        self, context: RequestContext, language: String, **kwargs
    ) -> DescribeTrustedAdvisorChecksResponse:
        raise NotImplementedError

    @handler("RefreshTrustedAdvisorCheck")
    def refresh_trusted_advisor_check(
        self, context: RequestContext, check_id: String, **kwargs
    ) -> RefreshTrustedAdvisorCheckResponse:
        raise NotImplementedError

    @handler("ResolveCase")
    def resolve_case(
        self, context: RequestContext, case_id: CaseId | None = None, **kwargs
    ) -> ResolveCaseResponse:
        raise NotImplementedError
