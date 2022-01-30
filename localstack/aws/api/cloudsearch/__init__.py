import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

APIVersion = str
ARN = str
Boolean = bool
DomainId = str
DomainName = str
Double = float
DynamicFieldName = str
ErrorCode = str
ErrorMessage = str
ExpressionValue = str
FieldName = str
FieldNameCommaList = str
FieldValue = str
InstanceCount = int
MaximumPartitionCount = int
MaximumReplicationCount = int
MultiAZ = bool
PartitionCount = int
PolicyDocument = str
SearchInstanceType = str
ServiceUrl = str
StandardName = str
String = str
UIntValue = int
Word = str


class AlgorithmicStemming(str):
    none = "none"
    minimal = "minimal"
    light = "light"
    full = "full"


class AnalysisSchemeLanguage(str):
    ar = "ar"
    bg = "bg"
    ca = "ca"
    cs = "cs"
    da = "da"
    de = "de"
    el = "el"
    en = "en"
    es = "es"
    eu = "eu"
    fa = "fa"
    fi = "fi"
    fr = "fr"
    ga = "ga"
    gl = "gl"
    he = "he"
    hi = "hi"
    hu = "hu"
    hy = "hy"
    id = "id"
    it = "it"
    ja = "ja"
    ko = "ko"
    lv = "lv"
    mul = "mul"
    nl = "nl"
    no = "no"
    pt = "pt"
    ro = "ro"
    ru = "ru"
    sv = "sv"
    th = "th"
    tr = "tr"
    zh_Hans = "zh-Hans"
    zh_Hant = "zh-Hant"


class IndexFieldType(str):
    int = "int"
    double = "double"
    literal = "literal"
    text = "text"
    date = "date"
    latlon = "latlon"
    int_array = "int-array"
    double_array = "double-array"
    literal_array = "literal-array"
    text_array = "text-array"
    date_array = "date-array"


class OptionState(str):
    RequiresIndexDocuments = "RequiresIndexDocuments"
    Processing = "Processing"
    Active = "Active"
    FailedToValidate = "FailedToValidate"


class PartitionInstanceType(str):
    search_m1_small = "search.m1.small"
    search_m1_large = "search.m1.large"
    search_m2_xlarge = "search.m2.xlarge"
    search_m2_2xlarge = "search.m2.2xlarge"
    search_m3_medium = "search.m3.medium"
    search_m3_large = "search.m3.large"
    search_m3_xlarge = "search.m3.xlarge"
    search_m3_2xlarge = "search.m3.2xlarge"
    search_small = "search.small"
    search_medium = "search.medium"
    search_large = "search.large"
    search_xlarge = "search.xlarge"
    search_2xlarge = "search.2xlarge"
    search_previousgeneration_small = "search.previousgeneration.small"
    search_previousgeneration_large = "search.previousgeneration.large"
    search_previousgeneration_xlarge = "search.previousgeneration.xlarge"
    search_previousgeneration_2xlarge = "search.previousgeneration.2xlarge"


class SuggesterFuzzyMatching(str):
    none = "none"
    low = "low"
    high = "high"


class TLSSecurityPolicy(str):
    Policy_Min_TLS_1_0_2019_07 = "Policy-Min-TLS-1-0-2019-07"
    Policy_Min_TLS_1_2_2019_07 = "Policy-Min-TLS-1-2-2019-07"


class BaseException(ServiceException):
    Code: Optional[ErrorCode]
    Message: Optional[ErrorMessage]


class DisabledOperationException(ServiceException):
    pass


class InternalException(ServiceException):
    pass


class InvalidTypeException(ServiceException):
    pass


class LimitExceededException(ServiceException):
    pass


class ResourceAlreadyExistsException(ServiceException):
    pass


class ResourceNotFoundException(ServiceException):
    pass


class ValidationException(ServiceException):
    pass


UpdateTimestamp = datetime


class OptionStatus(TypedDict, total=False):
    CreationDate: UpdateTimestamp
    UpdateDate: UpdateTimestamp
    UpdateVersion: Optional[UIntValue]
    State: OptionState
    PendingDeletion: Optional[Boolean]


class AccessPoliciesStatus(TypedDict, total=False):
    Options: PolicyDocument
    Status: OptionStatus


class AnalysisOptions(TypedDict, total=False):
    Synonyms: Optional[String]
    Stopwords: Optional[String]
    StemmingDictionary: Optional[String]
    JapaneseTokenizationDictionary: Optional[String]
    AlgorithmicStemming: Optional[AlgorithmicStemming]


class AnalysisScheme(TypedDict, total=False):
    AnalysisSchemeName: StandardName
    AnalysisSchemeLanguage: AnalysisSchemeLanguage
    AnalysisOptions: Optional[AnalysisOptions]


class AnalysisSchemeStatus(TypedDict, total=False):
    Options: AnalysisScheme
    Status: OptionStatus


AnalysisSchemeStatusList = List[AnalysisSchemeStatus]


class AvailabilityOptionsStatus(TypedDict, total=False):
    Options: MultiAZ
    Status: OptionStatus


class BuildSuggestersRequest(ServiceRequest):
    DomainName: DomainName


FieldNameList = List[FieldName]


class BuildSuggestersResponse(TypedDict, total=False):
    FieldNames: Optional[FieldNameList]


class CreateDomainRequest(ServiceRequest):
    DomainName: DomainName


class Limits(TypedDict, total=False):
    MaximumReplicationCount: MaximumReplicationCount
    MaximumPartitionCount: MaximumPartitionCount


class ServiceEndpoint(TypedDict, total=False):
    Endpoint: Optional[ServiceUrl]


class DomainStatus(TypedDict, total=False):
    DomainId: DomainId
    DomainName: DomainName
    ARN: Optional[ARN]
    Created: Optional[Boolean]
    Deleted: Optional[Boolean]
    DocService: Optional[ServiceEndpoint]
    SearchService: Optional[ServiceEndpoint]
    RequiresIndexDocuments: Boolean
    Processing: Optional[Boolean]
    SearchInstanceType: Optional[SearchInstanceType]
    SearchPartitionCount: Optional[PartitionCount]
    SearchInstanceCount: Optional[InstanceCount]
    Limits: Optional[Limits]


class CreateDomainResponse(TypedDict, total=False):
    DomainStatus: Optional[DomainStatus]


class DateArrayOptions(TypedDict, total=False):
    DefaultValue: Optional[FieldValue]
    SourceFields: Optional[FieldNameCommaList]
    FacetEnabled: Optional[Boolean]
    SearchEnabled: Optional[Boolean]
    ReturnEnabled: Optional[Boolean]


class DateOptions(TypedDict, total=False):
    DefaultValue: Optional[FieldValue]
    SourceField: Optional[FieldName]
    FacetEnabled: Optional[Boolean]
    SearchEnabled: Optional[Boolean]
    ReturnEnabled: Optional[Boolean]
    SortEnabled: Optional[Boolean]


class DefineAnalysisSchemeRequest(ServiceRequest):
    DomainName: DomainName
    AnalysisScheme: AnalysisScheme


class DefineAnalysisSchemeResponse(TypedDict, total=False):
    AnalysisScheme: AnalysisSchemeStatus


class Expression(TypedDict, total=False):
    ExpressionName: StandardName
    ExpressionValue: ExpressionValue


class DefineExpressionRequest(ServiceRequest):
    DomainName: DomainName
    Expression: Expression


class ExpressionStatus(TypedDict, total=False):
    Options: Expression
    Status: OptionStatus


class DefineExpressionResponse(TypedDict, total=False):
    Expression: ExpressionStatus


class TextArrayOptions(TypedDict, total=False):
    DefaultValue: Optional[FieldValue]
    SourceFields: Optional[FieldNameCommaList]
    ReturnEnabled: Optional[Boolean]
    HighlightEnabled: Optional[Boolean]
    AnalysisScheme: Optional[Word]


class LiteralArrayOptions(TypedDict, total=False):
    DefaultValue: Optional[FieldValue]
    SourceFields: Optional[FieldNameCommaList]
    FacetEnabled: Optional[Boolean]
    SearchEnabled: Optional[Boolean]
    ReturnEnabled: Optional[Boolean]


class DoubleArrayOptions(TypedDict, total=False):
    DefaultValue: Optional[Double]
    SourceFields: Optional[FieldNameCommaList]
    FacetEnabled: Optional[Boolean]
    SearchEnabled: Optional[Boolean]
    ReturnEnabled: Optional[Boolean]


Long = int


class IntArrayOptions(TypedDict, total=False):
    DefaultValue: Optional[Long]
    SourceFields: Optional[FieldNameCommaList]
    FacetEnabled: Optional[Boolean]
    SearchEnabled: Optional[Boolean]
    ReturnEnabled: Optional[Boolean]


class LatLonOptions(TypedDict, total=False):
    DefaultValue: Optional[FieldValue]
    SourceField: Optional[FieldName]
    FacetEnabled: Optional[Boolean]
    SearchEnabled: Optional[Boolean]
    ReturnEnabled: Optional[Boolean]
    SortEnabled: Optional[Boolean]


class TextOptions(TypedDict, total=False):
    DefaultValue: Optional[FieldValue]
    SourceField: Optional[FieldName]
    ReturnEnabled: Optional[Boolean]
    SortEnabled: Optional[Boolean]
    HighlightEnabled: Optional[Boolean]
    AnalysisScheme: Optional[Word]


class LiteralOptions(TypedDict, total=False):
    DefaultValue: Optional[FieldValue]
    SourceField: Optional[FieldName]
    FacetEnabled: Optional[Boolean]
    SearchEnabled: Optional[Boolean]
    ReturnEnabled: Optional[Boolean]
    SortEnabled: Optional[Boolean]


class DoubleOptions(TypedDict, total=False):
    DefaultValue: Optional[Double]
    SourceField: Optional[FieldName]
    FacetEnabled: Optional[Boolean]
    SearchEnabled: Optional[Boolean]
    ReturnEnabled: Optional[Boolean]
    SortEnabled: Optional[Boolean]


class IntOptions(TypedDict, total=False):
    DefaultValue: Optional[Long]
    SourceField: Optional[FieldName]
    FacetEnabled: Optional[Boolean]
    SearchEnabled: Optional[Boolean]
    ReturnEnabled: Optional[Boolean]
    SortEnabled: Optional[Boolean]


class IndexField(TypedDict, total=False):
    IndexFieldName: DynamicFieldName
    IndexFieldType: IndexFieldType
    IntOptions: Optional[IntOptions]
    DoubleOptions: Optional[DoubleOptions]
    LiteralOptions: Optional[LiteralOptions]
    TextOptions: Optional[TextOptions]
    DateOptions: Optional[DateOptions]
    LatLonOptions: Optional[LatLonOptions]
    IntArrayOptions: Optional[IntArrayOptions]
    DoubleArrayOptions: Optional[DoubleArrayOptions]
    LiteralArrayOptions: Optional[LiteralArrayOptions]
    TextArrayOptions: Optional[TextArrayOptions]
    DateArrayOptions: Optional[DateArrayOptions]


class DefineIndexFieldRequest(ServiceRequest):
    DomainName: DomainName
    IndexField: IndexField


class IndexFieldStatus(TypedDict, total=False):
    Options: IndexField
    Status: OptionStatus


class DefineIndexFieldResponse(TypedDict, total=False):
    IndexField: IndexFieldStatus


class DocumentSuggesterOptions(TypedDict, total=False):
    SourceField: FieldName
    FuzzyMatching: Optional[SuggesterFuzzyMatching]
    SortExpression: Optional[String]


class Suggester(TypedDict, total=False):
    SuggesterName: StandardName
    DocumentSuggesterOptions: DocumentSuggesterOptions


class DefineSuggesterRequest(ServiceRequest):
    DomainName: DomainName
    Suggester: Suggester


class SuggesterStatus(TypedDict, total=False):
    Options: Suggester
    Status: OptionStatus


class DefineSuggesterResponse(TypedDict, total=False):
    Suggester: SuggesterStatus


class DeleteAnalysisSchemeRequest(ServiceRequest):
    DomainName: DomainName
    AnalysisSchemeName: StandardName


class DeleteAnalysisSchemeResponse(TypedDict, total=False):
    AnalysisScheme: AnalysisSchemeStatus


class DeleteDomainRequest(ServiceRequest):
    DomainName: DomainName


class DeleteDomainResponse(TypedDict, total=False):
    DomainStatus: Optional[DomainStatus]


class DeleteExpressionRequest(ServiceRequest):
    DomainName: DomainName
    ExpressionName: StandardName


class DeleteExpressionResponse(TypedDict, total=False):
    Expression: ExpressionStatus


class DeleteIndexFieldRequest(ServiceRequest):
    DomainName: DomainName
    IndexFieldName: DynamicFieldName


class DeleteIndexFieldResponse(TypedDict, total=False):
    IndexField: IndexFieldStatus


class DeleteSuggesterRequest(ServiceRequest):
    DomainName: DomainName
    SuggesterName: StandardName


class DeleteSuggesterResponse(TypedDict, total=False):
    Suggester: SuggesterStatus


StandardNameList = List[StandardName]


class DescribeAnalysisSchemesRequest(ServiceRequest):
    DomainName: DomainName
    AnalysisSchemeNames: Optional[StandardNameList]
    Deployed: Optional[Boolean]


class DescribeAnalysisSchemesResponse(TypedDict, total=False):
    AnalysisSchemes: AnalysisSchemeStatusList


class DescribeAvailabilityOptionsRequest(ServiceRequest):
    DomainName: DomainName
    Deployed: Optional[Boolean]


class DescribeAvailabilityOptionsResponse(TypedDict, total=False):
    AvailabilityOptions: Optional[AvailabilityOptionsStatus]


class DescribeDomainEndpointOptionsRequest(ServiceRequest):
    DomainName: DomainName
    Deployed: Optional[Boolean]


class DomainEndpointOptions(TypedDict, total=False):
    EnforceHTTPS: Optional[Boolean]
    TLSSecurityPolicy: Optional[TLSSecurityPolicy]


class DomainEndpointOptionsStatus(TypedDict, total=False):
    Options: DomainEndpointOptions
    Status: OptionStatus


class DescribeDomainEndpointOptionsResponse(TypedDict, total=False):
    DomainEndpointOptions: Optional[DomainEndpointOptionsStatus]


DomainNameList = List[DomainName]


class DescribeDomainsRequest(ServiceRequest):
    DomainNames: Optional[DomainNameList]


DomainStatusList = List[DomainStatus]


class DescribeDomainsResponse(TypedDict, total=False):
    DomainStatusList: DomainStatusList


class DescribeExpressionsRequest(ServiceRequest):
    DomainName: DomainName
    ExpressionNames: Optional[StandardNameList]
    Deployed: Optional[Boolean]


ExpressionStatusList = List[ExpressionStatus]


class DescribeExpressionsResponse(TypedDict, total=False):
    Expressions: ExpressionStatusList


DynamicFieldNameList = List[DynamicFieldName]


class DescribeIndexFieldsRequest(ServiceRequest):
    DomainName: DomainName
    FieldNames: Optional[DynamicFieldNameList]
    Deployed: Optional[Boolean]


IndexFieldStatusList = List[IndexFieldStatus]


class DescribeIndexFieldsResponse(TypedDict, total=False):
    IndexFields: IndexFieldStatusList


class DescribeScalingParametersRequest(ServiceRequest):
    DomainName: DomainName


class ScalingParameters(TypedDict, total=False):
    DesiredInstanceType: Optional[PartitionInstanceType]
    DesiredReplicationCount: Optional[UIntValue]
    DesiredPartitionCount: Optional[UIntValue]


class ScalingParametersStatus(TypedDict, total=False):
    Options: ScalingParameters
    Status: OptionStatus


class DescribeScalingParametersResponse(TypedDict, total=False):
    ScalingParameters: ScalingParametersStatus


class DescribeServiceAccessPoliciesRequest(ServiceRequest):
    DomainName: DomainName
    Deployed: Optional[Boolean]


class DescribeServiceAccessPoliciesResponse(TypedDict, total=False):
    AccessPolicies: AccessPoliciesStatus


class DescribeSuggestersRequest(ServiceRequest):
    DomainName: DomainName
    SuggesterNames: Optional[StandardNameList]
    Deployed: Optional[Boolean]


SuggesterStatusList = List[SuggesterStatus]


class DescribeSuggestersResponse(TypedDict, total=False):
    Suggesters: SuggesterStatusList


DomainNameMap = Dict[DomainName, APIVersion]


class IndexDocumentsRequest(ServiceRequest):
    DomainName: DomainName


class IndexDocumentsResponse(TypedDict, total=False):
    FieldNames: Optional[FieldNameList]


class ListDomainNamesResponse(TypedDict, total=False):
    DomainNames: Optional[DomainNameMap]


class UpdateAvailabilityOptionsRequest(ServiceRequest):
    DomainName: DomainName
    MultiAZ: Boolean


class UpdateAvailabilityOptionsResponse(TypedDict, total=False):
    AvailabilityOptions: Optional[AvailabilityOptionsStatus]


class UpdateDomainEndpointOptionsRequest(ServiceRequest):
    DomainName: DomainName
    DomainEndpointOptions: DomainEndpointOptions


class UpdateDomainEndpointOptionsResponse(TypedDict, total=False):
    DomainEndpointOptions: Optional[DomainEndpointOptionsStatus]


class UpdateScalingParametersRequest(ServiceRequest):
    DomainName: DomainName
    ScalingParameters: ScalingParameters


class UpdateScalingParametersResponse(TypedDict, total=False):
    ScalingParameters: ScalingParametersStatus


class UpdateServiceAccessPoliciesRequest(ServiceRequest):
    DomainName: DomainName
    AccessPolicies: PolicyDocument


class UpdateServiceAccessPoliciesResponse(TypedDict, total=False):
    AccessPolicies: AccessPoliciesStatus


class CloudsearchApi:

    service = "cloudsearch"
    version = "2013-01-01"

    @handler("BuildSuggesters")
    def build_suggesters(
        self, context: RequestContext, domain_name: DomainName
    ) -> BuildSuggestersResponse:
        raise NotImplementedError

    @handler("CreateDomain")
    def create_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> CreateDomainResponse:
        raise NotImplementedError

    @handler("DefineAnalysisScheme")
    def define_analysis_scheme(
        self, context: RequestContext, domain_name: DomainName, analysis_scheme: AnalysisScheme
    ) -> DefineAnalysisSchemeResponse:
        raise NotImplementedError

    @handler("DefineExpression")
    def define_expression(
        self, context: RequestContext, domain_name: DomainName, expression: Expression
    ) -> DefineExpressionResponse:
        raise NotImplementedError

    @handler("DefineIndexField")
    def define_index_field(
        self, context: RequestContext, domain_name: DomainName, index_field: IndexField
    ) -> DefineIndexFieldResponse:
        raise NotImplementedError

    @handler("DefineSuggester")
    def define_suggester(
        self, context: RequestContext, domain_name: DomainName, suggester: Suggester
    ) -> DefineSuggesterResponse:
        raise NotImplementedError

    @handler("DeleteAnalysisScheme")
    def delete_analysis_scheme(
        self, context: RequestContext, domain_name: DomainName, analysis_scheme_name: StandardName
    ) -> DeleteAnalysisSchemeResponse:
        raise NotImplementedError

    @handler("DeleteDomain")
    def delete_domain(
        self, context: RequestContext, domain_name: DomainName
    ) -> DeleteDomainResponse:
        raise NotImplementedError

    @handler("DeleteExpression")
    def delete_expression(
        self, context: RequestContext, domain_name: DomainName, expression_name: StandardName
    ) -> DeleteExpressionResponse:
        raise NotImplementedError

    @handler("DeleteIndexField")
    def delete_index_field(
        self, context: RequestContext, domain_name: DomainName, index_field_name: DynamicFieldName
    ) -> DeleteIndexFieldResponse:
        raise NotImplementedError

    @handler("DeleteSuggester")
    def delete_suggester(
        self, context: RequestContext, domain_name: DomainName, suggester_name: StandardName
    ) -> DeleteSuggesterResponse:
        raise NotImplementedError

    @handler("DescribeAnalysisSchemes")
    def describe_analysis_schemes(
        self,
        context: RequestContext,
        domain_name: DomainName,
        analysis_scheme_names: StandardNameList = None,
        deployed: Boolean = None,
    ) -> DescribeAnalysisSchemesResponse:
        raise NotImplementedError

    @handler("DescribeAvailabilityOptions")
    def describe_availability_options(
        self, context: RequestContext, domain_name: DomainName, deployed: Boolean = None
    ) -> DescribeAvailabilityOptionsResponse:
        raise NotImplementedError

    @handler("DescribeDomainEndpointOptions")
    def describe_domain_endpoint_options(
        self, context: RequestContext, domain_name: DomainName, deployed: Boolean = None
    ) -> DescribeDomainEndpointOptionsResponse:
        raise NotImplementedError

    @handler("DescribeDomains")
    def describe_domains(
        self, context: RequestContext, domain_names: DomainNameList = None
    ) -> DescribeDomainsResponse:
        raise NotImplementedError

    @handler("DescribeExpressions")
    def describe_expressions(
        self,
        context: RequestContext,
        domain_name: DomainName,
        expression_names: StandardNameList = None,
        deployed: Boolean = None,
    ) -> DescribeExpressionsResponse:
        raise NotImplementedError

    @handler("DescribeIndexFields")
    def describe_index_fields(
        self,
        context: RequestContext,
        domain_name: DomainName,
        field_names: DynamicFieldNameList = None,
        deployed: Boolean = None,
    ) -> DescribeIndexFieldsResponse:
        raise NotImplementedError

    @handler("DescribeScalingParameters")
    def describe_scaling_parameters(
        self, context: RequestContext, domain_name: DomainName
    ) -> DescribeScalingParametersResponse:
        raise NotImplementedError

    @handler("DescribeServiceAccessPolicies")
    def describe_service_access_policies(
        self, context: RequestContext, domain_name: DomainName, deployed: Boolean = None
    ) -> DescribeServiceAccessPoliciesResponse:
        raise NotImplementedError

    @handler("DescribeSuggesters")
    def describe_suggesters(
        self,
        context: RequestContext,
        domain_name: DomainName,
        suggester_names: StandardNameList = None,
        deployed: Boolean = None,
    ) -> DescribeSuggestersResponse:
        raise NotImplementedError

    @handler("IndexDocuments")
    def index_documents(
        self, context: RequestContext, domain_name: DomainName
    ) -> IndexDocumentsResponse:
        raise NotImplementedError

    @handler("ListDomainNames")
    def list_domain_names(
        self,
        context: RequestContext,
    ) -> ListDomainNamesResponse:
        raise NotImplementedError

    @handler("UpdateAvailabilityOptions")
    def update_availability_options(
        self, context: RequestContext, domain_name: DomainName, multi_az: Boolean
    ) -> UpdateAvailabilityOptionsResponse:
        raise NotImplementedError

    @handler("UpdateDomainEndpointOptions")
    def update_domain_endpoint_options(
        self,
        context: RequestContext,
        domain_name: DomainName,
        domain_endpoint_options: DomainEndpointOptions,
    ) -> UpdateDomainEndpointOptionsResponse:
        raise NotImplementedError

    @handler("UpdateScalingParameters")
    def update_scaling_parameters(
        self,
        context: RequestContext,
        domain_name: DomainName,
        scaling_parameters: ScalingParameters,
    ) -> UpdateScalingParametersResponse:
        raise NotImplementedError

    @handler("UpdateServiceAccessPolicies")
    def update_service_access_policies(
        self, context: RequestContext, domain_name: DomainName, access_policies: PolicyDocument
    ) -> UpdateServiceAccessPoliciesResponse:
        raise NotImplementedError
