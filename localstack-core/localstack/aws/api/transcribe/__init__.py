from datetime import datetime
from enum import StrEnum
from typing import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Boolean = bool
CallAnalyticsJobName = str
CategoryName = str
ChannelId = int
DataAccessRoleArn = str
DurationInSeconds = float
FailureReason = str
IdentifiedLanguageScore = float
KMSKeyId = str
MaxAlternatives = int
MaxResults = int
MaxSpeakers = int
MediaSampleRateHertz = int
MedicalMediaSampleRateHertz = int
MedicalScribeChannelId = int
ModelName = str
NextToken = str
NonEmptyString = str
OutputBucketName = str
OutputKey = str
Percentage = int
Phrase = str
String = str
SubtitleOutputStartIndex = int
TagKey = str
TagValue = str
TranscribeArn = str
TranscriptionJobName = str
Uri = str
VocabularyFilterName = str
VocabularyName = str
Word = str


class BaseModelName(StrEnum):
    NarrowBand = "NarrowBand"
    WideBand = "WideBand"


class CLMLanguageCode(StrEnum):
    en_US = "en-US"
    hi_IN = "hi-IN"
    es_US = "es-US"
    en_GB = "en-GB"
    en_AU = "en-AU"
    de_DE = "de-DE"
    ja_JP = "ja-JP"


class CallAnalyticsFeature(StrEnum):
    GENERATIVE_SUMMARIZATION = "GENERATIVE_SUMMARIZATION"


class CallAnalyticsJobStatus(StrEnum):
    QUEUED = "QUEUED"
    IN_PROGRESS = "IN_PROGRESS"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"


class CallAnalyticsSkippedReasonCode(StrEnum):
    INSUFFICIENT_CONVERSATION_CONTENT = "INSUFFICIENT_CONVERSATION_CONTENT"
    FAILED_SAFETY_GUIDELINES = "FAILED_SAFETY_GUIDELINES"


class InputType(StrEnum):
    REAL_TIME = "REAL_TIME"
    POST_CALL = "POST_CALL"


class LanguageCode(StrEnum):
    af_ZA = "af-ZA"
    ar_AE = "ar-AE"
    ar_SA = "ar-SA"
    da_DK = "da-DK"
    de_CH = "de-CH"
    de_DE = "de-DE"
    en_AB = "en-AB"
    en_AU = "en-AU"
    en_GB = "en-GB"
    en_IE = "en-IE"
    en_IN = "en-IN"
    en_US = "en-US"
    en_WL = "en-WL"
    es_ES = "es-ES"
    es_US = "es-US"
    fa_IR = "fa-IR"
    fr_CA = "fr-CA"
    fr_FR = "fr-FR"
    he_IL = "he-IL"
    hi_IN = "hi-IN"
    id_ID = "id-ID"
    it_IT = "it-IT"
    ja_JP = "ja-JP"
    ko_KR = "ko-KR"
    ms_MY = "ms-MY"
    nl_NL = "nl-NL"
    pt_BR = "pt-BR"
    pt_PT = "pt-PT"
    ru_RU = "ru-RU"
    ta_IN = "ta-IN"
    te_IN = "te-IN"
    tr_TR = "tr-TR"
    zh_CN = "zh-CN"
    zh_TW = "zh-TW"
    th_TH = "th-TH"
    en_ZA = "en-ZA"
    en_NZ = "en-NZ"
    vi_VN = "vi-VN"
    sv_SE = "sv-SE"
    ab_GE = "ab-GE"
    ast_ES = "ast-ES"
    az_AZ = "az-AZ"
    ba_RU = "ba-RU"
    be_BY = "be-BY"
    bg_BG = "bg-BG"
    bn_IN = "bn-IN"
    bs_BA = "bs-BA"
    ca_ES = "ca-ES"
    ckb_IQ = "ckb-IQ"
    ckb_IR = "ckb-IR"
    cs_CZ = "cs-CZ"
    cy_WL = "cy-WL"
    el_GR = "el-GR"
    et_EE = "et-EE"
    et_ET = "et-ET"
    eu_ES = "eu-ES"
    fi_FI = "fi-FI"
    gl_ES = "gl-ES"
    gu_IN = "gu-IN"
    ha_NG = "ha-NG"
    hr_HR = "hr-HR"
    hu_HU = "hu-HU"
    hy_AM = "hy-AM"
    is_IS = "is-IS"
    ka_GE = "ka-GE"
    kab_DZ = "kab-DZ"
    kk_KZ = "kk-KZ"
    kn_IN = "kn-IN"
    ky_KG = "ky-KG"
    lg_IN = "lg-IN"
    lt_LT = "lt-LT"
    lv_LV = "lv-LV"
    mhr_RU = "mhr-RU"
    mi_NZ = "mi-NZ"
    mk_MK = "mk-MK"
    ml_IN = "ml-IN"
    mn_MN = "mn-MN"
    mr_IN = "mr-IN"
    mt_MT = "mt-MT"
    no_NO = "no-NO"
    or_IN = "or-IN"
    pa_IN = "pa-IN"
    pl_PL = "pl-PL"
    ps_AF = "ps-AF"
    ro_RO = "ro-RO"
    rw_RW = "rw-RW"
    si_LK = "si-LK"
    sk_SK = "sk-SK"
    sl_SI = "sl-SI"
    so_SO = "so-SO"
    sr_RS = "sr-RS"
    su_ID = "su-ID"
    sw_BI = "sw-BI"
    sw_KE = "sw-KE"
    sw_RW = "sw-RW"
    sw_TZ = "sw-TZ"
    sw_UG = "sw-UG"
    tl_PH = "tl-PH"
    tt_RU = "tt-RU"
    ug_CN = "ug-CN"
    uk_UA = "uk-UA"
    uz_UZ = "uz-UZ"
    wo_SN = "wo-SN"
    zh_HK = "zh-HK"
    zu_ZA = "zu-ZA"


class MediaFormat(StrEnum):
    mp3 = "mp3"
    mp4 = "mp4"
    wav = "wav"
    flac = "flac"
    ogg = "ogg"
    amr = "amr"
    webm = "webm"
    m4a = "m4a"


class MedicalContentIdentificationType(StrEnum):
    PHI = "PHI"


class MedicalScribeJobStatus(StrEnum):
    QUEUED = "QUEUED"
    IN_PROGRESS = "IN_PROGRESS"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"


class MedicalScribeLanguageCode(StrEnum):
    en_US = "en-US"


class MedicalScribeNoteTemplate(StrEnum):
    HISTORY_AND_PHYSICAL = "HISTORY_AND_PHYSICAL"
    GIRPP = "GIRPP"
    BIRP = "BIRP"
    SIRP = "SIRP"
    DAP = "DAP"
    BEHAVIORAL_SOAP = "BEHAVIORAL_SOAP"
    PHYSICAL_SOAP = "PHYSICAL_SOAP"


class MedicalScribeParticipantRole(StrEnum):
    PATIENT = "PATIENT"
    CLINICIAN = "CLINICIAN"


class ModelStatus(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"


class OutputLocationType(StrEnum):
    CUSTOMER_BUCKET = "CUSTOMER_BUCKET"
    SERVICE_BUCKET = "SERVICE_BUCKET"


class ParticipantRole(StrEnum):
    AGENT = "AGENT"
    CUSTOMER = "CUSTOMER"


class PiiEntityType(StrEnum):
    BANK_ACCOUNT_NUMBER = "BANK_ACCOUNT_NUMBER"
    BANK_ROUTING = "BANK_ROUTING"
    CREDIT_DEBIT_NUMBER = "CREDIT_DEBIT_NUMBER"
    CREDIT_DEBIT_CVV = "CREDIT_DEBIT_CVV"
    CREDIT_DEBIT_EXPIRY = "CREDIT_DEBIT_EXPIRY"
    PIN = "PIN"
    EMAIL = "EMAIL"
    ADDRESS = "ADDRESS"
    NAME = "NAME"
    PHONE = "PHONE"
    SSN = "SSN"
    ALL = "ALL"


class Pronouns(StrEnum):
    HE_HIM = "HE_HIM"
    SHE_HER = "SHE_HER"
    THEY_THEM = "THEY_THEM"


class RedactionOutput(StrEnum):
    redacted = "redacted"
    redacted_and_unredacted = "redacted_and_unredacted"


class RedactionType(StrEnum):
    PII = "PII"


class SentimentValue(StrEnum):
    POSITIVE = "POSITIVE"
    NEGATIVE = "NEGATIVE"
    NEUTRAL = "NEUTRAL"
    MIXED = "MIXED"


class Specialty(StrEnum):
    PRIMARYCARE = "PRIMARYCARE"


class SubtitleFormat(StrEnum):
    vtt = "vtt"
    srt = "srt"


class ToxicityCategory(StrEnum):
    ALL = "ALL"


class TranscriptFilterType(StrEnum):
    EXACT = "EXACT"


class TranscriptionJobStatus(StrEnum):
    QUEUED = "QUEUED"
    IN_PROGRESS = "IN_PROGRESS"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"


class Type(StrEnum):
    CONVERSATION = "CONVERSATION"
    DICTATION = "DICTATION"


class VocabularyFilterMethod(StrEnum):
    remove = "remove"
    mask = "mask"
    tag = "tag"


class VocabularyState(StrEnum):
    PENDING = "PENDING"
    READY = "READY"
    FAILED = "FAILED"


class BadRequestException(ServiceException):
    code: str = "BadRequestException"
    sender_fault: bool = False
    status_code: int = 400


class ConflictException(ServiceException):
    code: str = "ConflictException"
    sender_fault: bool = False
    status_code: int = 400


class InternalFailureException(ServiceException):
    code: str = "InternalFailureException"
    sender_fault: bool = False
    status_code: int = 400


class LimitExceededException(ServiceException):
    code: str = "LimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class NotFoundException(ServiceException):
    code: str = "NotFoundException"
    sender_fault: bool = False
    status_code: int = 400


TimestampMilliseconds = int


class AbsoluteTimeRange(TypedDict, total=False):
    StartTime: TimestampMilliseconds | None
    EndTime: TimestampMilliseconds | None
    First: TimestampMilliseconds | None
    Last: TimestampMilliseconds | None


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = list[Tag]


class ChannelDefinition(TypedDict, total=False):
    ChannelId: ChannelId | None
    ParticipantRole: ParticipantRole | None


ChannelDefinitions = list[ChannelDefinition]


class Summarization(TypedDict, total=False):
    GenerateAbstractiveSummary: Boolean


class LanguageIdSettings(TypedDict, total=False):
    VocabularyName: VocabularyName | None
    VocabularyFilterName: VocabularyFilterName | None
    LanguageModelName: ModelName | None


LanguageIdSettingsMap = dict[LanguageCode, LanguageIdSettings]
LanguageOptions = list[LanguageCode]
PiiEntityTypes = list[PiiEntityType]


class ContentRedaction(TypedDict, total=False):
    RedactionType: RedactionType
    RedactionOutput: RedactionOutput
    PiiEntityTypes: PiiEntityTypes | None


class CallAnalyticsJobSettings(TypedDict, total=False):
    VocabularyName: VocabularyName | None
    VocabularyFilterName: VocabularyFilterName | None
    VocabularyFilterMethod: VocabularyFilterMethod | None
    LanguageModelName: ModelName | None
    ContentRedaction: ContentRedaction | None
    LanguageOptions: LanguageOptions | None
    LanguageIdSettings: LanguageIdSettingsMap | None
    Summarization: Summarization | None


DateTime = datetime


class Transcript(TypedDict, total=False):
    TranscriptFileUri: Uri | None
    RedactedTranscriptFileUri: Uri | None


class Media(TypedDict, total=False):
    MediaFileUri: Uri | None
    RedactedMediaFileUri: Uri | None


class CallAnalyticsSkippedFeature(TypedDict, total=False):
    Feature: CallAnalyticsFeature | None
    ReasonCode: CallAnalyticsSkippedReasonCode | None
    Message: String | None


CallAnalyticsSkippedFeatureList = list[CallAnalyticsSkippedFeature]


class CallAnalyticsJobDetails(TypedDict, total=False):
    Skipped: CallAnalyticsSkippedFeatureList | None


class CallAnalyticsJob(TypedDict, total=False):
    CallAnalyticsJobName: CallAnalyticsJobName | None
    CallAnalyticsJobStatus: CallAnalyticsJobStatus | None
    CallAnalyticsJobDetails: CallAnalyticsJobDetails | None
    LanguageCode: LanguageCode | None
    MediaSampleRateHertz: MediaSampleRateHertz | None
    MediaFormat: MediaFormat | None
    Media: Media | None
    Transcript: Transcript | None
    StartTime: DateTime | None
    CreationTime: DateTime | None
    CompletionTime: DateTime | None
    FailureReason: FailureReason | None
    DataAccessRoleArn: DataAccessRoleArn | None
    IdentifiedLanguageScore: IdentifiedLanguageScore | None
    Settings: CallAnalyticsJobSettings | None
    ChannelDefinitions: ChannelDefinitions | None
    Tags: TagList | None


class CallAnalyticsJobSummary(TypedDict, total=False):
    CallAnalyticsJobName: CallAnalyticsJobName | None
    CreationTime: DateTime | None
    StartTime: DateTime | None
    CompletionTime: DateTime | None
    LanguageCode: LanguageCode | None
    CallAnalyticsJobStatus: CallAnalyticsJobStatus | None
    CallAnalyticsJobDetails: CallAnalyticsJobDetails | None
    FailureReason: FailureReason | None


CallAnalyticsJobSummaries = list[CallAnalyticsJobSummary]


class RelativeTimeRange(TypedDict, total=False):
    StartPercentage: Percentage | None
    EndPercentage: Percentage | None
    First: Percentage | None
    Last: Percentage | None


SentimentValueList = list[SentimentValue]


class SentimentFilter(TypedDict, total=False):
    Sentiments: SentimentValueList
    AbsoluteTimeRange: AbsoluteTimeRange | None
    RelativeTimeRange: RelativeTimeRange | None
    ParticipantRole: ParticipantRole | None
    Negate: Boolean | None


StringTargetList = list[NonEmptyString]


class TranscriptFilter(TypedDict, total=False):
    TranscriptFilterType: TranscriptFilterType
    AbsoluteTimeRange: AbsoluteTimeRange | None
    RelativeTimeRange: RelativeTimeRange | None
    ParticipantRole: ParticipantRole | None
    Negate: Boolean | None
    Targets: StringTargetList


class InterruptionFilter(TypedDict, total=False):
    Threshold: TimestampMilliseconds | None
    ParticipantRole: ParticipantRole | None
    AbsoluteTimeRange: AbsoluteTimeRange | None
    RelativeTimeRange: RelativeTimeRange | None
    Negate: Boolean | None


class NonTalkTimeFilter(TypedDict, total=False):
    Threshold: TimestampMilliseconds | None
    AbsoluteTimeRange: AbsoluteTimeRange | None
    RelativeTimeRange: RelativeTimeRange | None
    Negate: Boolean | None


class Rule(TypedDict, total=False):
    NonTalkTimeFilter: NonTalkTimeFilter | None
    InterruptionFilter: InterruptionFilter | None
    TranscriptFilter: TranscriptFilter | None
    SentimentFilter: SentimentFilter | None


RuleList = list[Rule]


class CategoryProperties(TypedDict, total=False):
    CategoryName: CategoryName | None
    Rules: RuleList | None
    CreateTime: DateTime | None
    LastUpdateTime: DateTime | None
    Tags: TagList | None
    InputType: InputType | None


CategoryPropertiesList = list[CategoryProperties]


class ClinicalNoteGenerationSettings(TypedDict, total=False):
    NoteTemplate: MedicalScribeNoteTemplate | None


class CreateCallAnalyticsCategoryRequest(ServiceRequest):
    CategoryName: CategoryName
    Rules: RuleList
    Tags: TagList | None
    InputType: InputType | None


class CreateCallAnalyticsCategoryResponse(TypedDict, total=False):
    CategoryProperties: CategoryProperties | None


class InputDataConfig(TypedDict, total=False):
    S3Uri: Uri
    TuningDataS3Uri: Uri | None
    DataAccessRoleArn: DataAccessRoleArn


class CreateLanguageModelRequest(ServiceRequest):
    LanguageCode: CLMLanguageCode
    BaseModelName: BaseModelName
    ModelName: ModelName
    InputDataConfig: InputDataConfig
    Tags: TagList | None


class CreateLanguageModelResponse(TypedDict, total=False):
    LanguageCode: CLMLanguageCode | None
    BaseModelName: BaseModelName | None
    ModelName: ModelName | None
    InputDataConfig: InputDataConfig | None
    ModelStatus: ModelStatus | None


class CreateMedicalVocabularyRequest(ServiceRequest):
    VocabularyName: VocabularyName
    LanguageCode: LanguageCode
    VocabularyFileUri: Uri
    Tags: TagList | None


class CreateMedicalVocabularyResponse(TypedDict, total=False):
    VocabularyName: VocabularyName | None
    LanguageCode: LanguageCode | None
    VocabularyState: VocabularyState | None
    LastModifiedTime: DateTime | None
    FailureReason: FailureReason | None


Words = list[Word]


class CreateVocabularyFilterRequest(ServiceRequest):
    VocabularyFilterName: VocabularyFilterName
    LanguageCode: LanguageCode
    Words: Words | None
    VocabularyFilterFileUri: Uri | None
    Tags: TagList | None
    DataAccessRoleArn: DataAccessRoleArn | None


class CreateVocabularyFilterResponse(TypedDict, total=False):
    VocabularyFilterName: VocabularyFilterName | None
    LanguageCode: LanguageCode | None
    LastModifiedTime: DateTime | None


Phrases = list[Phrase]


class CreateVocabularyRequest(ServiceRequest):
    VocabularyName: VocabularyName
    LanguageCode: LanguageCode
    Phrases: Phrases | None
    VocabularyFileUri: Uri | None
    Tags: TagList | None
    DataAccessRoleArn: DataAccessRoleArn | None


class CreateVocabularyResponse(TypedDict, total=False):
    VocabularyName: VocabularyName | None
    LanguageCode: LanguageCode | None
    VocabularyState: VocabularyState | None
    LastModifiedTime: DateTime | None
    FailureReason: FailureReason | None


class DeleteCallAnalyticsCategoryRequest(ServiceRequest):
    CategoryName: CategoryName


class DeleteCallAnalyticsCategoryResponse(TypedDict, total=False):
    pass


class DeleteCallAnalyticsJobRequest(ServiceRequest):
    CallAnalyticsJobName: CallAnalyticsJobName


class DeleteCallAnalyticsJobResponse(TypedDict, total=False):
    pass


class DeleteLanguageModelRequest(ServiceRequest):
    ModelName: ModelName


class DeleteMedicalScribeJobRequest(ServiceRequest):
    MedicalScribeJobName: TranscriptionJobName


class DeleteMedicalTranscriptionJobRequest(ServiceRequest):
    MedicalTranscriptionJobName: TranscriptionJobName


class DeleteMedicalVocabularyRequest(ServiceRequest):
    VocabularyName: VocabularyName


class DeleteTranscriptionJobRequest(ServiceRequest):
    TranscriptionJobName: TranscriptionJobName


class DeleteVocabularyFilterRequest(ServiceRequest):
    VocabularyFilterName: VocabularyFilterName


class DeleteVocabularyRequest(ServiceRequest):
    VocabularyName: VocabularyName


class DescribeLanguageModelRequest(ServiceRequest):
    ModelName: ModelName


class LanguageModel(TypedDict, total=False):
    ModelName: ModelName | None
    CreateTime: DateTime | None
    LastModifiedTime: DateTime | None
    LanguageCode: CLMLanguageCode | None
    BaseModelName: BaseModelName | None
    ModelStatus: ModelStatus | None
    UpgradeAvailability: Boolean | None
    FailureReason: FailureReason | None
    InputDataConfig: InputDataConfig | None


class DescribeLanguageModelResponse(TypedDict, total=False):
    LanguageModel: LanguageModel | None


class GetCallAnalyticsCategoryRequest(ServiceRequest):
    CategoryName: CategoryName


class GetCallAnalyticsCategoryResponse(TypedDict, total=False):
    CategoryProperties: CategoryProperties | None


class GetCallAnalyticsJobRequest(ServiceRequest):
    CallAnalyticsJobName: CallAnalyticsJobName


class GetCallAnalyticsJobResponse(TypedDict, total=False):
    CallAnalyticsJob: CallAnalyticsJob | None


class GetMedicalScribeJobRequest(ServiceRequest):
    MedicalScribeJobName: TranscriptionJobName


class MedicalScribeChannelDefinition(TypedDict, total=False):
    ChannelId: MedicalScribeChannelId
    ParticipantRole: MedicalScribeParticipantRole


MedicalScribeChannelDefinitions = list[MedicalScribeChannelDefinition]


class MedicalScribeSettings(TypedDict, total=False):
    ShowSpeakerLabels: Boolean | None
    MaxSpeakerLabels: MaxSpeakers | None
    ChannelIdentification: Boolean | None
    VocabularyName: VocabularyName | None
    VocabularyFilterName: VocabularyFilterName | None
    VocabularyFilterMethod: VocabularyFilterMethod | None
    ClinicalNoteGenerationSettings: ClinicalNoteGenerationSettings | None


class MedicalScribeOutput(TypedDict, total=False):
    TranscriptFileUri: Uri
    ClinicalDocumentUri: Uri


class MedicalScribeJob(TypedDict, total=False):
    MedicalScribeJobName: TranscriptionJobName | None
    MedicalScribeJobStatus: MedicalScribeJobStatus | None
    LanguageCode: MedicalScribeLanguageCode | None
    Media: Media | None
    MedicalScribeOutput: MedicalScribeOutput | None
    StartTime: DateTime | None
    CreationTime: DateTime | None
    CompletionTime: DateTime | None
    FailureReason: FailureReason | None
    Settings: MedicalScribeSettings | None
    DataAccessRoleArn: DataAccessRoleArn | None
    ChannelDefinitions: MedicalScribeChannelDefinitions | None
    MedicalScribeContextProvided: Boolean | None
    Tags: TagList | None


class GetMedicalScribeJobResponse(TypedDict, total=False):
    MedicalScribeJob: MedicalScribeJob | None


class GetMedicalTranscriptionJobRequest(ServiceRequest):
    MedicalTranscriptionJobName: TranscriptionJobName


class MedicalTranscriptionSetting(TypedDict, total=False):
    ShowSpeakerLabels: Boolean | None
    MaxSpeakerLabels: MaxSpeakers | None
    ChannelIdentification: Boolean | None
    ShowAlternatives: Boolean | None
    MaxAlternatives: MaxAlternatives | None
    VocabularyName: VocabularyName | None


class MedicalTranscript(TypedDict, total=False):
    TranscriptFileUri: Uri | None


class MedicalTranscriptionJob(TypedDict, total=False):
    MedicalTranscriptionJobName: TranscriptionJobName | None
    TranscriptionJobStatus: TranscriptionJobStatus | None
    LanguageCode: LanguageCode | None
    MediaSampleRateHertz: MedicalMediaSampleRateHertz | None
    MediaFormat: MediaFormat | None
    Media: Media | None
    Transcript: MedicalTranscript | None
    StartTime: DateTime | None
    CreationTime: DateTime | None
    CompletionTime: DateTime | None
    FailureReason: FailureReason | None
    Settings: MedicalTranscriptionSetting | None
    ContentIdentificationType: MedicalContentIdentificationType | None
    Specialty: Specialty | None
    Type: Type | None
    Tags: TagList | None


class GetMedicalTranscriptionJobResponse(TypedDict, total=False):
    MedicalTranscriptionJob: MedicalTranscriptionJob | None


class GetMedicalVocabularyRequest(ServiceRequest):
    VocabularyName: VocabularyName


class GetMedicalVocabularyResponse(TypedDict, total=False):
    VocabularyName: VocabularyName | None
    LanguageCode: LanguageCode | None
    VocabularyState: VocabularyState | None
    LastModifiedTime: DateTime | None
    FailureReason: FailureReason | None
    DownloadUri: Uri | None


class GetTranscriptionJobRequest(ServiceRequest):
    TranscriptionJobName: TranscriptionJobName


ToxicityCategories = list[ToxicityCategory]


class ToxicityDetectionSettings(TypedDict, total=False):
    ToxicityCategories: ToxicityCategories


ToxicityDetection = list[ToxicityDetectionSettings]
SubtitleFileUris = list[Uri]
SubtitleFormats = list[SubtitleFormat]


class SubtitlesOutput(TypedDict, total=False):
    Formats: SubtitleFormats | None
    SubtitleFileUris: SubtitleFileUris | None
    OutputStartIndex: SubtitleOutputStartIndex | None


class LanguageCodeItem(TypedDict, total=False):
    LanguageCode: LanguageCode | None
    DurationInSeconds: DurationInSeconds | None


LanguageCodeList = list[LanguageCodeItem]


class JobExecutionSettings(TypedDict, total=False):
    AllowDeferredExecution: Boolean | None
    DataAccessRoleArn: DataAccessRoleArn | None


class ModelSettings(TypedDict, total=False):
    LanguageModelName: ModelName | None


class Settings(TypedDict, total=False):
    VocabularyName: VocabularyName | None
    ShowSpeakerLabels: Boolean | None
    MaxSpeakerLabels: MaxSpeakers | None
    ChannelIdentification: Boolean | None
    ShowAlternatives: Boolean | None
    MaxAlternatives: MaxAlternatives | None
    VocabularyFilterName: VocabularyFilterName | None
    VocabularyFilterMethod: VocabularyFilterMethod | None


class TranscriptionJob(TypedDict, total=False):
    TranscriptionJobName: TranscriptionJobName | None
    TranscriptionJobStatus: TranscriptionJobStatus | None
    LanguageCode: LanguageCode | None
    MediaSampleRateHertz: MediaSampleRateHertz | None
    MediaFormat: MediaFormat | None
    Media: Media | None
    Transcript: Transcript | None
    StartTime: DateTime | None
    CreationTime: DateTime | None
    CompletionTime: DateTime | None
    FailureReason: FailureReason | None
    Settings: Settings | None
    ModelSettings: ModelSettings | None
    JobExecutionSettings: JobExecutionSettings | None
    ContentRedaction: ContentRedaction | None
    IdentifyLanguage: Boolean | None
    IdentifyMultipleLanguages: Boolean | None
    LanguageOptions: LanguageOptions | None
    IdentifiedLanguageScore: IdentifiedLanguageScore | None
    LanguageCodes: LanguageCodeList | None
    Tags: TagList | None
    Subtitles: SubtitlesOutput | None
    LanguageIdSettings: LanguageIdSettingsMap | None
    ToxicityDetection: ToxicityDetection | None


class GetTranscriptionJobResponse(TypedDict, total=False):
    TranscriptionJob: TranscriptionJob | None


class GetVocabularyFilterRequest(ServiceRequest):
    VocabularyFilterName: VocabularyFilterName


class GetVocabularyFilterResponse(TypedDict, total=False):
    VocabularyFilterName: VocabularyFilterName | None
    LanguageCode: LanguageCode | None
    LastModifiedTime: DateTime | None
    DownloadUri: Uri | None


class GetVocabularyRequest(ServiceRequest):
    VocabularyName: VocabularyName


class GetVocabularyResponse(TypedDict, total=False):
    VocabularyName: VocabularyName | None
    LanguageCode: LanguageCode | None
    VocabularyState: VocabularyState | None
    LastModifiedTime: DateTime | None
    FailureReason: FailureReason | None
    DownloadUri: Uri | None


KMSEncryptionContextMap = dict[NonEmptyString, NonEmptyString]


class ListCallAnalyticsCategoriesRequest(ServiceRequest):
    NextToken: NextToken | None
    MaxResults: MaxResults | None


class ListCallAnalyticsCategoriesResponse(TypedDict, total=False):
    NextToken: NextToken | None
    Categories: CategoryPropertiesList | None


class ListCallAnalyticsJobsRequest(ServiceRequest):
    Status: CallAnalyticsJobStatus | None
    JobNameContains: CallAnalyticsJobName | None
    NextToken: NextToken | None
    MaxResults: MaxResults | None


class ListCallAnalyticsJobsResponse(TypedDict, total=False):
    Status: CallAnalyticsJobStatus | None
    NextToken: NextToken | None
    CallAnalyticsJobSummaries: CallAnalyticsJobSummaries | None


class ListLanguageModelsRequest(ServiceRequest):
    StatusEquals: ModelStatus | None
    NameContains: ModelName | None
    NextToken: NextToken | None
    MaxResults: MaxResults | None


Models = list[LanguageModel]


class ListLanguageModelsResponse(TypedDict, total=False):
    NextToken: NextToken | None
    Models: Models | None


class ListMedicalScribeJobsRequest(ServiceRequest):
    Status: MedicalScribeJobStatus | None
    JobNameContains: TranscriptionJobName | None
    NextToken: NextToken | None
    MaxResults: MaxResults | None


class MedicalScribeJobSummary(TypedDict, total=False):
    MedicalScribeJobName: TranscriptionJobName | None
    CreationTime: DateTime | None
    StartTime: DateTime | None
    CompletionTime: DateTime | None
    LanguageCode: MedicalScribeLanguageCode | None
    MedicalScribeJobStatus: MedicalScribeJobStatus | None
    FailureReason: FailureReason | None


MedicalScribeJobSummaries = list[MedicalScribeJobSummary]


class ListMedicalScribeJobsResponse(TypedDict, total=False):
    Status: MedicalScribeJobStatus | None
    NextToken: NextToken | None
    MedicalScribeJobSummaries: MedicalScribeJobSummaries | None


class ListMedicalTranscriptionJobsRequest(ServiceRequest):
    Status: TranscriptionJobStatus | None
    JobNameContains: TranscriptionJobName | None
    NextToken: NextToken | None
    MaxResults: MaxResults | None


class MedicalTranscriptionJobSummary(TypedDict, total=False):
    MedicalTranscriptionJobName: TranscriptionJobName | None
    CreationTime: DateTime | None
    StartTime: DateTime | None
    CompletionTime: DateTime | None
    LanguageCode: LanguageCode | None
    TranscriptionJobStatus: TranscriptionJobStatus | None
    FailureReason: FailureReason | None
    OutputLocationType: OutputLocationType | None
    Specialty: Specialty | None
    ContentIdentificationType: MedicalContentIdentificationType | None
    Type: Type | None


MedicalTranscriptionJobSummaries = list[MedicalTranscriptionJobSummary]


class ListMedicalTranscriptionJobsResponse(TypedDict, total=False):
    Status: TranscriptionJobStatus | None
    NextToken: NextToken | None
    MedicalTranscriptionJobSummaries: MedicalTranscriptionJobSummaries | None


class ListMedicalVocabulariesRequest(ServiceRequest):
    NextToken: NextToken | None
    MaxResults: MaxResults | None
    StateEquals: VocabularyState | None
    NameContains: VocabularyName | None


class VocabularyInfo(TypedDict, total=False):
    VocabularyName: VocabularyName | None
    LanguageCode: LanguageCode | None
    LastModifiedTime: DateTime | None
    VocabularyState: VocabularyState | None


Vocabularies = list[VocabularyInfo]


class ListMedicalVocabulariesResponse(TypedDict, total=False):
    Status: VocabularyState | None
    NextToken: NextToken | None
    Vocabularies: Vocabularies | None


class ListTagsForResourceRequest(ServiceRequest):
    ResourceArn: TranscribeArn


class ListTagsForResourceResponse(TypedDict, total=False):
    ResourceArn: TranscribeArn | None
    Tags: TagList | None


class ListTranscriptionJobsRequest(ServiceRequest):
    Status: TranscriptionJobStatus | None
    JobNameContains: TranscriptionJobName | None
    NextToken: NextToken | None
    MaxResults: MaxResults | None


class TranscriptionJobSummary(TypedDict, total=False):
    TranscriptionJobName: TranscriptionJobName | None
    CreationTime: DateTime | None
    StartTime: DateTime | None
    CompletionTime: DateTime | None
    LanguageCode: LanguageCode | None
    TranscriptionJobStatus: TranscriptionJobStatus | None
    FailureReason: FailureReason | None
    OutputLocationType: OutputLocationType | None
    ContentRedaction: ContentRedaction | None
    ModelSettings: ModelSettings | None
    IdentifyLanguage: Boolean | None
    IdentifyMultipleLanguages: Boolean | None
    IdentifiedLanguageScore: IdentifiedLanguageScore | None
    LanguageCodes: LanguageCodeList | None
    ToxicityDetection: ToxicityDetection | None


TranscriptionJobSummaries = list[TranscriptionJobSummary]


class ListTranscriptionJobsResponse(TypedDict, total=False):
    Status: TranscriptionJobStatus | None
    NextToken: NextToken | None
    TranscriptionJobSummaries: TranscriptionJobSummaries | None


class ListVocabulariesRequest(ServiceRequest):
    NextToken: NextToken | None
    MaxResults: MaxResults | None
    StateEquals: VocabularyState | None
    NameContains: VocabularyName | None


class ListVocabulariesResponse(TypedDict, total=False):
    Status: VocabularyState | None
    NextToken: NextToken | None
    Vocabularies: Vocabularies | None


class ListVocabularyFiltersRequest(ServiceRequest):
    NextToken: NextToken | None
    MaxResults: MaxResults | None
    NameContains: VocabularyFilterName | None


class VocabularyFilterInfo(TypedDict, total=False):
    VocabularyFilterName: VocabularyFilterName | None
    LanguageCode: LanguageCode | None
    LastModifiedTime: DateTime | None


VocabularyFilters = list[VocabularyFilterInfo]


class ListVocabularyFiltersResponse(TypedDict, total=False):
    NextToken: NextToken | None
    VocabularyFilters: VocabularyFilters | None


class MedicalScribePatientContext(TypedDict, total=False):
    Pronouns: Pronouns | None


class MedicalScribeContext(TypedDict, total=False):
    PatientContext: MedicalScribePatientContext | None


class StartCallAnalyticsJobRequest(ServiceRequest):
    CallAnalyticsJobName: CallAnalyticsJobName
    Media: Media
    OutputLocation: Uri | None
    OutputEncryptionKMSKeyId: KMSKeyId | None
    DataAccessRoleArn: DataAccessRoleArn | None
    Settings: CallAnalyticsJobSettings | None
    Tags: TagList | None
    ChannelDefinitions: ChannelDefinitions | None


class StartCallAnalyticsJobResponse(TypedDict, total=False):
    CallAnalyticsJob: CallAnalyticsJob | None


class StartMedicalScribeJobRequest(ServiceRequest):
    MedicalScribeJobName: TranscriptionJobName
    Media: Media
    OutputBucketName: OutputBucketName
    OutputEncryptionKMSKeyId: KMSKeyId | None
    KMSEncryptionContext: KMSEncryptionContextMap | None
    DataAccessRoleArn: DataAccessRoleArn
    Settings: MedicalScribeSettings
    ChannelDefinitions: MedicalScribeChannelDefinitions | None
    Tags: TagList | None
    MedicalScribeContext: MedicalScribeContext | None


class StartMedicalScribeJobResponse(TypedDict, total=False):
    MedicalScribeJob: MedicalScribeJob | None


class StartMedicalTranscriptionJobRequest(ServiceRequest):
    MedicalTranscriptionJobName: TranscriptionJobName
    LanguageCode: LanguageCode
    MediaSampleRateHertz: MedicalMediaSampleRateHertz | None
    MediaFormat: MediaFormat | None
    Media: Media
    OutputBucketName: OutputBucketName
    OutputKey: OutputKey | None
    OutputEncryptionKMSKeyId: KMSKeyId | None
    KMSEncryptionContext: KMSEncryptionContextMap | None
    Settings: MedicalTranscriptionSetting | None
    ContentIdentificationType: MedicalContentIdentificationType | None
    Specialty: Specialty
    Type: Type
    Tags: TagList | None


class StartMedicalTranscriptionJobResponse(TypedDict, total=False):
    MedicalTranscriptionJob: MedicalTranscriptionJob | None


class Subtitles(TypedDict, total=False):
    Formats: SubtitleFormats | None
    OutputStartIndex: SubtitleOutputStartIndex | None


class StartTranscriptionJobRequest(ServiceRequest):
    TranscriptionJobName: TranscriptionJobName
    LanguageCode: LanguageCode | None
    MediaSampleRateHertz: MediaSampleRateHertz | None
    MediaFormat: MediaFormat | None
    Media: Media
    OutputBucketName: OutputBucketName | None
    OutputKey: OutputKey | None
    OutputEncryptionKMSKeyId: KMSKeyId | None
    KMSEncryptionContext: KMSEncryptionContextMap | None
    Settings: Settings | None
    ModelSettings: ModelSettings | None
    JobExecutionSettings: JobExecutionSettings | None
    ContentRedaction: ContentRedaction | None
    IdentifyLanguage: Boolean | None
    IdentifyMultipleLanguages: Boolean | None
    LanguageOptions: LanguageOptions | None
    Subtitles: Subtitles | None
    Tags: TagList | None
    LanguageIdSettings: LanguageIdSettingsMap | None
    ToxicityDetection: ToxicityDetection | None


class StartTranscriptionJobResponse(TypedDict, total=False):
    TranscriptionJob: TranscriptionJob | None


TagKeyList = list[TagKey]


class TagResourceRequest(ServiceRequest):
    ResourceArn: TranscribeArn
    Tags: TagList


class TagResourceResponse(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    ResourceArn: TranscribeArn
    TagKeys: TagKeyList


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateCallAnalyticsCategoryRequest(ServiceRequest):
    CategoryName: CategoryName
    Rules: RuleList
    InputType: InputType | None


class UpdateCallAnalyticsCategoryResponse(TypedDict, total=False):
    CategoryProperties: CategoryProperties | None


class UpdateMedicalVocabularyRequest(ServiceRequest):
    VocabularyName: VocabularyName
    LanguageCode: LanguageCode
    VocabularyFileUri: Uri


class UpdateMedicalVocabularyResponse(TypedDict, total=False):
    VocabularyName: VocabularyName | None
    LanguageCode: LanguageCode | None
    LastModifiedTime: DateTime | None
    VocabularyState: VocabularyState | None


class UpdateVocabularyFilterRequest(ServiceRequest):
    VocabularyFilterName: VocabularyFilterName
    Words: Words | None
    VocabularyFilterFileUri: Uri | None
    DataAccessRoleArn: DataAccessRoleArn | None


class UpdateVocabularyFilterResponse(TypedDict, total=False):
    VocabularyFilterName: VocabularyFilterName | None
    LanguageCode: LanguageCode | None
    LastModifiedTime: DateTime | None


class UpdateVocabularyRequest(ServiceRequest):
    VocabularyName: VocabularyName
    LanguageCode: LanguageCode
    Phrases: Phrases | None
    VocabularyFileUri: Uri | None
    DataAccessRoleArn: DataAccessRoleArn | None


class UpdateVocabularyResponse(TypedDict, total=False):
    VocabularyName: VocabularyName | None
    LanguageCode: LanguageCode | None
    LastModifiedTime: DateTime | None
    VocabularyState: VocabularyState | None


class TranscribeApi:
    service: str = "transcribe"
    version: str = "2017-10-26"

    @handler("CreateCallAnalyticsCategory")
    def create_call_analytics_category(
        self,
        context: RequestContext,
        category_name: CategoryName,
        rules: RuleList,
        tags: TagList | None = None,
        input_type: InputType | None = None,
        **kwargs,
    ) -> CreateCallAnalyticsCategoryResponse:
        raise NotImplementedError

    @handler("CreateLanguageModel")
    def create_language_model(
        self,
        context: RequestContext,
        language_code: CLMLanguageCode,
        base_model_name: BaseModelName,
        model_name: ModelName,
        input_data_config: InputDataConfig,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateLanguageModelResponse:
        raise NotImplementedError

    @handler("CreateMedicalVocabulary")
    def create_medical_vocabulary(
        self,
        context: RequestContext,
        vocabulary_name: VocabularyName,
        language_code: LanguageCode,
        vocabulary_file_uri: Uri,
        tags: TagList | None = None,
        **kwargs,
    ) -> CreateMedicalVocabularyResponse:
        raise NotImplementedError

    @handler("CreateVocabulary")
    def create_vocabulary(
        self,
        context: RequestContext,
        vocabulary_name: VocabularyName,
        language_code: LanguageCode,
        phrases: Phrases | None = None,
        vocabulary_file_uri: Uri | None = None,
        tags: TagList | None = None,
        data_access_role_arn: DataAccessRoleArn | None = None,
        **kwargs,
    ) -> CreateVocabularyResponse:
        raise NotImplementedError

    @handler("CreateVocabularyFilter")
    def create_vocabulary_filter(
        self,
        context: RequestContext,
        vocabulary_filter_name: VocabularyFilterName,
        language_code: LanguageCode,
        words: Words | None = None,
        vocabulary_filter_file_uri: Uri | None = None,
        tags: TagList | None = None,
        data_access_role_arn: DataAccessRoleArn | None = None,
        **kwargs,
    ) -> CreateVocabularyFilterResponse:
        raise NotImplementedError

    @handler("DeleteCallAnalyticsCategory")
    def delete_call_analytics_category(
        self, context: RequestContext, category_name: CategoryName, **kwargs
    ) -> DeleteCallAnalyticsCategoryResponse:
        raise NotImplementedError

    @handler("DeleteCallAnalyticsJob")
    def delete_call_analytics_job(
        self, context: RequestContext, call_analytics_job_name: CallAnalyticsJobName, **kwargs
    ) -> DeleteCallAnalyticsJobResponse:
        raise NotImplementedError

    @handler("DeleteLanguageModel")
    def delete_language_model(
        self, context: RequestContext, model_name: ModelName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteMedicalScribeJob")
    def delete_medical_scribe_job(
        self, context: RequestContext, medical_scribe_job_name: TranscriptionJobName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteMedicalTranscriptionJob")
    def delete_medical_transcription_job(
        self,
        context: RequestContext,
        medical_transcription_job_name: TranscriptionJobName,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteMedicalVocabulary")
    def delete_medical_vocabulary(
        self, context: RequestContext, vocabulary_name: VocabularyName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteTranscriptionJob")
    def delete_transcription_job(
        self, context: RequestContext, transcription_job_name: TranscriptionJobName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteVocabulary")
    def delete_vocabulary(
        self, context: RequestContext, vocabulary_name: VocabularyName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteVocabularyFilter")
    def delete_vocabulary_filter(
        self, context: RequestContext, vocabulary_filter_name: VocabularyFilterName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DescribeLanguageModel")
    def describe_language_model(
        self, context: RequestContext, model_name: ModelName, **kwargs
    ) -> DescribeLanguageModelResponse:
        raise NotImplementedError

    @handler("GetCallAnalyticsCategory")
    def get_call_analytics_category(
        self, context: RequestContext, category_name: CategoryName, **kwargs
    ) -> GetCallAnalyticsCategoryResponse:
        raise NotImplementedError

    @handler("GetCallAnalyticsJob")
    def get_call_analytics_job(
        self, context: RequestContext, call_analytics_job_name: CallAnalyticsJobName, **kwargs
    ) -> GetCallAnalyticsJobResponse:
        raise NotImplementedError

    @handler("GetMedicalScribeJob")
    def get_medical_scribe_job(
        self, context: RequestContext, medical_scribe_job_name: TranscriptionJobName, **kwargs
    ) -> GetMedicalScribeJobResponse:
        raise NotImplementedError

    @handler("GetMedicalTranscriptionJob")
    def get_medical_transcription_job(
        self,
        context: RequestContext,
        medical_transcription_job_name: TranscriptionJobName,
        **kwargs,
    ) -> GetMedicalTranscriptionJobResponse:
        raise NotImplementedError

    @handler("GetMedicalVocabulary")
    def get_medical_vocabulary(
        self, context: RequestContext, vocabulary_name: VocabularyName, **kwargs
    ) -> GetMedicalVocabularyResponse:
        raise NotImplementedError

    @handler("GetTranscriptionJob")
    def get_transcription_job(
        self, context: RequestContext, transcription_job_name: TranscriptionJobName, **kwargs
    ) -> GetTranscriptionJobResponse:
        raise NotImplementedError

    @handler("GetVocabulary")
    def get_vocabulary(
        self, context: RequestContext, vocabulary_name: VocabularyName, **kwargs
    ) -> GetVocabularyResponse:
        raise NotImplementedError

    @handler("GetVocabularyFilter")
    def get_vocabulary_filter(
        self, context: RequestContext, vocabulary_filter_name: VocabularyFilterName, **kwargs
    ) -> GetVocabularyFilterResponse:
        raise NotImplementedError

    @handler("ListCallAnalyticsCategories")
    def list_call_analytics_categories(
        self,
        context: RequestContext,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListCallAnalyticsCategoriesResponse:
        raise NotImplementedError

    @handler("ListCallAnalyticsJobs")
    def list_call_analytics_jobs(
        self,
        context: RequestContext,
        status: CallAnalyticsJobStatus | None = None,
        job_name_contains: CallAnalyticsJobName | None = None,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListCallAnalyticsJobsResponse:
        raise NotImplementedError

    @handler("ListLanguageModels")
    def list_language_models(
        self,
        context: RequestContext,
        status_equals: ModelStatus | None = None,
        name_contains: ModelName | None = None,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListLanguageModelsResponse:
        raise NotImplementedError

    @handler("ListMedicalScribeJobs")
    def list_medical_scribe_jobs(
        self,
        context: RequestContext,
        status: MedicalScribeJobStatus | None = None,
        job_name_contains: TranscriptionJobName | None = None,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListMedicalScribeJobsResponse:
        raise NotImplementedError

    @handler("ListMedicalTranscriptionJobs")
    def list_medical_transcription_jobs(
        self,
        context: RequestContext,
        status: TranscriptionJobStatus | None = None,
        job_name_contains: TranscriptionJobName | None = None,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListMedicalTranscriptionJobsResponse:
        raise NotImplementedError

    @handler("ListMedicalVocabularies")
    def list_medical_vocabularies(
        self,
        context: RequestContext,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        state_equals: VocabularyState | None = None,
        name_contains: VocabularyName | None = None,
        **kwargs,
    ) -> ListMedicalVocabulariesResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: TranscribeArn, **kwargs
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ListTranscriptionJobs")
    def list_transcription_jobs(
        self,
        context: RequestContext,
        status: TranscriptionJobStatus | None = None,
        job_name_contains: TranscriptionJobName | None = None,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListTranscriptionJobsResponse:
        raise NotImplementedError

    @handler("ListVocabularies")
    def list_vocabularies(
        self,
        context: RequestContext,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        state_equals: VocabularyState | None = None,
        name_contains: VocabularyName | None = None,
        **kwargs,
    ) -> ListVocabulariesResponse:
        raise NotImplementedError

    @handler("ListVocabularyFilters")
    def list_vocabulary_filters(
        self,
        context: RequestContext,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        name_contains: VocabularyFilterName | None = None,
        **kwargs,
    ) -> ListVocabularyFiltersResponse:
        raise NotImplementedError

    @handler("StartCallAnalyticsJob")
    def start_call_analytics_job(
        self,
        context: RequestContext,
        call_analytics_job_name: CallAnalyticsJobName,
        media: Media,
        output_location: Uri | None = None,
        output_encryption_kms_key_id: KMSKeyId | None = None,
        data_access_role_arn: DataAccessRoleArn | None = None,
        settings: CallAnalyticsJobSettings | None = None,
        tags: TagList | None = None,
        channel_definitions: ChannelDefinitions | None = None,
        **kwargs,
    ) -> StartCallAnalyticsJobResponse:
        raise NotImplementedError

    @handler("StartMedicalScribeJob")
    def start_medical_scribe_job(
        self,
        context: RequestContext,
        medical_scribe_job_name: TranscriptionJobName,
        media: Media,
        output_bucket_name: OutputBucketName,
        data_access_role_arn: DataAccessRoleArn,
        settings: MedicalScribeSettings,
        output_encryption_kms_key_id: KMSKeyId | None = None,
        kms_encryption_context: KMSEncryptionContextMap | None = None,
        channel_definitions: MedicalScribeChannelDefinitions | None = None,
        tags: TagList | None = None,
        medical_scribe_context: MedicalScribeContext | None = None,
        **kwargs,
    ) -> StartMedicalScribeJobResponse:
        raise NotImplementedError

    @handler("StartMedicalTranscriptionJob", expand=False)
    def start_medical_transcription_job(
        self, context: RequestContext, request: StartMedicalTranscriptionJobRequest, **kwargs
    ) -> StartMedicalTranscriptionJobResponse:
        raise NotImplementedError

    @handler("StartTranscriptionJob")
    def start_transcription_job(
        self,
        context: RequestContext,
        transcription_job_name: TranscriptionJobName,
        media: Media,
        language_code: LanguageCode | None = None,
        media_sample_rate_hertz: MediaSampleRateHertz | None = None,
        media_format: MediaFormat | None = None,
        output_bucket_name: OutputBucketName | None = None,
        output_key: OutputKey | None = None,
        output_encryption_kms_key_id: KMSKeyId | None = None,
        kms_encryption_context: KMSEncryptionContextMap | None = None,
        settings: Settings | None = None,
        model_settings: ModelSettings | None = None,
        job_execution_settings: JobExecutionSettings | None = None,
        content_redaction: ContentRedaction | None = None,
        identify_language: Boolean | None = None,
        identify_multiple_languages: Boolean | None = None,
        language_options: LanguageOptions | None = None,
        subtitles: Subtitles | None = None,
        tags: TagList | None = None,
        language_id_settings: LanguageIdSettingsMap | None = None,
        toxicity_detection: ToxicityDetection | None = None,
        **kwargs,
    ) -> StartTranscriptionJobResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: TranscribeArn, tags: TagList, **kwargs
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: TranscribeArn, tag_keys: TagKeyList, **kwargs
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateCallAnalyticsCategory")
    def update_call_analytics_category(
        self,
        context: RequestContext,
        category_name: CategoryName,
        rules: RuleList,
        input_type: InputType | None = None,
        **kwargs,
    ) -> UpdateCallAnalyticsCategoryResponse:
        raise NotImplementedError

    @handler("UpdateMedicalVocabulary")
    def update_medical_vocabulary(
        self,
        context: RequestContext,
        vocabulary_name: VocabularyName,
        language_code: LanguageCode,
        vocabulary_file_uri: Uri,
        **kwargs,
    ) -> UpdateMedicalVocabularyResponse:
        raise NotImplementedError

    @handler("UpdateVocabulary")
    def update_vocabulary(
        self,
        context: RequestContext,
        vocabulary_name: VocabularyName,
        language_code: LanguageCode,
        phrases: Phrases | None = None,
        vocabulary_file_uri: Uri | None = None,
        data_access_role_arn: DataAccessRoleArn | None = None,
        **kwargs,
    ) -> UpdateVocabularyResponse:
        raise NotImplementedError

    @handler("UpdateVocabularyFilter")
    def update_vocabulary_filter(
        self,
        context: RequestContext,
        vocabulary_filter_name: VocabularyFilterName,
        words: Words | None = None,
        vocabulary_filter_file_uri: Uri | None = None,
        data_access_role_arn: DataAccessRoleArn | None = None,
        **kwargs,
    ) -> UpdateVocabularyFilterResponse:
        raise NotImplementedError
