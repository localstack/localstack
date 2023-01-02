import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

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


class BaseModelName(str):
    NarrowBand = "NarrowBand"
    WideBand = "WideBand"


class CLMLanguageCode(str):
    en_US = "en-US"
    hi_IN = "hi-IN"
    es_US = "es-US"
    en_GB = "en-GB"
    en_AU = "en-AU"
    de_DE = "de-DE"
    ja_JP = "ja-JP"


class CallAnalyticsJobStatus(str):
    QUEUED = "QUEUED"
    IN_PROGRESS = "IN_PROGRESS"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"


class InputType(str):
    REAL_TIME = "REAL_TIME"
    POST_CALL = "POST_CALL"


class LanguageCode(str):
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


class MediaFormat(str):
    mp3 = "mp3"
    mp4 = "mp4"
    wav = "wav"
    flac = "flac"
    ogg = "ogg"
    amr = "amr"
    webm = "webm"


class MedicalContentIdentificationType(str):
    PHI = "PHI"


class ModelStatus(str):
    IN_PROGRESS = "IN_PROGRESS"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"


class OutputLocationType(str):
    CUSTOMER_BUCKET = "CUSTOMER_BUCKET"
    SERVICE_BUCKET = "SERVICE_BUCKET"


class ParticipantRole(str):
    AGENT = "AGENT"
    CUSTOMER = "CUSTOMER"


class PiiEntityType(str):
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


class RedactionOutput(str):
    redacted = "redacted"
    redacted_and_unredacted = "redacted_and_unredacted"


class RedactionType(str):
    PII = "PII"


class SentimentValue(str):
    POSITIVE = "POSITIVE"
    NEGATIVE = "NEGATIVE"
    NEUTRAL = "NEUTRAL"
    MIXED = "MIXED"


class Specialty(str):
    PRIMARYCARE = "PRIMARYCARE"


class SubtitleFormat(str):
    vtt = "vtt"
    srt = "srt"


class TranscriptFilterType(str):
    EXACT = "EXACT"


class TranscriptionJobStatus(str):
    QUEUED = "QUEUED"
    IN_PROGRESS = "IN_PROGRESS"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"


class Type(str):
    CONVERSATION = "CONVERSATION"
    DICTATION = "DICTATION"


class VocabularyFilterMethod(str):
    remove = "remove"
    mask = "mask"
    tag = "tag"


class VocabularyState(str):
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
    StartTime: Optional[TimestampMilliseconds]
    EndTime: Optional[TimestampMilliseconds]
    First: Optional[TimestampMilliseconds]
    Last: Optional[TimestampMilliseconds]


class ChannelDefinition(TypedDict, total=False):
    ChannelId: Optional[ChannelId]
    ParticipantRole: Optional[ParticipantRole]


ChannelDefinitions = List[ChannelDefinition]


class LanguageIdSettings(TypedDict, total=False):
    VocabularyName: Optional[VocabularyName]
    VocabularyFilterName: Optional[VocabularyFilterName]
    LanguageModelName: Optional[ModelName]


LanguageIdSettingsMap = Dict[LanguageCode, LanguageIdSettings]
LanguageOptions = List[LanguageCode]
PiiEntityTypes = List[PiiEntityType]


class ContentRedaction(TypedDict, total=False):
    RedactionType: RedactionType
    RedactionOutput: RedactionOutput
    PiiEntityTypes: Optional[PiiEntityTypes]


class CallAnalyticsJobSettings(TypedDict, total=False):
    VocabularyName: Optional[VocabularyName]
    VocabularyFilterName: Optional[VocabularyFilterName]
    VocabularyFilterMethod: Optional[VocabularyFilterMethod]
    LanguageModelName: Optional[ModelName]
    ContentRedaction: Optional[ContentRedaction]
    LanguageOptions: Optional[LanguageOptions]
    LanguageIdSettings: Optional[LanguageIdSettingsMap]


DateTime = datetime


class Transcript(TypedDict, total=False):
    TranscriptFileUri: Optional[Uri]
    RedactedTranscriptFileUri: Optional[Uri]


class Media(TypedDict, total=False):
    MediaFileUri: Optional[Uri]
    RedactedMediaFileUri: Optional[Uri]


class CallAnalyticsJob(TypedDict, total=False):
    CallAnalyticsJobName: Optional[CallAnalyticsJobName]
    CallAnalyticsJobStatus: Optional[CallAnalyticsJobStatus]
    LanguageCode: Optional[LanguageCode]
    MediaSampleRateHertz: Optional[MediaSampleRateHertz]
    MediaFormat: Optional[MediaFormat]
    Media: Optional[Media]
    Transcript: Optional[Transcript]
    StartTime: Optional[DateTime]
    CreationTime: Optional[DateTime]
    CompletionTime: Optional[DateTime]
    FailureReason: Optional[FailureReason]
    DataAccessRoleArn: Optional[DataAccessRoleArn]
    IdentifiedLanguageScore: Optional[IdentifiedLanguageScore]
    Settings: Optional[CallAnalyticsJobSettings]
    ChannelDefinitions: Optional[ChannelDefinitions]


class CallAnalyticsJobSummary(TypedDict, total=False):
    CallAnalyticsJobName: Optional[CallAnalyticsJobName]
    CreationTime: Optional[DateTime]
    StartTime: Optional[DateTime]
    CompletionTime: Optional[DateTime]
    LanguageCode: Optional[LanguageCode]
    CallAnalyticsJobStatus: Optional[CallAnalyticsJobStatus]
    FailureReason: Optional[FailureReason]


CallAnalyticsJobSummaries = List[CallAnalyticsJobSummary]


class RelativeTimeRange(TypedDict, total=False):
    StartPercentage: Optional[Percentage]
    EndPercentage: Optional[Percentage]
    First: Optional[Percentage]
    Last: Optional[Percentage]


SentimentValueList = List[SentimentValue]


class SentimentFilter(TypedDict, total=False):
    Sentiments: SentimentValueList
    AbsoluteTimeRange: Optional[AbsoluteTimeRange]
    RelativeTimeRange: Optional[RelativeTimeRange]
    ParticipantRole: Optional[ParticipantRole]
    Negate: Optional[Boolean]


StringTargetList = List[NonEmptyString]


class TranscriptFilter(TypedDict, total=False):
    TranscriptFilterType: TranscriptFilterType
    AbsoluteTimeRange: Optional[AbsoluteTimeRange]
    RelativeTimeRange: Optional[RelativeTimeRange]
    ParticipantRole: Optional[ParticipantRole]
    Negate: Optional[Boolean]
    Targets: StringTargetList


class InterruptionFilter(TypedDict, total=False):
    Threshold: Optional[TimestampMilliseconds]
    ParticipantRole: Optional[ParticipantRole]
    AbsoluteTimeRange: Optional[AbsoluteTimeRange]
    RelativeTimeRange: Optional[RelativeTimeRange]
    Negate: Optional[Boolean]


class NonTalkTimeFilter(TypedDict, total=False):
    Threshold: Optional[TimestampMilliseconds]
    AbsoluteTimeRange: Optional[AbsoluteTimeRange]
    RelativeTimeRange: Optional[RelativeTimeRange]
    Negate: Optional[Boolean]


class Rule(TypedDict, total=False):
    NonTalkTimeFilter: Optional[NonTalkTimeFilter]
    InterruptionFilter: Optional[InterruptionFilter]
    TranscriptFilter: Optional[TranscriptFilter]
    SentimentFilter: Optional[SentimentFilter]


RuleList = List[Rule]


class CategoryProperties(TypedDict, total=False):
    CategoryName: Optional[CategoryName]
    Rules: Optional[RuleList]
    CreateTime: Optional[DateTime]
    LastUpdateTime: Optional[DateTime]
    InputType: Optional[InputType]


CategoryPropertiesList = List[CategoryProperties]


class CreateCallAnalyticsCategoryRequest(ServiceRequest):
    CategoryName: CategoryName
    Rules: RuleList
    InputType: Optional[InputType]


class CreateCallAnalyticsCategoryResponse(TypedDict, total=False):
    CategoryProperties: Optional[CategoryProperties]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = List[Tag]


class InputDataConfig(TypedDict, total=False):
    S3Uri: Uri
    TuningDataS3Uri: Optional[Uri]
    DataAccessRoleArn: DataAccessRoleArn


class CreateLanguageModelRequest(ServiceRequest):
    LanguageCode: CLMLanguageCode
    BaseModelName: BaseModelName
    ModelName: ModelName
    InputDataConfig: InputDataConfig
    Tags: Optional[TagList]


class CreateLanguageModelResponse(TypedDict, total=False):
    LanguageCode: Optional[CLMLanguageCode]
    BaseModelName: Optional[BaseModelName]
    ModelName: Optional[ModelName]
    InputDataConfig: Optional[InputDataConfig]
    ModelStatus: Optional[ModelStatus]


class CreateMedicalVocabularyRequest(ServiceRequest):
    VocabularyName: VocabularyName
    LanguageCode: LanguageCode
    VocabularyFileUri: Uri
    Tags: Optional[TagList]


class CreateMedicalVocabularyResponse(TypedDict, total=False):
    VocabularyName: Optional[VocabularyName]
    LanguageCode: Optional[LanguageCode]
    VocabularyState: Optional[VocabularyState]
    LastModifiedTime: Optional[DateTime]
    FailureReason: Optional[FailureReason]


Words = List[Word]


class CreateVocabularyFilterRequest(ServiceRequest):
    VocabularyFilterName: VocabularyFilterName
    LanguageCode: LanguageCode
    Words: Optional[Words]
    VocabularyFilterFileUri: Optional[Uri]
    Tags: Optional[TagList]


class CreateVocabularyFilterResponse(TypedDict, total=False):
    VocabularyFilterName: Optional[VocabularyFilterName]
    LanguageCode: Optional[LanguageCode]
    LastModifiedTime: Optional[DateTime]


Phrases = List[Phrase]


class CreateVocabularyRequest(ServiceRequest):
    VocabularyName: VocabularyName
    LanguageCode: LanguageCode
    Phrases: Optional[Phrases]
    VocabularyFileUri: Optional[Uri]
    Tags: Optional[TagList]


class CreateVocabularyResponse(TypedDict, total=False):
    VocabularyName: Optional[VocabularyName]
    LanguageCode: Optional[LanguageCode]
    VocabularyState: Optional[VocabularyState]
    LastModifiedTime: Optional[DateTime]
    FailureReason: Optional[FailureReason]


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
    ModelName: Optional[ModelName]
    CreateTime: Optional[DateTime]
    LastModifiedTime: Optional[DateTime]
    LanguageCode: Optional[CLMLanguageCode]
    BaseModelName: Optional[BaseModelName]
    ModelStatus: Optional[ModelStatus]
    UpgradeAvailability: Optional[Boolean]
    FailureReason: Optional[FailureReason]
    InputDataConfig: Optional[InputDataConfig]


class DescribeLanguageModelResponse(TypedDict, total=False):
    LanguageModel: Optional[LanguageModel]


class GetCallAnalyticsCategoryRequest(ServiceRequest):
    CategoryName: CategoryName


class GetCallAnalyticsCategoryResponse(TypedDict, total=False):
    CategoryProperties: Optional[CategoryProperties]


class GetCallAnalyticsJobRequest(ServiceRequest):
    CallAnalyticsJobName: CallAnalyticsJobName


class GetCallAnalyticsJobResponse(TypedDict, total=False):
    CallAnalyticsJob: Optional[CallAnalyticsJob]


class GetMedicalTranscriptionJobRequest(ServiceRequest):
    MedicalTranscriptionJobName: TranscriptionJobName


class MedicalTranscriptionSetting(TypedDict, total=False):
    ShowSpeakerLabels: Optional[Boolean]
    MaxSpeakerLabels: Optional[MaxSpeakers]
    ChannelIdentification: Optional[Boolean]
    ShowAlternatives: Optional[Boolean]
    MaxAlternatives: Optional[MaxAlternatives]
    VocabularyName: Optional[VocabularyName]


class MedicalTranscript(TypedDict, total=False):
    TranscriptFileUri: Optional[Uri]


class MedicalTranscriptionJob(TypedDict, total=False):
    MedicalTranscriptionJobName: Optional[TranscriptionJobName]
    TranscriptionJobStatus: Optional[TranscriptionJobStatus]
    LanguageCode: Optional[LanguageCode]
    MediaSampleRateHertz: Optional[MedicalMediaSampleRateHertz]
    MediaFormat: Optional[MediaFormat]
    Media: Optional[Media]
    Transcript: Optional[MedicalTranscript]
    StartTime: Optional[DateTime]
    CreationTime: Optional[DateTime]
    CompletionTime: Optional[DateTime]
    FailureReason: Optional[FailureReason]
    Settings: Optional[MedicalTranscriptionSetting]
    ContentIdentificationType: Optional[MedicalContentIdentificationType]
    Specialty: Optional[Specialty]
    Type: Optional[Type]
    Tags: Optional[TagList]


class GetMedicalTranscriptionJobResponse(TypedDict, total=False):
    MedicalTranscriptionJob: Optional[MedicalTranscriptionJob]


class GetMedicalVocabularyRequest(ServiceRequest):
    VocabularyName: VocabularyName


class GetMedicalVocabularyResponse(TypedDict, total=False):
    VocabularyName: Optional[VocabularyName]
    LanguageCode: Optional[LanguageCode]
    VocabularyState: Optional[VocabularyState]
    LastModifiedTime: Optional[DateTime]
    FailureReason: Optional[FailureReason]
    DownloadUri: Optional[Uri]


class GetTranscriptionJobRequest(ServiceRequest):
    TranscriptionJobName: TranscriptionJobName


SubtitleFileUris = List[Uri]
SubtitleFormats = List[SubtitleFormat]


class SubtitlesOutput(TypedDict, total=False):
    Formats: Optional[SubtitleFormats]
    SubtitleFileUris: Optional[SubtitleFileUris]
    OutputStartIndex: Optional[SubtitleOutputStartIndex]


class LanguageCodeItem(TypedDict, total=False):
    LanguageCode: Optional[LanguageCode]
    DurationInSeconds: Optional[DurationInSeconds]


LanguageCodeList = List[LanguageCodeItem]


class JobExecutionSettings(TypedDict, total=False):
    AllowDeferredExecution: Optional[Boolean]
    DataAccessRoleArn: Optional[DataAccessRoleArn]


class ModelSettings(TypedDict, total=False):
    LanguageModelName: Optional[ModelName]


class Settings(TypedDict, total=False):
    VocabularyName: Optional[VocabularyName]
    ShowSpeakerLabels: Optional[Boolean]
    MaxSpeakerLabels: Optional[MaxSpeakers]
    ChannelIdentification: Optional[Boolean]
    ShowAlternatives: Optional[Boolean]
    MaxAlternatives: Optional[MaxAlternatives]
    VocabularyFilterName: Optional[VocabularyFilterName]
    VocabularyFilterMethod: Optional[VocabularyFilterMethod]


class TranscriptionJob(TypedDict, total=False):
    TranscriptionJobName: Optional[TranscriptionJobName]
    TranscriptionJobStatus: Optional[TranscriptionJobStatus]
    LanguageCode: Optional[LanguageCode]
    MediaSampleRateHertz: Optional[MediaSampleRateHertz]
    MediaFormat: Optional[MediaFormat]
    Media: Optional[Media]
    Transcript: Optional[Transcript]
    StartTime: Optional[DateTime]
    CreationTime: Optional[DateTime]
    CompletionTime: Optional[DateTime]
    FailureReason: Optional[FailureReason]
    Settings: Optional[Settings]
    ModelSettings: Optional[ModelSettings]
    JobExecutionSettings: Optional[JobExecutionSettings]
    ContentRedaction: Optional[ContentRedaction]
    IdentifyLanguage: Optional[Boolean]
    IdentifyMultipleLanguages: Optional[Boolean]
    LanguageOptions: Optional[LanguageOptions]
    IdentifiedLanguageScore: Optional[IdentifiedLanguageScore]
    LanguageCodes: Optional[LanguageCodeList]
    Tags: Optional[TagList]
    Subtitles: Optional[SubtitlesOutput]
    LanguageIdSettings: Optional[LanguageIdSettingsMap]


class GetTranscriptionJobResponse(TypedDict, total=False):
    TranscriptionJob: Optional[TranscriptionJob]


class GetVocabularyFilterRequest(ServiceRequest):
    VocabularyFilterName: VocabularyFilterName


class GetVocabularyFilterResponse(TypedDict, total=False):
    VocabularyFilterName: Optional[VocabularyFilterName]
    LanguageCode: Optional[LanguageCode]
    LastModifiedTime: Optional[DateTime]
    DownloadUri: Optional[Uri]


class GetVocabularyRequest(ServiceRequest):
    VocabularyName: VocabularyName


class GetVocabularyResponse(TypedDict, total=False):
    VocabularyName: Optional[VocabularyName]
    LanguageCode: Optional[LanguageCode]
    VocabularyState: Optional[VocabularyState]
    LastModifiedTime: Optional[DateTime]
    FailureReason: Optional[FailureReason]
    DownloadUri: Optional[Uri]


KMSEncryptionContextMap = Dict[NonEmptyString, NonEmptyString]


class ListCallAnalyticsCategoriesRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListCallAnalyticsCategoriesResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    Categories: Optional[CategoryPropertiesList]


class ListCallAnalyticsJobsRequest(ServiceRequest):
    Status: Optional[CallAnalyticsJobStatus]
    JobNameContains: Optional[CallAnalyticsJobName]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListCallAnalyticsJobsResponse(TypedDict, total=False):
    Status: Optional[CallAnalyticsJobStatus]
    NextToken: Optional[NextToken]
    CallAnalyticsJobSummaries: Optional[CallAnalyticsJobSummaries]


class ListLanguageModelsRequest(ServiceRequest):
    StatusEquals: Optional[ModelStatus]
    NameContains: Optional[ModelName]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


Models = List[LanguageModel]


class ListLanguageModelsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    Models: Optional[Models]


class ListMedicalTranscriptionJobsRequest(ServiceRequest):
    Status: Optional[TranscriptionJobStatus]
    JobNameContains: Optional[TranscriptionJobName]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class MedicalTranscriptionJobSummary(TypedDict, total=False):
    MedicalTranscriptionJobName: Optional[TranscriptionJobName]
    CreationTime: Optional[DateTime]
    StartTime: Optional[DateTime]
    CompletionTime: Optional[DateTime]
    LanguageCode: Optional[LanguageCode]
    TranscriptionJobStatus: Optional[TranscriptionJobStatus]
    FailureReason: Optional[FailureReason]
    OutputLocationType: Optional[OutputLocationType]
    Specialty: Optional[Specialty]
    ContentIdentificationType: Optional[MedicalContentIdentificationType]
    Type: Optional[Type]


MedicalTranscriptionJobSummaries = List[MedicalTranscriptionJobSummary]


class ListMedicalTranscriptionJobsResponse(TypedDict, total=False):
    Status: Optional[TranscriptionJobStatus]
    NextToken: Optional[NextToken]
    MedicalTranscriptionJobSummaries: Optional[MedicalTranscriptionJobSummaries]


class ListMedicalVocabulariesRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    StateEquals: Optional[VocabularyState]
    NameContains: Optional[VocabularyName]


class VocabularyInfo(TypedDict, total=False):
    VocabularyName: Optional[VocabularyName]
    LanguageCode: Optional[LanguageCode]
    LastModifiedTime: Optional[DateTime]
    VocabularyState: Optional[VocabularyState]


Vocabularies = List[VocabularyInfo]


class ListMedicalVocabulariesResponse(TypedDict, total=False):
    Status: Optional[VocabularyState]
    NextToken: Optional[NextToken]
    Vocabularies: Optional[Vocabularies]


class ListTagsForResourceRequest(ServiceRequest):
    ResourceArn: TranscribeArn


class ListTagsForResourceResponse(TypedDict, total=False):
    ResourceArn: Optional[TranscribeArn]
    Tags: Optional[TagList]


class ListTranscriptionJobsRequest(ServiceRequest):
    Status: Optional[TranscriptionJobStatus]
    JobNameContains: Optional[TranscriptionJobName]
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class TranscriptionJobSummary(TypedDict, total=False):
    TranscriptionJobName: Optional[TranscriptionJobName]
    CreationTime: Optional[DateTime]
    StartTime: Optional[DateTime]
    CompletionTime: Optional[DateTime]
    LanguageCode: Optional[LanguageCode]
    TranscriptionJobStatus: Optional[TranscriptionJobStatus]
    FailureReason: Optional[FailureReason]
    OutputLocationType: Optional[OutputLocationType]
    ContentRedaction: Optional[ContentRedaction]
    ModelSettings: Optional[ModelSettings]
    IdentifyLanguage: Optional[Boolean]
    IdentifyMultipleLanguages: Optional[Boolean]
    IdentifiedLanguageScore: Optional[IdentifiedLanguageScore]
    LanguageCodes: Optional[LanguageCodeList]


TranscriptionJobSummaries = List[TranscriptionJobSummary]


class ListTranscriptionJobsResponse(TypedDict, total=False):
    Status: Optional[TranscriptionJobStatus]
    NextToken: Optional[NextToken]
    TranscriptionJobSummaries: Optional[TranscriptionJobSummaries]


class ListVocabulariesRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    StateEquals: Optional[VocabularyState]
    NameContains: Optional[VocabularyName]


class ListVocabulariesResponse(TypedDict, total=False):
    Status: Optional[VocabularyState]
    NextToken: Optional[NextToken]
    Vocabularies: Optional[Vocabularies]


class ListVocabularyFiltersRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    NameContains: Optional[VocabularyFilterName]


class VocabularyFilterInfo(TypedDict, total=False):
    VocabularyFilterName: Optional[VocabularyFilterName]
    LanguageCode: Optional[LanguageCode]
    LastModifiedTime: Optional[DateTime]


VocabularyFilters = List[VocabularyFilterInfo]


class ListVocabularyFiltersResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    VocabularyFilters: Optional[VocabularyFilters]


class StartCallAnalyticsJobRequest(ServiceRequest):
    CallAnalyticsJobName: CallAnalyticsJobName
    Media: Media
    OutputLocation: Optional[Uri]
    OutputEncryptionKMSKeyId: Optional[KMSKeyId]
    DataAccessRoleArn: Optional[DataAccessRoleArn]
    Settings: Optional[CallAnalyticsJobSettings]
    ChannelDefinitions: Optional[ChannelDefinitions]


class StartCallAnalyticsJobResponse(TypedDict, total=False):
    CallAnalyticsJob: Optional[CallAnalyticsJob]


class StartMedicalTranscriptionJobRequest(ServiceRequest):
    MedicalTranscriptionJobName: TranscriptionJobName
    LanguageCode: LanguageCode
    MediaSampleRateHertz: Optional[MedicalMediaSampleRateHertz]
    MediaFormat: Optional[MediaFormat]
    Media: Media
    OutputBucketName: OutputBucketName
    OutputKey: Optional[OutputKey]
    OutputEncryptionKMSKeyId: Optional[KMSKeyId]
    KMSEncryptionContext: Optional[KMSEncryptionContextMap]
    Settings: Optional[MedicalTranscriptionSetting]
    ContentIdentificationType: Optional[MedicalContentIdentificationType]
    Specialty: Specialty
    Type: Type
    Tags: Optional[TagList]


class StartMedicalTranscriptionJobResponse(TypedDict, total=False):
    MedicalTranscriptionJob: Optional[MedicalTranscriptionJob]


class Subtitles(TypedDict, total=False):
    Formats: Optional[SubtitleFormats]
    OutputStartIndex: Optional[SubtitleOutputStartIndex]


class StartTranscriptionJobRequest(ServiceRequest):
    TranscriptionJobName: TranscriptionJobName
    LanguageCode: Optional[LanguageCode]
    MediaSampleRateHertz: Optional[MediaSampleRateHertz]
    MediaFormat: Optional[MediaFormat]
    Media: Media
    OutputBucketName: Optional[OutputBucketName]
    OutputKey: Optional[OutputKey]
    OutputEncryptionKMSKeyId: Optional[KMSKeyId]
    KMSEncryptionContext: Optional[KMSEncryptionContextMap]
    Settings: Optional[Settings]
    ModelSettings: Optional[ModelSettings]
    JobExecutionSettings: Optional[JobExecutionSettings]
    ContentRedaction: Optional[ContentRedaction]
    IdentifyLanguage: Optional[Boolean]
    IdentifyMultipleLanguages: Optional[Boolean]
    LanguageOptions: Optional[LanguageOptions]
    Subtitles: Optional[Subtitles]
    Tags: Optional[TagList]
    LanguageIdSettings: Optional[LanguageIdSettingsMap]


class StartTranscriptionJobResponse(TypedDict, total=False):
    TranscriptionJob: Optional[TranscriptionJob]


TagKeyList = List[TagKey]


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
    InputType: Optional[InputType]


class UpdateCallAnalyticsCategoryResponse(TypedDict, total=False):
    CategoryProperties: Optional[CategoryProperties]


class UpdateMedicalVocabularyRequest(ServiceRequest):
    VocabularyName: VocabularyName
    LanguageCode: LanguageCode
    VocabularyFileUri: Uri


class UpdateMedicalVocabularyResponse(TypedDict, total=False):
    VocabularyName: Optional[VocabularyName]
    LanguageCode: Optional[LanguageCode]
    LastModifiedTime: Optional[DateTime]
    VocabularyState: Optional[VocabularyState]


class UpdateVocabularyFilterRequest(ServiceRequest):
    VocabularyFilterName: VocabularyFilterName
    Words: Optional[Words]
    VocabularyFilterFileUri: Optional[Uri]


class UpdateVocabularyFilterResponse(TypedDict, total=False):
    VocabularyFilterName: Optional[VocabularyFilterName]
    LanguageCode: Optional[LanguageCode]
    LastModifiedTime: Optional[DateTime]


class UpdateVocabularyRequest(ServiceRequest):
    VocabularyName: VocabularyName
    LanguageCode: LanguageCode
    Phrases: Optional[Phrases]
    VocabularyFileUri: Optional[Uri]


class UpdateVocabularyResponse(TypedDict, total=False):
    VocabularyName: Optional[VocabularyName]
    LanguageCode: Optional[LanguageCode]
    LastModifiedTime: Optional[DateTime]
    VocabularyState: Optional[VocabularyState]


class TranscribeApi:

    service = "transcribe"
    version = "2017-10-26"

    @handler("CreateCallAnalyticsCategory")
    def create_call_analytics_category(
        self,
        context: RequestContext,
        category_name: CategoryName,
        rules: RuleList,
        input_type: InputType = None,
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
        tags: TagList = None,
    ) -> CreateLanguageModelResponse:
        raise NotImplementedError

    @handler("CreateMedicalVocabulary")
    def create_medical_vocabulary(
        self,
        context: RequestContext,
        vocabulary_name: VocabularyName,
        language_code: LanguageCode,
        vocabulary_file_uri: Uri,
        tags: TagList = None,
    ) -> CreateMedicalVocabularyResponse:
        raise NotImplementedError

    @handler("CreateVocabulary")
    def create_vocabulary(
        self,
        context: RequestContext,
        vocabulary_name: VocabularyName,
        language_code: LanguageCode,
        phrases: Phrases = None,
        vocabulary_file_uri: Uri = None,
        tags: TagList = None,
    ) -> CreateVocabularyResponse:
        raise NotImplementedError

    @handler("CreateVocabularyFilter")
    def create_vocabulary_filter(
        self,
        context: RequestContext,
        vocabulary_filter_name: VocabularyFilterName,
        language_code: LanguageCode,
        words: Words = None,
        vocabulary_filter_file_uri: Uri = None,
        tags: TagList = None,
    ) -> CreateVocabularyFilterResponse:
        raise NotImplementedError

    @handler("DeleteCallAnalyticsCategory")
    def delete_call_analytics_category(
        self, context: RequestContext, category_name: CategoryName
    ) -> DeleteCallAnalyticsCategoryResponse:
        raise NotImplementedError

    @handler("DeleteCallAnalyticsJob")
    def delete_call_analytics_job(
        self, context: RequestContext, call_analytics_job_name: CallAnalyticsJobName
    ) -> DeleteCallAnalyticsJobResponse:
        raise NotImplementedError

    @handler("DeleteLanguageModel")
    def delete_language_model(self, context: RequestContext, model_name: ModelName) -> None:
        raise NotImplementedError

    @handler("DeleteMedicalTranscriptionJob")
    def delete_medical_transcription_job(
        self, context: RequestContext, medical_transcription_job_name: TranscriptionJobName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteMedicalVocabulary")
    def delete_medical_vocabulary(
        self, context: RequestContext, vocabulary_name: VocabularyName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteTranscriptionJob")
    def delete_transcription_job(
        self, context: RequestContext, transcription_job_name: TranscriptionJobName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteVocabulary")
    def delete_vocabulary(self, context: RequestContext, vocabulary_name: VocabularyName) -> None:
        raise NotImplementedError

    @handler("DeleteVocabularyFilter")
    def delete_vocabulary_filter(
        self, context: RequestContext, vocabulary_filter_name: VocabularyFilterName
    ) -> None:
        raise NotImplementedError

    @handler("DescribeLanguageModel")
    def describe_language_model(
        self, context: RequestContext, model_name: ModelName
    ) -> DescribeLanguageModelResponse:
        raise NotImplementedError

    @handler("GetCallAnalyticsCategory")
    def get_call_analytics_category(
        self, context: RequestContext, category_name: CategoryName
    ) -> GetCallAnalyticsCategoryResponse:
        raise NotImplementedError

    @handler("GetCallAnalyticsJob")
    def get_call_analytics_job(
        self, context: RequestContext, call_analytics_job_name: CallAnalyticsJobName
    ) -> GetCallAnalyticsJobResponse:
        raise NotImplementedError

    @handler("GetMedicalTranscriptionJob")
    def get_medical_transcription_job(
        self, context: RequestContext, medical_transcription_job_name: TranscriptionJobName
    ) -> GetMedicalTranscriptionJobResponse:
        raise NotImplementedError

    @handler("GetMedicalVocabulary")
    def get_medical_vocabulary(
        self, context: RequestContext, vocabulary_name: VocabularyName
    ) -> GetMedicalVocabularyResponse:
        raise NotImplementedError

    @handler("GetTranscriptionJob")
    def get_transcription_job(
        self, context: RequestContext, transcription_job_name: TranscriptionJobName
    ) -> GetTranscriptionJobResponse:
        raise NotImplementedError

    @handler("GetVocabulary")
    def get_vocabulary(
        self, context: RequestContext, vocabulary_name: VocabularyName
    ) -> GetVocabularyResponse:
        raise NotImplementedError

    @handler("GetVocabularyFilter")
    def get_vocabulary_filter(
        self, context: RequestContext, vocabulary_filter_name: VocabularyFilterName
    ) -> GetVocabularyFilterResponse:
        raise NotImplementedError

    @handler("ListCallAnalyticsCategories")
    def list_call_analytics_categories(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListCallAnalyticsCategoriesResponse:
        raise NotImplementedError

    @handler("ListCallAnalyticsJobs")
    def list_call_analytics_jobs(
        self,
        context: RequestContext,
        status: CallAnalyticsJobStatus = None,
        job_name_contains: CallAnalyticsJobName = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListCallAnalyticsJobsResponse:
        raise NotImplementedError

    @handler("ListLanguageModels")
    def list_language_models(
        self,
        context: RequestContext,
        status_equals: ModelStatus = None,
        name_contains: ModelName = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListLanguageModelsResponse:
        raise NotImplementedError

    @handler("ListMedicalTranscriptionJobs")
    def list_medical_transcription_jobs(
        self,
        context: RequestContext,
        status: TranscriptionJobStatus = None,
        job_name_contains: TranscriptionJobName = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListMedicalTranscriptionJobsResponse:
        raise NotImplementedError

    @handler("ListMedicalVocabularies")
    def list_medical_vocabularies(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        state_equals: VocabularyState = None,
        name_contains: VocabularyName = None,
    ) -> ListMedicalVocabulariesResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: TranscribeArn
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ListTranscriptionJobs")
    def list_transcription_jobs(
        self,
        context: RequestContext,
        status: TranscriptionJobStatus = None,
        job_name_contains: TranscriptionJobName = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListTranscriptionJobsResponse:
        raise NotImplementedError

    @handler("ListVocabularies")
    def list_vocabularies(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        state_equals: VocabularyState = None,
        name_contains: VocabularyName = None,
    ) -> ListVocabulariesResponse:
        raise NotImplementedError

    @handler("ListVocabularyFilters")
    def list_vocabulary_filters(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        name_contains: VocabularyFilterName = None,
    ) -> ListVocabularyFiltersResponse:
        raise NotImplementedError

    @handler("StartCallAnalyticsJob")
    def start_call_analytics_job(
        self,
        context: RequestContext,
        call_analytics_job_name: CallAnalyticsJobName,
        media: Media,
        output_location: Uri = None,
        output_encryption_kms_key_id: KMSKeyId = None,
        data_access_role_arn: DataAccessRoleArn = None,
        settings: CallAnalyticsJobSettings = None,
        channel_definitions: ChannelDefinitions = None,
    ) -> StartCallAnalyticsJobResponse:
        raise NotImplementedError

    @handler("StartMedicalTranscriptionJob", expand=False)
    def start_medical_transcription_job(
        self, context: RequestContext, request: StartMedicalTranscriptionJobRequest
    ) -> StartMedicalTranscriptionJobResponse:
        raise NotImplementedError

    @handler("StartTranscriptionJob")
    def start_transcription_job(
        self,
        context: RequestContext,
        transcription_job_name: TranscriptionJobName,
        media: Media,
        language_code: LanguageCode = None,
        media_sample_rate_hertz: MediaSampleRateHertz = None,
        media_format: MediaFormat = None,
        output_bucket_name: OutputBucketName = None,
        output_key: OutputKey = None,
        output_encryption_kms_key_id: KMSKeyId = None,
        kms_encryption_context: KMSEncryptionContextMap = None,
        settings: Settings = None,
        model_settings: ModelSettings = None,
        job_execution_settings: JobExecutionSettings = None,
        content_redaction: ContentRedaction = None,
        identify_language: Boolean = None,
        identify_multiple_languages: Boolean = None,
        language_options: LanguageOptions = None,
        subtitles: Subtitles = None,
        tags: TagList = None,
        language_id_settings: LanguageIdSettingsMap = None,
    ) -> StartTranscriptionJobResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: TranscribeArn, tags: TagList
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: TranscribeArn, tag_keys: TagKeyList
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateCallAnalyticsCategory")
    def update_call_analytics_category(
        self,
        context: RequestContext,
        category_name: CategoryName,
        rules: RuleList,
        input_type: InputType = None,
    ) -> UpdateCallAnalyticsCategoryResponse:
        raise NotImplementedError

    @handler("UpdateMedicalVocabulary")
    def update_medical_vocabulary(
        self,
        context: RequestContext,
        vocabulary_name: VocabularyName,
        language_code: LanguageCode,
        vocabulary_file_uri: Uri,
    ) -> UpdateMedicalVocabularyResponse:
        raise NotImplementedError

    @handler("UpdateVocabulary")
    def update_vocabulary(
        self,
        context: RequestContext,
        vocabulary_name: VocabularyName,
        language_code: LanguageCode,
        phrases: Phrases = None,
        vocabulary_file_uri: Uri = None,
    ) -> UpdateVocabularyResponse:
        raise NotImplementedError

    @handler("UpdateVocabularyFilter")
    def update_vocabulary_filter(
        self,
        context: RequestContext,
        vocabulary_filter_name: VocabularyFilterName,
        words: Words = None,
        vocabulary_filter_file_uri: Uri = None,
    ) -> UpdateVocabularyFilterResponse:
        raise NotImplementedError
