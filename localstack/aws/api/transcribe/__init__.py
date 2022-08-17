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


class CallAnalyticsJobStatus(str):
    QUEUED = "QUEUED"
    IN_PROGRESS = "IN_PROGRESS"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"


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
    """Your request didn't pass one or more validation tests. This can occur
    when the entity you're trying to delete doesn't exist or if it's in a
    non-terminal state (such as ``IN PROGRESS``). See the exception message
    field for more information.
    """

    code: str = "BadRequestException"
    sender_fault: bool = False
    status_code: int = 400


class ConflictException(ServiceException):
    """A resource already exists with this name. Resource names must be unique
    within an Amazon Web Services account.
    """

    code: str = "ConflictException"
    sender_fault: bool = False
    status_code: int = 400


class InternalFailureException(ServiceException):
    """There was an internal error. Check the error message, correct the issue,
    and try your request again.
    """

    code: str = "InternalFailureException"
    sender_fault: bool = False
    status_code: int = 400


class LimitExceededException(ServiceException):
    """You've either sent too many requests or your input file is too long.
    Wait before retrying your request, or use a smaller file and try your
    request again.
    """

    code: str = "LimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class NotFoundException(ServiceException):
    """We can't find the requested resource. Check that the specified name is
    correct and try your request again.
    """

    code: str = "NotFoundException"
    sender_fault: bool = False
    status_code: int = 400


TimestampMilliseconds = int


class AbsoluteTimeRange(TypedDict, total=False):
    """A time range, in milliseconds, between two points in your media file.

    You can use ``StartTime`` and ``EndTime`` to search a custom segment.
    For example, setting ``StartTime`` to 10000 and ``EndTime`` to 50000
    only searches for your specified criteria in the audio contained between
    the 10,000 millisecond mark and the 50,000 millisecond mark of your
    media file. You must use ``StartTime`` and ``EndTime`` as a set; that
    is, if you include one, you must include both.

    You can use also ``First`` to search from the start of the audio until
    the time you specify, or ``Last`` to search from the time you specify
    until the end of the audio. For example, setting ``First`` to 50000 only
    searches for your specified criteria in the audio contained between the
    start of the media file to the 50,000 millisecond mark. You can use
    ``First`` and ``Last`` independently of each other.

    If you prefer to use percentage instead of milliseconds, see .
    """

    StartTime: Optional[TimestampMilliseconds]
    EndTime: Optional[TimestampMilliseconds]
    First: Optional[TimestampMilliseconds]
    Last: Optional[TimestampMilliseconds]


class ChannelDefinition(TypedDict, total=False):
    """Allows you to specify which speaker is on which channel. For example, if
    your agent is the first participant to speak, you would set
    ``ChannelId`` to ``0`` (to indicate the first channel) and
    ``ParticipantRole`` to ``AGENT`` (to indicate that it's the agent
    speaking).
    """

    ChannelId: Optional[ChannelId]
    ParticipantRole: Optional[ParticipantRole]


ChannelDefinitions = List[ChannelDefinition]


class LanguageIdSettings(TypedDict, total=False):
    """If using automatic language identification (``IdentifyLanguage``) in
    your request and you want to apply a custom language model, a custom
    vocabulary, or a custom vocabulary filter, include
    ``LanguageIdSettings`` with the relevant sub-parameters
    (``VocabularyName``, ``LanguageModelName``, and
    ``VocabularyFilterName``).

    You can specify two or more language codes that represent the languages
    you think may be present in your media; including more than five is not
    recommended. Each language code you include can have an associated
    custom language model, custom vocabulary, and custom vocabulary filter.
    The languages you specify must match the languages of the specified
    custom language models, custom vocabularies, and custom vocabulary
    filters.

    To include language options using ``IdentifyLanguage`` **without**
    including a custom language model, a custom vocabulary, or a custom
    vocabulary filter, use ``LanguageOptions`` instead of
    ``LanguageIdSettings``. Including language options can improve the
    accuracy of automatic language identification.

    If you want to include a custom language model with your request but
    **do not** want to use automatic language identification, use instead
    the ```` parameter with the ``LanguageModelName`` sub-parameter.

    If you want to include a custom vocabulary or a custom vocabulary filter
    (or both) with your request but **do not** want to use automatic
    language identification, use instead the ```` parameter with the
    ``VocabularyName`` or ``VocabularyFilterName`` (or both) sub-parameter.
    """

    VocabularyName: Optional[VocabularyName]
    VocabularyFilterName: Optional[VocabularyFilterName]
    LanguageModelName: Optional[ModelName]


LanguageIdSettingsMap = Dict[LanguageCode, LanguageIdSettings]
LanguageOptions = List[LanguageCode]
PiiEntityTypes = List[PiiEntityType]


class ContentRedaction(TypedDict, total=False):
    """Allows you to redact or flag specified personally identifiable
    information (PII) in your transcript. If you use ``ContentRedaction``,
    you must also include the sub-parameters: ``PiiEntityTypes``,
    ``RedactionOutput``, and ``RedactionType``.
    """

    RedactionType: RedactionType
    RedactionOutput: RedactionOutput
    PiiEntityTypes: Optional[PiiEntityTypes]


class CallAnalyticsJobSettings(TypedDict, total=False):
    """Provides additional optional settings for your request, including
    content redaction, automatic language identification; allows you to
    apply custom language models, vocabulary filters, and custom
    vocabularies.
    """

    VocabularyName: Optional[VocabularyName]
    VocabularyFilterName: Optional[VocabularyFilterName]
    VocabularyFilterMethod: Optional[VocabularyFilterMethod]
    LanguageModelName: Optional[ModelName]
    ContentRedaction: Optional[ContentRedaction]
    LanguageOptions: Optional[LanguageOptions]
    LanguageIdSettings: Optional[LanguageIdSettingsMap]


DateTime = datetime


class Transcript(TypedDict, total=False):
    """Provides you with the Amazon S3 URI you can use to access your
    transcript.
    """

    TranscriptFileUri: Optional[Uri]
    RedactedTranscriptFileUri: Optional[Uri]


class Media(TypedDict, total=False):
    """Describes the Amazon S3 location of the media file you want to use in
    your request.
    """

    MediaFileUri: Optional[Uri]
    RedactedMediaFileUri: Optional[Uri]


class CallAnalyticsJob(TypedDict, total=False):
    """Provides detailed information about a Call Analytics job.

    To view the job's status, refer to ``CallAnalyticsJobStatus``. If the
    status is ``COMPLETED``, the job is finished. You can find your
    completed transcript at the URI specified in ``TranscriptFileUri``. If
    the status is ``FAILED``, ``FailureReason`` provides details on why your
    transcription job failed.

    If you enabled personally identifiable information (PII) redaction, the
    redacted transcript appears at the location specified in
    ``RedactedTranscriptFileUri``.

    If you chose to redact the audio in your media file, you can find your
    redacted media file at the location specified in the
    ``RedactedMediaFileUri`` field of your response.
    """

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
    """Provides detailed information about a specific Call Analytics job."""

    CallAnalyticsJobName: Optional[CallAnalyticsJobName]
    CreationTime: Optional[DateTime]
    StartTime: Optional[DateTime]
    CompletionTime: Optional[DateTime]
    LanguageCode: Optional[LanguageCode]
    CallAnalyticsJobStatus: Optional[CallAnalyticsJobStatus]
    FailureReason: Optional[FailureReason]


CallAnalyticsJobSummaries = List[CallAnalyticsJobSummary]


class RelativeTimeRange(TypedDict, total=False):
    """A time range, in percentage, between two points in your media file.

    You can use ``StartPercentage`` and ``EndPercentage`` to search a custom
    segment. For example, setting ``StartPercentage`` to 10 and
    ``EndPercentage`` to 50 only searches for your specified criteria in the
    audio contained between the 10 percent mark and the 50 percent mark of
    your media file.

    You can use also ``First`` to search from the start of the media file
    until the time you specify, or ``Last`` to search from the time you
    specify until the end of the media file. For example, setting ``First``
    to 10 only searches for your specified criteria in the audio contained
    in the first 10 percent of the media file.

    If you prefer to use milliseconds instead of percentage, see .
    """

    StartPercentage: Optional[Percentage]
    EndPercentage: Optional[Percentage]
    First: Optional[Percentage]
    Last: Optional[Percentage]


SentimentValueList = List[SentimentValue]


class SentimentFilter(TypedDict, total=False):
    """Flag the presence or absence of specific sentiments detected in your
    Call Analytics transcription output.

    Rules using ``SentimentFilter`` are designed to match:

    -  The presence or absence of a positive sentiment felt by the customer,
       agent, or both at specified points in the call

    -  The presence or absence of a negative sentiment felt by the customer,
       agent, or both at specified points in the call

    -  The presence or absence of a neutral sentiment felt by the customer,
       agent, or both at specified points in the call

    -  The presence or absence of a mixed sentiment felt by the customer,
       the agent, or both at specified points in the call

    See `Rule
    criteria <https://docs.aws.amazon.com/transcribe/latest/dg/call-analytics-create-categories.html#call-analytics-create-categories-rules>`__
    for examples.
    """

    Sentiments: SentimentValueList
    AbsoluteTimeRange: Optional[AbsoluteTimeRange]
    RelativeTimeRange: Optional[RelativeTimeRange]
    ParticipantRole: Optional[ParticipantRole]
    Negate: Optional[Boolean]


StringTargetList = List[NonEmptyString]


class TranscriptFilter(TypedDict, total=False):
    """Flag the presence or absence of specific words or phrases detected in
    your Call Analytics transcription output.

    Rules using ``TranscriptFilter`` are designed to match:

    -  Custom words or phrases spoken by the agent, the customer, or both

    -  Custom words or phrases **not** spoken by the agent, the customer, or
       either

    -  Custom words or phrases that occur at a specific time frame

    See `Rule
    criteria <https://docs.aws.amazon.com/transcribe/latest/dg/call-analytics-create-categories.html#call-analytics-create-categories-rules>`__
    for examples.
    """

    TranscriptFilterType: TranscriptFilterType
    AbsoluteTimeRange: Optional[AbsoluteTimeRange]
    RelativeTimeRange: Optional[RelativeTimeRange]
    ParticipantRole: Optional[ParticipantRole]
    Negate: Optional[Boolean]
    Targets: StringTargetList


class InterruptionFilter(TypedDict, total=False):
    """Flag the presence or absence of interruptions in your Call Analytics
    transcription output.

    Rules using ``InterruptionFilter`` are designed to match:

    -  Instances where an agent interrupts a customer

    -  Instances where a customer interrupts an agent

    -  Either participant interrupting the other

    -  A lack of interruptions

    See `Rule
    criteria <https://docs.aws.amazon.com/transcribe/latest/dg/call-analytics-create-categories.html#call-analytics-create-categories-rules>`__
    for usage examples.
    """

    Threshold: Optional[TimestampMilliseconds]
    ParticipantRole: Optional[ParticipantRole]
    AbsoluteTimeRange: Optional[AbsoluteTimeRange]
    RelativeTimeRange: Optional[RelativeTimeRange]
    Negate: Optional[Boolean]


class NonTalkTimeFilter(TypedDict, total=False):
    """Flag the presence or absence of periods of silence in your Call
    Analytics transcription output.

    Rules using ``NonTalkTimeFilter`` are designed to match:

    -  The presence of silence at specified periods throughout the call

    -  The presence of speech at specified periods throughout the call

    See `Rule
    criteria <https://docs.aws.amazon.com/transcribe/latest/dg/call-analytics-create-categories.html#call-analytics-create-categories-rules>`__
    for usage examples.
    """

    Threshold: Optional[TimestampMilliseconds]
    AbsoluteTimeRange: Optional[AbsoluteTimeRange]
    RelativeTimeRange: Optional[RelativeTimeRange]
    Negate: Optional[Boolean]


class Rule(TypedDict, total=False):
    """A rule is a set of criteria you can specify to flag an attribute in your
    Call Analytics output. Rules define a Call Analytics category.

    Rules can include these parameters: , , , and . To learn more about
    these parameters, refer to `Rule
    criteria <https://docs.aws.amazon.com/transcribe/latest/dg/call-analytics-create-categories.html#call-analytics-create-categories-rules>`__.

    To learn more about Call Analytics categories, see `Creating
    categories <https://docs.aws.amazon.com/transcribe/latest/dg/call-analytics-create-categories.html>`__.

    To learn more about Call Analytics, see `Analyzing call center audio
    with Call
    Analytics <https://docs.aws.amazon.com/transcribe/latest/dg/call-analytics.html>`__.
    """

    NonTalkTimeFilter: Optional[NonTalkTimeFilter]
    InterruptionFilter: Optional[InterruptionFilter]
    TranscriptFilter: Optional[TranscriptFilter]
    SentimentFilter: Optional[SentimentFilter]


RuleList = List[Rule]


class CategoryProperties(TypedDict, total=False):
    """Provides you with the properties of the Call Analytics category you
    specified in your request. This includes the list of rules that define
    the specified category.
    """

    CategoryName: Optional[CategoryName]
    Rules: Optional[RuleList]
    CreateTime: Optional[DateTime]
    LastUpdateTime: Optional[DateTime]


CategoryPropertiesList = List[CategoryProperties]


class CreateCallAnalyticsCategoryRequest(ServiceRequest):
    CategoryName: CategoryName
    Rules: RuleList


class CreateCallAnalyticsCategoryResponse(TypedDict, total=False):
    CategoryProperties: Optional[CategoryProperties]


class Tag(TypedDict, total=False):
    """Adds metadata, in the form of a key:value pair, to the specified
    resource.

    For example, you could add the tag ``Department:Sales`` to a resource to
    indicate that it pertains to your organization's sales department. You
    can also use tags for tag-based access control.

    To learn more about tagging, see `Tagging
    resources <https://docs.aws.amazon.com/transcribe/latest/dg/tagging.html>`__.
    """

    Key: TagKey
    Value: TagValue


TagList = List[Tag]


class InputDataConfig(TypedDict, total=False):
    """Contains the Amazon S3 location of the training data you want to use to
    create a new custom language model, and permissions to access this
    location.

    When using ``InputDataConfig``, you must include these sub-parameters:
    ``S3Uri`` and ``DataAccessRoleArn``. You can optionally include
    ``TuningDataS3Uri``.
    """

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
    """Provides information about a custom language model, including the base
    model name, when the model was created, the location of the files used
    to train the model, when the model was last modified, the name you chose
    for the model, its language, its processing state, and if there is an
    upgrade available for the base model.
    """

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
    """Allows additional optional settings in your request, including channel
    identification, alternative transcriptions, and speaker labeling; allows
    you to apply custom vocabularies to your medical transcription job.
    """

    ShowSpeakerLabels: Optional[Boolean]
    MaxSpeakerLabels: Optional[MaxSpeakers]
    ChannelIdentification: Optional[Boolean]
    ShowAlternatives: Optional[Boolean]
    MaxAlternatives: Optional[MaxAlternatives]
    VocabularyName: Optional[VocabularyName]


class MedicalTranscript(TypedDict, total=False):
    """Provides you with the Amazon S3 URI you can use to access your
    transcript.
    """

    TranscriptFileUri: Optional[Uri]


class MedicalTranscriptionJob(TypedDict, total=False):
    """Provides detailed information about a medical transcription job.

    To view the status of the specified medical transcription job, check the
    ``TranscriptionJobStatus`` field. If the status is ``COMPLETED``, the
    job is finished and you can find the results at the location specified
    in ``TranscriptFileUri``. If the status is ``FAILED``, ``FailureReason``
    provides details on why your transcription job failed.
    """

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
    """Provides information about your subtitle file, including format, start
    index, and Amazon S3 location.
    """

    Formats: Optional[SubtitleFormats]
    SubtitleFileUris: Optional[SubtitleFileUris]
    OutputStartIndex: Optional[SubtitleOutputStartIndex]


class LanguageCodeItem(TypedDict, total=False):
    """Provides information on the speech contained in a discreet utterance
    when multi-language identification is enabled in your request. This
    utterance represents a block of speech consisting of one language,
    preceded or followed by a block of speech in a different language.
    """

    LanguageCode: Optional[LanguageCode]
    DurationInSeconds: Optional[DurationInSeconds]


LanguageCodeList = List[LanguageCodeItem]


class JobExecutionSettings(TypedDict, total=False):
    """Allows you to control how your transcription job is processed.
    Currently, the only ``JobExecutionSettings`` modification you can choose
    is enabling job queueing using the ``AllowDeferredExecution``
    sub-parameter.

    If you include ``JobExecutionSettings`` in your request, you must also
    include the sub-parameters: ``AllowDeferredExecution`` and
    ``DataAccessRoleArn``.
    """

    AllowDeferredExecution: Optional[Boolean]
    DataAccessRoleArn: Optional[DataAccessRoleArn]


class ModelSettings(TypedDict, total=False):
    """Provides the name of the custom language model that was included in the
    specified transcription job.

    Only use ``ModelSettings`` with the ``LanguageModelName`` sub-parameter
    if you're **not** using automatic language identification (````). If
    using ``LanguageIdSettings`` in your request, this parameter contains a
    ``LanguageModelName`` sub-parameter.
    """

    LanguageModelName: Optional[ModelName]


class Settings(TypedDict, total=False):
    """Allows additional optional settings in your request, including channel
    identification, alternative transcriptions, and speaker labeling; allows
    you to apply custom vocabularies to your transcription job.
    """

    VocabularyName: Optional[VocabularyName]
    ShowSpeakerLabels: Optional[Boolean]
    MaxSpeakerLabels: Optional[MaxSpeakers]
    ChannelIdentification: Optional[Boolean]
    ShowAlternatives: Optional[Boolean]
    MaxAlternatives: Optional[MaxAlternatives]
    VocabularyFilterName: Optional[VocabularyFilterName]
    VocabularyFilterMethod: Optional[VocabularyFilterMethod]


class TranscriptionJob(TypedDict, total=False):
    """Provides detailed information about a transcription job.

    To view the status of the specified transcription job, check the
    ``TranscriptionJobStatus`` field. If the status is ``COMPLETED``, the
    job is finished and you can find the results at the location specified
    in ``TranscriptFileUri``. If the status is ``FAILED``, ``FailureReason``
    provides details on why your transcription job failed.

    If you enabled content redaction, the redacted transcript can be found
    at the location specified in ``RedactedTranscriptFileUri``.
    """

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
    """Provides detailed information about a specific medical transcription
    job.
    """

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
    """Provides information about a custom vocabulary, including the language
    of the vocabulary, when it was last modified, its name, and the
    processing state.
    """

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
    """Provides detailed information about a specific transcription job."""

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
    """Provides information about a vocabulary filter, including the language
    of the filter, when it was last modified, and its name.
    """

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
    """Generate subtitles for your media file with your transcription request.

    You can choose a start index of 0 or 1, and you can specify either
    WebVTT or SubRip (or both) as your output format.

    Note that your subtitle files are placed in the same location as your
    transcription output.
    """

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
        self, context: RequestContext, category_name: CategoryName, rules: RuleList
    ) -> CreateCallAnalyticsCategoryResponse:
        """Creates a new Call Analytics category.

        All categories are automatically applied to your Call Analytics jobs.
        Note that in order to apply your categories to your jobs, you must
        create them before submitting your job request, as categories cannot be
        applied retroactively.

        Call Analytics categories are composed of rules. For each category, you
        must create between 1 and 20 rules. Rules can include these parameters:
        , , , and .

        To update an existing category, see .

        To learn more about:

        -  Call Analytics categories, see `Creating
           categories <https://docs.aws.amazon.com/transcribe/latest/dg/call-analytics-create-categories.html>`__

        -  Using rules, see `Rule
           criteria <https://docs.aws.amazon.com/transcribe/latest/dg/call-analytics-create-categories.html#call-analytics-create-categories-rules>`__
           and refer to the data type

        -  Call Analytics, see `Analyzing call center audio with Call
           Analytics <https://docs.aws.amazon.com/transcribe/latest/dg/call-analytics.html>`__

        :param category_name: A unique name, chosen by you, for your Call Analytics category.
        :param rules: Rules define a Call Analytics category.
        :returns: CreateCallAnalyticsCategoryResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        :raises ConflictException:
        """
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
        """Creates a new custom language model.

        When creating a new language model, you must specify:

        -  If you want a Wideband (audio sample rates over 16,000 Hz) or
           Narrowband (audio sample rates under 16,000 Hz) base model

        -  The location of your training and tuning files (this must be an
           Amazon S3 URI)

        -  The language of your model

        -  A unique name for your model

        For more information, see `Custom language
        models <https://docs.aws.amazon.com/transcribe/latest/dg/custom-language-models.html>`__.

        :param language_code: The language code that represents the language of your model.
        :param base_model_name: The Amazon Transcribe standard language model, or base model, used to
        create your custom language model.
        :param model_name: A unique name, chosen by you, for your custom language model.
        :param input_data_config: Contains the Amazon S3 location of the training data you want to use to
        create a new custom language model, and permissions to access this
        location.
        :param tags: Adds one or more custom tags, each in the form of a key:value pair, to a
        new custom language model at the time you create this new model.
        :returns: CreateLanguageModelResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        :raises ConflictException:
        """
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
        """Creates a new custom medical vocabulary.

        Prior to creating a new medical vocabulary, you must first upload a text
        file that contains your new entries, phrases, and terms into an Amazon
        S3 bucket. Note that this differs from , where you can include a list of
        terms within your request using the ``Phrases`` flag;
        ``CreateMedicalVocabulary`` does not support the ``Phrases`` flag.

        Each language has a character set that contains all allowed characters
        for that specific language. If you use unsupported characters, your
        vocabulary request fails. Refer to `Character Sets for Custom
        Vocabularies <https://docs.aws.amazon.com/transcribe/latest/dg/charsets.html>`__
        to get the character set for your language.

        For more information, see `Creating a custom
        vocabulary <https://docs.aws.amazon.com/transcribe/latest/dg/custom-vocabulary-create.html>`__.

        :param vocabulary_name: A unique name, chosen by you, for your new custom medical vocabulary.
        :param language_code: The language code that represents the language of the entries in your
        custom vocabulary.
        :param vocabulary_file_uri: The Amazon S3 location (URI) of the text file that contains your custom
        medical vocabulary.
        :param tags: Adds one or more custom tags, each in the form of a key:value pair, to a
        new medical vocabulary at the time you create this new vocabulary.
        :returns: CreateMedicalVocabularyResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        :raises ConflictException:
        """
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
        """Creates a new custom vocabulary.

        When creating a new vocabulary, you can either upload a text file that
        contains your new entries, phrases, and terms into an Amazon S3 bucket
        and include the URI in your request, or you can include a list of terms
        directly in your request using the ``Phrases`` flag.

        Each language has a character set that contains all allowed characters
        for that specific language. If you use unsupported characters, your
        vocabulary request fails. Refer to `Character Sets for Custom
        Vocabularies <https://docs.aws.amazon.com/transcribe/latest/dg/charsets.html>`__
        to get the character set for your language.

        For more information, see `Creating a custom
        vocabulary <https://docs.aws.amazon.com/transcribe/latest/dg/custom-vocabulary-create.html>`__.

        :param vocabulary_name: A unique name, chosen by you, for your new custom vocabulary.
        :param language_code: The language code that represents the language of the entries in your
        custom vocabulary.
        :param phrases: Use this parameter if you want to create your vocabulary by including
        all desired terms, as comma-separated values, within your request.
        :param vocabulary_file_uri: The Amazon S3 location of the text file that contains your custom
        vocabulary.
        :param tags: Adds one or more custom tags, each in the form of a key:value pair, to a
        new custom vocabulary at the time you create this new vocabulary.
        :returns: CreateVocabularyResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        :raises ConflictException:
        """
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
        """Creates a new custom vocabulary filter.

        You can use vocabulary filters to mask, delete, or flag specific words
        from your transcript. Vocabulary filters are commonly used to mask
        profanity in transcripts.

        Each language has a character set that contains all allowed characters
        for that specific language. If you use unsupported characters, your
        vocabulary filter request fails. Refer to `Character Sets for Custom
        Vocabularies <https://docs.aws.amazon.com/transcribe/latest/dg/charsets.html>`__
        to get the character set for your language.

        For more information, see `Using vocabulary filtering with unwanted
        words <https://docs.aws.amazon.com/transcribe/latest/dg/vocabulary-filtering.html>`__.

        :param vocabulary_filter_name: A unique name, chosen by you, for your new custom vocabulary filter.
        :param language_code: The language code that represents the language of the entries in your
        vocabulary filter.
        :param words: Use this parameter if you want to create your vocabulary filter by
        including all desired terms, as comma-separated values, within your
        request.
        :param vocabulary_filter_file_uri: The Amazon S3 location of the text file that contains your custom
        vocabulary filter terms.
        :param tags: Adds one or more custom tags, each in the form of a key:value pair, to a
        new custom vocabulary filter at the time you create this new filter.
        :returns: CreateVocabularyFilterResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        :raises ConflictException:
        """
        raise NotImplementedError

    @handler("DeleteCallAnalyticsCategory")
    def delete_call_analytics_category(
        self, context: RequestContext, category_name: CategoryName
    ) -> DeleteCallAnalyticsCategoryResponse:
        """Deletes a Call Analytics category. To use this operation, specify the
        name of the category you want to delete using ``CategoryName``. Category
        names are case sensitive.

        :param category_name: The name of the Call Analytics category you want to delete.
        :returns: DeleteCallAnalyticsCategoryResponse
        :raises NotFoundException:
        :raises LimitExceededException:
        :raises BadRequestException:
        :raises InternalFailureException:
        """
        raise NotImplementedError

    @handler("DeleteCallAnalyticsJob")
    def delete_call_analytics_job(
        self, context: RequestContext, call_analytics_job_name: CallAnalyticsJobName
    ) -> DeleteCallAnalyticsJobResponse:
        """Deletes a Call Analytics job. To use this operation, specify the name of
        the job you want to delete using ``CallAnalyticsJobName``. Job names are
        case sensitive.

        :param call_analytics_job_name: The name of the Call Analytics job you want to delete.
        :returns: DeleteCallAnalyticsJobResponse
        :raises LimitExceededException:
        :raises BadRequestException:
        :raises InternalFailureException:
        """
        raise NotImplementedError

    @handler("DeleteLanguageModel")
    def delete_language_model(self, context: RequestContext, model_name: ModelName) -> None:
        """Deletes a custom language model. To use this operation, specify the name
        of the language model you want to delete using ``ModelName``. Language
        model names are case sensitive.

        :param model_name: The name of the custom language model you want to delete.
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        """
        raise NotImplementedError

    @handler("DeleteMedicalTranscriptionJob")
    def delete_medical_transcription_job(
        self, context: RequestContext, medical_transcription_job_name: TranscriptionJobName
    ) -> None:
        """Deletes a medical transcription job. To use this operation, specify the
        name of the job you want to delete using
        ``MedicalTranscriptionJobName``. Job names are case sensitive.

        :param medical_transcription_job_name: The name of the medical transcription job you want to delete.
        :raises LimitExceededException:
        :raises BadRequestException:
        :raises InternalFailureException:
        """
        raise NotImplementedError

    @handler("DeleteMedicalVocabulary")
    def delete_medical_vocabulary(
        self, context: RequestContext, vocabulary_name: VocabularyName
    ) -> None:
        """Deletes a custom medical vocabulary. To use this operation, specify the
        name of the vocabulary you want to delete using ``VocabularyName``.
        Vocabulary names are case sensitive.

        :param vocabulary_name: The name of the custom medical vocabulary you want to delete.
        :raises NotFoundException:
        :raises LimitExceededException:
        :raises BadRequestException:
        :raises InternalFailureException:
        """
        raise NotImplementedError

    @handler("DeleteTranscriptionJob")
    def delete_transcription_job(
        self, context: RequestContext, transcription_job_name: TranscriptionJobName
    ) -> None:
        """Deletes a transcription job. To use this operation, specify the name of
        the job you want to delete using ``TranscriptionJobName``. Job names are
        case sensitive.

        :param transcription_job_name: The name of the transcription job you want to delete.
        :raises LimitExceededException:
        :raises BadRequestException:
        :raises InternalFailureException:
        """
        raise NotImplementedError

    @handler("DeleteVocabulary")
    def delete_vocabulary(self, context: RequestContext, vocabulary_name: VocabularyName) -> None:
        """Deletes a custom vocabulary. To use this operation, specify the name of
        the vocabulary you want to delete using ``VocabularyName``. Vocabulary
        names are case sensitive.

        :param vocabulary_name: The name of the custom vocabulary you want to delete.
        :raises NotFoundException:
        :raises LimitExceededException:
        :raises BadRequestException:
        :raises InternalFailureException:
        """
        raise NotImplementedError

    @handler("DeleteVocabularyFilter")
    def delete_vocabulary_filter(
        self, context: RequestContext, vocabulary_filter_name: VocabularyFilterName
    ) -> None:
        """Deletes a vocabulary filter. To use this operation, specify the name of
        the vocabulary filter you want to delete using ``VocabularyFilterName``.
        Vocabulary filter names are case sensitive.

        :param vocabulary_filter_name: The name of the custom vocabulary filter you want to delete.
        :raises NotFoundException:
        :raises LimitExceededException:
        :raises BadRequestException:
        :raises InternalFailureException:
        """
        raise NotImplementedError

    @handler("DescribeLanguageModel")
    def describe_language_model(
        self, context: RequestContext, model_name: ModelName
    ) -> DescribeLanguageModelResponse:
        """Provides information about the specified custom language model.

        This operation also shows if the base language model you used to create
        your custom language model has been updated. If Amazon Transcribe has
        updated the base model, you can create a new custom language model using
        the updated base model.

        If you tried to create a new custom language model and the request
        wasn't successful, you can use ``DescribeLanguageModel`` to help
        identify the reason for this failure.

        To get a list of your custom language models, use the operation.

        :param model_name: The name of the custom language model you want information about.
        :returns: DescribeLanguageModelResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        :raises NotFoundException:
        """
        raise NotImplementedError

    @handler("GetCallAnalyticsCategory")
    def get_call_analytics_category(
        self, context: RequestContext, category_name: CategoryName
    ) -> GetCallAnalyticsCategoryResponse:
        """Provides information about the specified Call Analytics category.

        To get a list of your Call Analytics categories, use the operation.

        :param category_name: The name of the Call Analytics category you want information about.
        :returns: GetCallAnalyticsCategoryResponse
        :raises NotFoundException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        :raises BadRequestException:
        """
        raise NotImplementedError

    @handler("GetCallAnalyticsJob")
    def get_call_analytics_job(
        self, context: RequestContext, call_analytics_job_name: CallAnalyticsJobName
    ) -> GetCallAnalyticsJobResponse:
        """Provides information about the specified Call Analytics job.

        To view the job's status, refer to ``CallAnalyticsJobStatus``. If the
        status is ``COMPLETED``, the job is finished. You can find your
        completed transcript at the URI specified in ``TranscriptFileUri``. If
        the status is ``FAILED``, ``FailureReason`` provides details on why your
        transcription job failed.

        If you enabled personally identifiable information (PII) redaction, the
        redacted transcript appears at the location specified in
        ``RedactedTranscriptFileUri``.

        If you chose to redact the audio in your media file, you can find your
        redacted media file at the location specified in
        ``RedactedMediaFileUri``.

        To get a list of your Call Analytics jobs, use the operation.

        :param call_analytics_job_name: The name of the Call Analytics job you want information about.
        :returns: GetCallAnalyticsJobResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        :raises NotFoundException:
        """
        raise NotImplementedError

    @handler("GetMedicalTranscriptionJob")
    def get_medical_transcription_job(
        self, context: RequestContext, medical_transcription_job_name: TranscriptionJobName
    ) -> GetMedicalTranscriptionJobResponse:
        """Provides information about the specified medical transcription job.

        To view the status of the specified medical transcription job, check the
        ``TranscriptionJobStatus`` field. If the status is ``COMPLETED``, the
        job is finished and you can find the results at the location specified
        in ``TranscriptFileUri``. If the status is ``FAILED``, ``FailureReason``
        provides details on why your transcription job failed.

        To get a list of your medical transcription jobs, use the operation.

        :param medical_transcription_job_name: The name of the medical transcription job you want information about.
        :returns: GetMedicalTranscriptionJobResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        :raises NotFoundException:
        """
        raise NotImplementedError

    @handler("GetMedicalVocabulary")
    def get_medical_vocabulary(
        self, context: RequestContext, vocabulary_name: VocabularyName
    ) -> GetMedicalVocabularyResponse:
        """Provides information about the specified custom medical vocabulary.

        To view the status of the specified medical vocabulary, check the
        ``VocabularyState`` field. If the status is ``READY``, your vocabulary
        is available to use. If the status is ``FAILED``, ``FailureReason``
        provides details on why your vocabulary failed.

        To get a list of your custom medical vocabularies, use the operation.

        :param vocabulary_name: The name of the custom medical vocabulary you want information about.
        :returns: GetMedicalVocabularyResponse
        :raises NotFoundException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        :raises BadRequestException:
        """
        raise NotImplementedError

    @handler("GetTranscriptionJob")
    def get_transcription_job(
        self, context: RequestContext, transcription_job_name: TranscriptionJobName
    ) -> GetTranscriptionJobResponse:
        """Provides information about the specified transcription job.

        To view the status of the specified transcription job, check the
        ``TranscriptionJobStatus`` field. If the status is ``COMPLETED``, the
        job is finished and you can find the results at the location specified
        in ``TranscriptFileUri``. If the status is ``FAILED``, ``FailureReason``
        provides details on why your transcription job failed.

        If you enabled content redaction, the redacted transcript can be found
        at the location specified in ``RedactedTranscriptFileUri``.

        To get a list of your transcription jobs, use the operation.

        :param transcription_job_name: The name of the transcription job you want information about.
        :returns: GetTranscriptionJobResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        :raises NotFoundException:
        """
        raise NotImplementedError

    @handler("GetVocabulary")
    def get_vocabulary(
        self, context: RequestContext, vocabulary_name: VocabularyName
    ) -> GetVocabularyResponse:
        """Provides information about the specified custom vocabulary.

        To view the status of the specified vocabulary, check the
        ``VocabularyState`` field. If the status is ``READY``, your vocabulary
        is available to use. If the status is ``FAILED``, ``FailureReason``
        provides details on why your vocabulary failed.

        To get a list of your custom vocabularies, use the operation.

        :param vocabulary_name: The name of the custom vocabulary you want information about.
        :returns: GetVocabularyResponse
        :raises NotFoundException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        :raises BadRequestException:
        """
        raise NotImplementedError

    @handler("GetVocabularyFilter")
    def get_vocabulary_filter(
        self, context: RequestContext, vocabulary_filter_name: VocabularyFilterName
    ) -> GetVocabularyFilterResponse:
        """Provides information about the specified custom vocabulary filter.

        To view the status of the specified vocabulary filter, check the
        ``VocabularyState`` field. If the status is ``READY``, your vocabulary
        is available to use. If the status is ``FAILED``, ``FailureReason``
        provides details on why your vocabulary filter failed.

        To get a list of your custom vocabulary filters, use the operation.

        :param vocabulary_filter_name: The name of the custom vocabulary filter you want information about.
        :returns: GetVocabularyFilterResponse
        :raises NotFoundException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        :raises BadRequestException:
        """
        raise NotImplementedError

    @handler("ListCallAnalyticsCategories")
    def list_call_analytics_categories(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListCallAnalyticsCategoriesResponse:
        """Provides a list of Call Analytics categories, including all rules that
        make up each category.

        To get detailed information about a specific Call Analytics category,
        use the operation.

        :param next_token: If your ``ListCallAnalyticsCategories`` request returns more results
        than can be displayed, ``NextToken`` is displayed in the response with
        an associated string.
        :param max_results: The maximum number of Call Analytics categories to return in each page
        of results.
        :returns: ListCallAnalyticsCategoriesResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        """
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
        """Provides a list of Call Analytics jobs that match the specified
        criteria. If no criteria are specified, all Call Analytics jobs are
        returned.

        To get detailed information about a specific Call Analytics job, use the
        operation.

        :param status: Returns only Call Analytics jobs with the specified status.
        :param job_name_contains: Returns only the Call Analytics jobs that contain the specified string.
        :param next_token: If your ``ListCallAnalyticsJobs`` request returns more results than can
        be displayed, ``NextToken`` is displayed in the response with an
        associated string.
        :param max_results: The maximum number of Call Analytics jobs to return in each page of
        results.
        :returns: ListCallAnalyticsJobsResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        """
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
        """Provides a list of custom language models that match the specified
        criteria. If no criteria are specified, all language models are
        returned.

        To get detailed information about a specific custom language model, use
        the operation.

        :param status_equals: Returns only custom language models with the specified status.
        :param name_contains: Returns only the custom language models that contain the specified
        string.
        :param next_token: If your ``ListLanguageModels`` request returns more results than can be
        displayed, ``NextToken`` is displayed in the response with an associated
        string.
        :param max_results: The maximum number of custom language models to return in each page of
        results.
        :returns: ListLanguageModelsResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        """
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
        """Provides a list of medical transcription jobs that match the specified
        criteria. If no criteria are specified, all medical transcription jobs
        are returned.

        To get detailed information about a specific medical transcription job,
        use the operation.

        :param status: Returns only medical transcription jobs with the specified status.
        :param job_name_contains: Returns only the medical transcription jobs that contain the specified
        string.
        :param next_token: If your ``ListMedicalTranscriptionJobs`` request returns more results
        than can be displayed, ``NextToken`` is displayed in the response with
        an associated string.
        :param max_results: The maximum number of medical transcription jobs to return in each page
        of results.
        :returns: ListMedicalTranscriptionJobsResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        """
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
        """Provides a list of custom medical vocabularies that match the specified
        criteria. If no criteria are specified, all custom medical vocabularies
        are returned.

        To get detailed information about a specific custom medical vocabulary,
        use the operation.

        :param next_token: If your ``ListMedicalVocabularies`` request returns more results than
        can be displayed, ``NextToken`` is displayed in the response with an
        associated string.
        :param max_results: The maximum number of custom medical vocabularies to return in each page
        of results.
        :param state_equals: Returns only custom medical vocabularies with the specified state.
        :param name_contains: Returns only the custom medical vocabularies that contain the specified
        string.
        :returns: ListMedicalVocabulariesResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        """
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: TranscribeArn
    ) -> ListTagsForResourceResponse:
        """Lists all tags associated with the specified transcription job,
        vocabulary, model, or resource.

        To learn more about using tags with Amazon Transcribe, refer to `Tagging
        resources <https://docs.aws.amazon.com/transcribe/latest/dg/tagging.html>`__.

        :param resource_arn: Returns a list of all tags associated with the specified Amazon Resource
        Name (ARN).
        :returns: ListTagsForResourceResponse
        :raises BadRequestException:
        :raises NotFoundException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        """
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
        """Provides a list of transcription jobs that match the specified criteria.
        If no criteria are specified, all transcription jobs are returned.

        To get detailed information about a specific transcription job, use the
        operation.

        :param status: Returns only transcription jobs with the specified status.
        :param job_name_contains: Returns only the transcription jobs that contain the specified string.
        :param next_token: If your ``ListTranscriptionJobs`` request returns more results than can
        be displayed, ``NextToken`` is displayed in the response with an
        associated string.
        :param max_results: The maximum number of transcription jobs to return in each page of
        results.
        :returns: ListTranscriptionJobsResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        """
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
        """Provides a list of custom vocabularies that match the specified
        criteria. If no criteria are specified, all custom vocabularies are
        returned.

        To get detailed information about a specific custom vocabulary, use the
        operation.

        :param next_token: If your ``ListVocabularies`` request returns more results than can be
        displayed, ``NextToken`` is displayed in the response with an associated
        string.
        :param max_results: The maximum number of custom vocabularies to return in each page of
        results.
        :param state_equals: Returns only custom vocabularies with the specified state.
        :param name_contains: Returns only the custom vocabularies that contain the specified string.
        :returns: ListVocabulariesResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        """
        raise NotImplementedError

    @handler("ListVocabularyFilters")
    def list_vocabulary_filters(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        name_contains: VocabularyFilterName = None,
    ) -> ListVocabularyFiltersResponse:
        """Provides a list of custom vocabulary filters that match the specified
        criteria. If no criteria are specified, all custom vocabularies are
        returned.

        To get detailed information about a specific custom vocabulary filter,
        use the operation.

        :param next_token: If your ``ListVocabularyFilters`` request returns more results than can
        be displayed, ``NextToken`` is displayed in the response with an
        associated string.
        :param max_results: The maximum number of custom vocabulary filters to return in each page
        of results.
        :param name_contains: Returns only the custom vocabulary filters that contain the specified
        string.
        :returns: ListVocabularyFiltersResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        """
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
        """Transcribes the audio from a customer service call and applies any
        additional Request Parameters you choose to include in your request.

        In addition to many of the standard transcription features, Call
        Analytics provides you with call characteristics, call summarization,
        speaker sentiment, and optional redaction of your text transcript and
        your audio file. You can also apply custom categories to flag specified
        conditions. To learn more about these features and insights, refer to
        `Analyzing call center audio with Call
        Analytics <https://docs.aws.amazon.com/transcribe/latest/dg/call-analytics.html>`__.

        If you want to apply categories to your Call Analytics job, you must
        create them before submitting your job request. Categories cannot be
        retroactively applied to a job. To create a new category, use the
        operation. To learn more about Call Analytics categories, see `Creating
        categories <https://docs.aws.amazon.com/transcribe/latest/dg/call-analytics-create-categories.html>`__.

        To make a ``StartCallAnalyticsJob`` request, you must first upload your
        media file into an Amazon S3 bucket; you can then specify the Amazon S3
        location of the file using the ``Media`` parameter.

        You must include the following parameters in your
        ``StartCallAnalyticsJob`` request:

        -  ``region``: The Amazon Web Services Region where you are making your
           request. For a list of Amazon Web Services Regions supported with
           Amazon Transcribe, refer to `Amazon Transcribe endpoints and
           quotas <https://docs.aws.amazon.com/general/latest/gr/transcribe.html>`__.

        -  ``CallAnalyticsJobName``: A custom name you create for your
           transcription job that is unique within your Amazon Web Services
           account.

        -  ``DataAccessRoleArn``: The Amazon Resource Name (ARN) of an IAM role
           that has permissions to access the Amazon S3 bucket that contains
           your input files.

        -  ``Media`` (``MediaFileUri`` or ``RedactedMediaFileUri``): The Amazon
           S3 location of your media file.

        With Call Analytics, you can redact the audio contained in your media
        file by including ``RedactedMediaFileUri``, instead of ``MediaFileUri``,
        to specify the location of your input audio. If you choose to redact
        your audio, you can find your redacted media at the location specified
        in the ``RedactedMediaFileUri`` field of your response.

        :param call_analytics_job_name: A unique name, chosen by you, for your Call Analytics job.
        :param media: Describes the Amazon S3 location of the media file you want to use in
        your request.
        :param output_location: The Amazon S3 location where you want your Call Analytics transcription
        output stored.
        :param output_encryption_kms_key_id: The KMS key you want to use to encrypt your Call Analytics output.
        :param data_access_role_arn: The Amazon Resource Name (ARN) of an IAM role that has permissions to
        access the Amazon S3 bucket that contains your input files.
        :param settings: Specify additional optional settings in your request, including content
        redaction; allows you to apply custom language models, vocabulary
        filters, and custom vocabularies to your Call Analytics job.
        :param channel_definitions: Allows you to specify which speaker is on which channel.
        :returns: StartCallAnalyticsJobResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        :raises ConflictException:
        """
        raise NotImplementedError

    @handler("StartMedicalTranscriptionJob", expand=False)
    def start_medical_transcription_job(
        self, context: RequestContext, request: StartMedicalTranscriptionJobRequest
    ) -> StartMedicalTranscriptionJobResponse:
        """Transcribes the audio from a medical dictation or conversation and
        applies any additional Request Parameters you choose to include in your
        request.

        In addition to many of the standard transcription features, Amazon
        Transcribe Medical provides you with a robust medical vocabulary and,
        optionally, content identification, which adds flags to personal health
        information (PHI). To learn more about these features, refer to `How
        Amazon Transcribe Medical
        works <https://docs.aws.amazon.com/transcribe/latest/dg/how-it-works-med.html>`__.

        To make a ``StartMedicalTranscriptionJob`` request, you must first
        upload your media file into an Amazon S3 bucket; you can then specify
        the S3 location of the file using the ``Media`` parameter.

        You must include the following parameters in your
        ``StartMedicalTranscriptionJob`` request:

        -  ``region``: The Amazon Web Services Region where you are making your
           request. For a list of Amazon Web Services Regions supported with
           Amazon Transcribe, refer to `Amazon Transcribe endpoints and
           quotas <https://docs.aws.amazon.com/general/latest/gr/transcribe.html>`__.

        -  ``MedicalTranscriptionJobName``: A custom name you create for your
           transcription job that is unique within your Amazon Web Services
           account.

        -  ``Media`` (``MediaFileUri``): The Amazon S3 location of your media
           file.

        -  ``LanguageCode``: This must be ``en-US``.

        -  ``OutputBucketName``: The Amazon S3 bucket where you want your
           transcript stored. If you want your output stored in a sub-folder of
           this bucket, you must also include ``OutputKey``.

        -  ``Specialty``: This must be ``PRIMARYCARE``.

        -  ``Type``: Choose whether your audio is a conversation or a dictation.

        :param medical_transcription_job_name: A unique name, chosen by you, for your medical transcription job.
        :param language_code: The language code that represents the language spoken in the input media
        file.
        :param media: Describes the Amazon S3 location of the media file you want to use in
        your request.
        :param output_bucket_name: The name of the Amazon S3 bucket where you want your medical
        transcription output stored.
        :param specialty: Specify the predominant medical specialty represented in your media.
        :param type: Specify whether your input media contains only one person
        (``DICTATION``) or contains a conversation between two people
        (``CONVERSATION``).
        :param media_sample_rate_hertz: The sample rate, in Hertz, of the audio track in your input media file.
        :param media_format: Specify the format of your input media file.
        :param output_key: Use in combination with ``OutputBucketName`` to specify the output
        location of your transcript and, optionally, a unique name for your
        output file.
        :param output_encryption_kms_key_id: The KMS key you want to use to encrypt your medical transcription
        output.
        :param kms_encryption_context: A map of plain text, non-secret key:value pairs, known as encryption
        context pairs, that provide an added layer of security for your data.
        :param settings: Specify additional optional settings in your request, including channel
        identification, alternative transcriptions, and speaker labeling; allows
        you to apply custom vocabularies to your transcription job.
        :param content_identification_type: Labels all personal health information (PHI) identified in your
        transcript.
        :param tags: Adds one or more custom tags, each in the form of a key:value pair, to a
        new medical transcription job at the time you start this new job.
        :returns: StartMedicalTranscriptionJobResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        :raises ConflictException:
        """
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
        """Transcribes the audio from a media file and applies any additional
        Request Parameters you choose to include in your request.

        To make a ``StartTranscriptionJob`` request, you must first upload your
        media file into an Amazon S3 bucket; you can then specify the Amazon S3
        location of the file using the ``Media`` parameter.

        You must include the following parameters in your
        ``StartTranscriptionJob`` request:

        -  ``region``: The Amazon Web Services Region where you are making your
           request. For a list of Amazon Web Services Regions supported with
           Amazon Transcribe, refer to `Amazon Transcribe endpoints and
           quotas <https://docs.aws.amazon.com/general/latest/gr/transcribe.html>`__.

        -  ``TranscriptionJobName``: A custom name you create for your
           transcription job that is unique within your Amazon Web Services
           account.

        -  ``Media`` (``MediaFileUri``): The Amazon S3 location of your media
           file.

        -  One of ``LanguageCode``, ``IdentifyLanguage``, or
           ``IdentifyMultipleLanguages``: If you know the language of your media
           file, specify it using the ``LanguageCode`` parameter; you can find
           all valid language codes in the `Supported
           languages <https://docs.aws.amazon.com/transcribe/latest/dg/supported-languages.html>`__
           table. If you don't know the languages spoken in your media, use
           either ``IdentifyLanguage`` or ``IdentifyMultipleLanguages`` and let
           Amazon Transcribe identify the languages for you.

        :param transcription_job_name: A unique name, chosen by you, for your transcription job.
        :param media: Describes the Amazon S3 location of the media file you want to use in
        your request.
        :param language_code: The language code that represents the language spoken in the input media
        file.
        :param media_sample_rate_hertz: The sample rate, in Hertz, of the audio track in your input media file.
        :param media_format: Specify the format of your input media file.
        :param output_bucket_name: The name of the Amazon S3 bucket where you want your transcription
        output stored.
        :param output_key: Use in combination with ``OutputBucketName`` to specify the output
        location of your transcript and, optionally, a unique name for your
        output file.
        :param output_encryption_kms_key_id: The KMS key you want to use to encrypt your transcription output.
        :param kms_encryption_context: A map of plain text, non-secret key:value pairs, known as encryption
        context pairs, that provide an added layer of security for your data.
        :param settings: Specify additional optional settings in your request, including channel
        identification, alternative transcriptions, speaker labeling; allows you
        to apply custom vocabularies and vocabulary filters.
        :param model_settings: Specify the custom language model you want to include with your
        transcription job.
        :param job_execution_settings: Allows you to control how your transcription job is processed.
        :param content_redaction: Allows you to redact or flag specified personally identifiable
        information (PII) in your transcript.
        :param identify_language: Enables automatic language identification in your transcription job
        request.
        :param identify_multiple_languages: Enables automatic multi-language identification in your transcription
        job request.
        :param language_options: You can specify two or more language codes that represent the languages
        you think may be present in your media; including more than five is not
        recommended.
        :param subtitles: Produces subtitle files for your input media.
        :param tags: Adds one or more custom tags, each in the form of a key:value pair, to a
        new transcription job at the time you start this new job.
        :param language_id_settings: If using automatic language identification (``IdentifyLanguage``) in
        your request and you want to apply a custom language model, a custom
        vocabulary, or a custom vocabulary filter, include
        ``LanguageIdSettings`` with the relevant sub-parameters
        (``VocabularyName``, ``LanguageModelName``, and
        ``VocabularyFilterName``).
        :returns: StartTranscriptionJobResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        :raises ConflictException:
        """
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: TranscribeArn, tags: TagList
    ) -> TagResourceResponse:
        """Adds one or more custom tags, each in the form of a key:value pair, to
        the specified resource.

        To learn more about using tags with Amazon Transcribe, refer to `Tagging
        resources <https://docs.aws.amazon.com/transcribe/latest/dg/tagging.html>`__.

        :param resource_arn: The Amazon Resource Name (ARN) of the resource you want to tag.
        :param tags: Adds one or more custom tags, each in the form of a key:value pair, to
        the specified resource.
        :returns: TagResourceResponse
        :raises BadRequestException:
        :raises ConflictException:
        :raises NotFoundException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        """
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: TranscribeArn, tag_keys: TagKeyList
    ) -> UntagResourceResponse:
        """Removes the specified tags from the specified Amazon Transcribe
        resource.

        If you include ``UntagResource`` in your request, you must also include
        ``ResourceArn`` and ``TagKeys``.

        :param resource_arn: The Amazon Resource Name (ARN) of the Amazon Transcribe resource you
        want to remove tags from.
        :param tag_keys: Removes the specified tag keys from the specified Amazon Transcribe
        resource.
        :returns: UntagResourceResponse
        :raises LimitExceededException:
        :raises BadRequestException:
        :raises ConflictException:
        :raises NotFoundException:
        :raises InternalFailureException:
        """
        raise NotImplementedError

    @handler("UpdateCallAnalyticsCategory")
    def update_call_analytics_category(
        self, context: RequestContext, category_name: CategoryName, rules: RuleList
    ) -> UpdateCallAnalyticsCategoryResponse:
        """Updates the specified Call Analytics category with new rules. Note that
        the ``UpdateCallAnalyticsCategory`` operation overwrites all existing
        rules contained in the specified category. You cannot append additional
        rules onto an existing category.

        To create a new category, see .

        :param category_name: The name of the Call Analytics category you want to update.
        :param rules: The rules used for the updated Call Analytics category.
        :returns: UpdateCallAnalyticsCategoryResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        :raises NotFoundException:
        :raises ConflictException:
        """
        raise NotImplementedError

    @handler("UpdateMedicalVocabulary")
    def update_medical_vocabulary(
        self,
        context: RequestContext,
        vocabulary_name: VocabularyName,
        language_code: LanguageCode,
        vocabulary_file_uri: Uri,
    ) -> UpdateMedicalVocabularyResponse:
        """Updates an existing custom medical vocabulary with new values. This
        operation overwrites all existing information with your new values; you
        cannot append new terms onto an existing vocabulary.

        :param vocabulary_name: The name of the custom medical vocabulary you want to update.
        :param language_code: The language code that represents the language of the entries in the
        custom vocabulary you want to update.
        :param vocabulary_file_uri: The Amazon S3 location of the text file that contains your custom
        medical vocabulary.
        :returns: UpdateMedicalVocabularyResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        :raises NotFoundException:
        :raises ConflictException:
        """
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
        """Updates an existing custom vocabulary with new values. This operation
        overwrites all existing information with your new values; you cannot
        append new terms onto an existing vocabulary.

        :param vocabulary_name: The name of the custom vocabulary you want to update.
        :param language_code: The language code that represents the language of the entries in the
        custom vocabulary you want to update.
        :param phrases: Use this parameter if you want to update your vocabulary by including
        all desired terms, as comma-separated values, within your request.
        :param vocabulary_file_uri: The Amazon S3 location of the text file that contains your custom
        vocabulary.
        :returns: UpdateVocabularyResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        :raises NotFoundException:
        :raises ConflictException:
        """
        raise NotImplementedError

    @handler("UpdateVocabularyFilter")
    def update_vocabulary_filter(
        self,
        context: RequestContext,
        vocabulary_filter_name: VocabularyFilterName,
        words: Words = None,
        vocabulary_filter_file_uri: Uri = None,
    ) -> UpdateVocabularyFilterResponse:
        """Updates an existing custom vocabulary filter with a new list of words.
        The new list you provide overwrites all previous entries; you cannot
        append new terms onto an existing vocabulary filter.

        :param vocabulary_filter_name: The name of the custom vocabulary filter you want to update.
        :param words: Use this parameter if you want to update your vocabulary filter by
        including all desired terms, as comma-separated values, within your
        request.
        :param vocabulary_filter_file_uri: The Amazon S3 location of the text file that contains your custom
        vocabulary filter terms.
        :returns: UpdateVocabularyFilterResponse
        :raises BadRequestException:
        :raises LimitExceededException:
        :raises InternalFailureException:
        :raises NotFoundException:
        """
        raise NotImplementedError
