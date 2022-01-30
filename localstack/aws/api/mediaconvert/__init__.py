import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

_boolean = bool
_double = float
_doubleMin0 = float
_doubleMin0Max1 = float
_doubleMin0Max2147483647 = float
_doubleMinNegative59Max0 = float
_doubleMinNegative60Max3 = float
_doubleMinNegative60Max6 = float
_doubleMinNegative60MaxNegative1 = float
_doubleMinNegative6Max3 = float
_integer = int
_integerMin0Max0 = int
_integerMin0Max1 = int
_integerMin0Max10 = int
_integerMin0Max100 = int
_integerMin0Max1000 = int
_integerMin0Max10000 = int
_integerMin0Max1152000000 = int
_integerMin0Max128 = int
_integerMin0Max1466400000 = int
_integerMin0Max15 = int
_integerMin0Max16 = int
_integerMin0Max2147483647 = int
_integerMin0Max255 = int
_integerMin0Max3 = int
_integerMin0Max30 = int
_integerMin0Max30000 = int
_integerMin0Max3600 = int
_integerMin0Max4 = int
_integerMin0Max4000 = int
_integerMin0Max4194303 = int
_integerMin0Max47185920 = int
_integerMin0Max500 = int
_integerMin0Max50000 = int
_integerMin0Max65534 = int
_integerMin0Max65535 = int
_integerMin0Max7 = int
_integerMin0Max8 = int
_integerMin0Max9 = int
_integerMin0Max96 = int
_integerMin0Max99 = int
_integerMin100000Max100000000 = int
_integerMin1000Max1152000000 = int
_integerMin1000Max1466400000 = int
_integerMin1000Max288000000 = int
_integerMin1000Max30000 = int
_integerMin1000Max300000000 = int
_integerMin1000Max480000000 = int
_integerMin10Max48 = int
_integerMin16000Max320000 = int
_integerMin16000Max48000 = int
_integerMin16Max24 = int
_integerMin1Max1 = int
_integerMin1Max10 = int
_integerMin1Max100 = int
_integerMin1Max10000000 = int
_integerMin1Max1001 = int
_integerMin1Max17895697 = int
_integerMin1Max2 = int
_integerMin1Max20 = int
_integerMin1Max2048 = int
_integerMin1Max2147483640 = int
_integerMin1Max2147483647 = int
_integerMin1Max31 = int
_integerMin1Max32 = int
_integerMin1Max4 = int
_integerMin1Max4096 = int
_integerMin1Max512 = int
_integerMin1Max6 = int
_integerMin1Max60000 = int
_integerMin1Max64 = int
_integerMin22050Max48000 = int
_integerMin24Max60000 = int
_integerMin25Max10000 = int
_integerMin25Max2000 = int
_integerMin2Max2147483647 = int
_integerMin2Max4096 = int
_integerMin32000Max192000 = int
_integerMin32000Max384000 = int
_integerMin32000Max48000 = int
_integerMin32Max8182 = int
_integerMin32Max8192 = int
_integerMin384000Max1024000 = int
_integerMin3Max15 = int
_integerMin48000Max48000 = int
_integerMin4Max12 = int
_integerMin6000Max1024000 = int
_integerMin64000Max640000 = int
_integerMin8000Max192000 = int
_integerMin8000Max96000 = int
_integerMin8Max12 = int
_integerMin8Max4096 = int
_integerMin96Max600 = int
_integerMinNegative1000Max1000 = int
_integerMinNegative180Max180 = int
_integerMinNegative1Max10 = int
_integerMinNegative1Max3 = int
_integerMinNegative2147483648Max2147483647 = int
_integerMinNegative2Max3 = int
_integerMinNegative50Max50 = int
_integerMinNegative5Max5 = int
_integerMinNegative60Max6 = int
_integerMinNegative70Max0 = int
_string = str
_stringMin0 = str
_stringMin1 = str
_stringMin11Max11Pattern01D20305D205D = str
_stringMin14PatternS3BmpBMPPngPNGHttpsBmpBMPPngPNG = str
_stringMin14PatternS3BmpBMPPngPNGTgaTGAHttpsBmpBMPPngPNGTgaTGA = str
_stringMin14PatternS3Mov09PngHttpsMov09Png = str
_stringMin14PatternS3SccSCCTtmlTTMLDfxpDFXPStlSTLSrtSRTXmlXMLSmiSMIVttVTTWebvttWEBVTTHttpsSccSCCTtmlTTMLDfxpDFXPStlSTLSrtSRTXmlXMLSmiSMIVttVTTWebvttWEBVTT = (
    str
)
_stringMin14PatternS3XmlXMLHttpsXmlXML = str
_stringMin16Max24PatternAZaZ0922AZaZ0916 = str
_stringMin1Max100000 = str
_stringMin1Max20 = str
_stringMin1Max256 = str
_stringMin1Max50 = str
_stringMin1Max50PatternAZAZ09 = str
_stringMin1Max512PatternAZAZ09 = str
_stringMin24Max512PatternAZaZ0902 = str
_stringMin32Max32Pattern09aFAF32 = str
_stringMin36Max36Pattern09aFAF809aFAF409aFAF409aFAF409aFAF12 = str
_stringMin3Max3Pattern1809aFAF09aEAE = str
_stringMin3Max3PatternAZaZ3 = str
_stringMin6Max8Pattern09aFAF609aFAF2 = str
_stringMin9Max19PatternAZ26EastWestCentralNorthSouthEastWest1912 = str
_stringPattern = str
_stringPattern010920405090509092 = str
_stringPattern01D20305D205D = str
_stringPattern0940191020191209301 = str
_stringPattern09aFAF809aFAF409aFAF409aFAF409aFAF12 = str
_stringPattern0xAFaF0908190908 = str
_stringPatternAZaZ0902 = str
_stringPatternAZaZ0932 = str
_stringPatternAZaZ23AZaZ = str
_stringPatternArnAwsUsGovAcm = str
_stringPatternArnAwsUsGovCnKmsAZ26EastWestCentralNorthSouthEastWest1912D12KeyAFAF098AFAF094AFAF094AFAF094AFAF0912MrkAFAF0932 = (
    str
)
_stringPatternDD = str
_stringPatternHttps = str
_stringPatternHttpsKantarmediaCom = str
_stringPatternIdentityAZaZ26AZaZ09163 = str
_stringPatternS3 = str
_stringPatternS3ASSETMAPXml = str
_stringPatternS3MM2PPMM2VVMMPPEEGGMMPP3AAVVIIMMPP4FFLLVVMMPPTTMMPPGGMM4VVTTRRPPFF4VVMM2TTSSTTSS264HH264MMKKVVMMKKAAMMOOVVMMTTSSMM2TTWWMMVVaAAASSFFVVOOBB3GGPP3GGPPPPMMXXFFDDIIVVXXXXVVIIDDRRAAWWDDVVGGXXFFMM1VV3GG2VVMMFFMM3UU8WWEEBBMMLLCCHHGGXXFFMMPPEEGG2MMXXFFMMPPEEGG2MMXXFFHHDDWWAAVVYY4MMXXMMLLOOGGGGaAAATTMMOOSSHttpsMM2VVMMPPEEGGMMPP3AAVVIIMMPP4FFLLVVMMPPTTMMPPGGMM4VVTTRRPPFF4VVMM2TTSSTTSS264HH264MMKKVVMMKKAAMMOOVVMMTTSSMM2TTWWMMVVaAAASSFFVVOOBB3GGPP3GGPPPPMMXXFFDDIIVVXXXXVVIIDDRRAAWWDDVVGGXXFFMM1VV3GG2VVMMFFMM3UU8WWEEBBMMLLCCHHGGXXFFMMPPEEGG2MMXXFFMMPPEEGG2MMXXFFHHDDWWAAVVYY4MMXXMMLLOOGGGGaAAATTMMOOSS = (
    str
)
_stringPatternS3MM2PPWWEEBBMMMM2VVMMPPEEGGMMPP3AAVVIIMMPP4FFLLVVMMPPTTMMPPGGMM4VVTTRRPPFF4VVMM2TTSSTTSS264HH264MMKKVVMMKKAAMMOOVVMMTTSSMM2TTWWMMVVaAAASSFFVVOOBB3GGPP3GGPPPPMMXXFFDDIIVVXXXXVVIIDDRRAAWWDDVVGGXXFFMM1VV3GG2VVMMFFMM3UU8LLCCHHGGXXFFMMPPEEGG2MMXXFFMMPPEEGG2MMXXFFHHDDWWAAVVYY4MMAAAACCAAIIFFFFMMPP2AACC3EECC3DDTTSSEEAATTMMOOSSOOGGGGaAHttpsMM2VVMMPPEEGGMMPP3AAVVIIMMPP4FFLLVVMMPPTTMMPPGGMM4VVTTRRPPFF4VVMM2TTSSTTSS264HH264MMKKVVMMKKAAMMOOVVMMTTSSMM2TTWWMMVVaAAASSFFVVOOBB3GGPP3GGPPPPMMXXFFDDIIVVXXXXVVIIDDRRAAWWDDVVGGXXFFMM1VV3GG2VVMMFFMM3UU8LLCCHHGGXXFFMMPPEEGG2MMXXFFMMPPEEGG2MMXXFFHHDDWWAAVVYY4MMAAAACCAAIIFFFFMMPP2AACC3EECC3DDTTSSEEAATTMMOOSSOOGGGGaA = (
    str
)
_stringPatternSNManifestConfirmConditionNotificationNS = str
_stringPatternSNSignalProcessingNotificationNS = str
_stringPatternW = str
_stringPatternWS = str


class AacAudioDescriptionBroadcasterMix(str):
    BROADCASTER_MIXED_AD = "BROADCASTER_MIXED_AD"
    NORMAL = "NORMAL"


class AacCodecProfile(str):
    LC = "LC"
    HEV1 = "HEV1"
    HEV2 = "HEV2"


class AacCodingMode(str):
    AD_RECEIVER_MIX = "AD_RECEIVER_MIX"
    CODING_MODE_1_0 = "CODING_MODE_1_0"
    CODING_MODE_1_1 = "CODING_MODE_1_1"
    CODING_MODE_2_0 = "CODING_MODE_2_0"
    CODING_MODE_5_1 = "CODING_MODE_5_1"


class AacRateControlMode(str):
    CBR = "CBR"
    VBR = "VBR"


class AacRawFormat(str):
    LATM_LOAS = "LATM_LOAS"
    NONE = "NONE"


class AacSpecification(str):
    MPEG2 = "MPEG2"
    MPEG4 = "MPEG4"


class AacVbrQuality(str):
    LOW = "LOW"
    MEDIUM_LOW = "MEDIUM_LOW"
    MEDIUM_HIGH = "MEDIUM_HIGH"
    HIGH = "HIGH"


class Ac3BitstreamMode(str):
    COMPLETE_MAIN = "COMPLETE_MAIN"
    COMMENTARY = "COMMENTARY"
    DIALOGUE = "DIALOGUE"
    EMERGENCY = "EMERGENCY"
    HEARING_IMPAIRED = "HEARING_IMPAIRED"
    MUSIC_AND_EFFECTS = "MUSIC_AND_EFFECTS"
    VISUALLY_IMPAIRED = "VISUALLY_IMPAIRED"
    VOICE_OVER = "VOICE_OVER"


class Ac3CodingMode(str):
    CODING_MODE_1_0 = "CODING_MODE_1_0"
    CODING_MODE_1_1 = "CODING_MODE_1_1"
    CODING_MODE_2_0 = "CODING_MODE_2_0"
    CODING_MODE_3_2_LFE = "CODING_MODE_3_2_LFE"


class Ac3DynamicRangeCompressionLine(str):
    FILM_STANDARD = "FILM_STANDARD"
    FILM_LIGHT = "FILM_LIGHT"
    MUSIC_STANDARD = "MUSIC_STANDARD"
    MUSIC_LIGHT = "MUSIC_LIGHT"
    SPEECH = "SPEECH"
    NONE = "NONE"


class Ac3DynamicRangeCompressionProfile(str):
    FILM_STANDARD = "FILM_STANDARD"
    NONE = "NONE"


class Ac3DynamicRangeCompressionRf(str):
    FILM_STANDARD = "FILM_STANDARD"
    FILM_LIGHT = "FILM_LIGHT"
    MUSIC_STANDARD = "MUSIC_STANDARD"
    MUSIC_LIGHT = "MUSIC_LIGHT"
    SPEECH = "SPEECH"
    NONE = "NONE"


class Ac3LfeFilter(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class Ac3MetadataControl(str):
    FOLLOW_INPUT = "FOLLOW_INPUT"
    USE_CONFIGURED = "USE_CONFIGURED"


class AccelerationMode(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"
    PREFERRED = "PREFERRED"


class AccelerationStatus(str):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    IN_PROGRESS = "IN_PROGRESS"
    ACCELERATED = "ACCELERATED"
    NOT_ACCELERATED = "NOT_ACCELERATED"


class AfdSignaling(str):
    NONE = "NONE"
    AUTO = "AUTO"
    FIXED = "FIXED"


class AlphaBehavior(str):
    DISCARD = "DISCARD"
    REMAP_TO_LUMA = "REMAP_TO_LUMA"


class AncillaryConvert608To708(str):
    UPCONVERT = "UPCONVERT"
    DISABLED = "DISABLED"


class AncillaryTerminateCaptions(str):
    END_OF_INPUT = "END_OF_INPUT"
    DISABLED = "DISABLED"


class AntiAlias(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class AudioChannelTag(str):
    L = "L"
    R = "R"
    C = "C"
    LFE = "LFE"
    LS = "LS"
    RS = "RS"
    LC = "LC"
    RC = "RC"
    CS = "CS"
    LSD = "LSD"
    RSD = "RSD"
    TCS = "TCS"
    VHL = "VHL"
    VHC = "VHC"
    VHR = "VHR"


class AudioCodec(str):
    AAC = "AAC"
    MP2 = "MP2"
    MP3 = "MP3"
    WAV = "WAV"
    AIFF = "AIFF"
    AC3 = "AC3"
    EAC3 = "EAC3"
    EAC3_ATMOS = "EAC3_ATMOS"
    VORBIS = "VORBIS"
    OPUS = "OPUS"
    PASSTHROUGH = "PASSTHROUGH"


class AudioDefaultSelection(str):
    DEFAULT = "DEFAULT"
    NOT_DEFAULT = "NOT_DEFAULT"


class AudioLanguageCodeControl(str):
    FOLLOW_INPUT = "FOLLOW_INPUT"
    USE_CONFIGURED = "USE_CONFIGURED"


class AudioNormalizationAlgorithm(str):
    ITU_BS_1770_1 = "ITU_BS_1770_1"
    ITU_BS_1770_2 = "ITU_BS_1770_2"
    ITU_BS_1770_3 = "ITU_BS_1770_3"
    ITU_BS_1770_4 = "ITU_BS_1770_4"


class AudioNormalizationAlgorithmControl(str):
    CORRECT_AUDIO = "CORRECT_AUDIO"
    MEASURE_ONLY = "MEASURE_ONLY"


class AudioNormalizationLoudnessLogging(str):
    LOG = "LOG"
    DONT_LOG = "DONT_LOG"


class AudioNormalizationPeakCalculation(str):
    TRUE_PEAK = "TRUE_PEAK"
    NONE = "NONE"


class AudioSelectorType(str):
    PID = "PID"
    TRACK = "TRACK"
    LANGUAGE_CODE = "LANGUAGE_CODE"
    HLS_RENDITION_GROUP = "HLS_RENDITION_GROUP"


class AudioTypeControl(str):
    FOLLOW_INPUT = "FOLLOW_INPUT"
    USE_CONFIGURED = "USE_CONFIGURED"


class Av1AdaptiveQuantization(str):
    OFF = "OFF"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    HIGHER = "HIGHER"
    MAX = "MAX"


class Av1BitDepth(str):
    BIT_8 = "BIT_8"
    BIT_10 = "BIT_10"


class Av1FramerateControl(str):
    INITIALIZE_FROM_SOURCE = "INITIALIZE_FROM_SOURCE"
    SPECIFIED = "SPECIFIED"


class Av1FramerateConversionAlgorithm(str):
    DUPLICATE_DROP = "DUPLICATE_DROP"
    INTERPOLATE = "INTERPOLATE"
    FRAMEFORMER = "FRAMEFORMER"


class Av1RateControlMode(str):
    QVBR = "QVBR"


class Av1SpatialAdaptiveQuantization(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class AvcIntraClass(str):
    CLASS_50 = "CLASS_50"
    CLASS_100 = "CLASS_100"
    CLASS_200 = "CLASS_200"
    CLASS_4K_2K = "CLASS_4K_2K"


class AvcIntraFramerateControl(str):
    INITIALIZE_FROM_SOURCE = "INITIALIZE_FROM_SOURCE"
    SPECIFIED = "SPECIFIED"


class AvcIntraFramerateConversionAlgorithm(str):
    DUPLICATE_DROP = "DUPLICATE_DROP"
    INTERPOLATE = "INTERPOLATE"
    FRAMEFORMER = "FRAMEFORMER"


class AvcIntraInterlaceMode(str):
    PROGRESSIVE = "PROGRESSIVE"
    TOP_FIELD = "TOP_FIELD"
    BOTTOM_FIELD = "BOTTOM_FIELD"
    FOLLOW_TOP_FIELD = "FOLLOW_TOP_FIELD"
    FOLLOW_BOTTOM_FIELD = "FOLLOW_BOTTOM_FIELD"


class AvcIntraScanTypeConversionMode(str):
    INTERLACED = "INTERLACED"
    INTERLACED_OPTIMIZE = "INTERLACED_OPTIMIZE"


class AvcIntraSlowPal(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class AvcIntraTelecine(str):
    NONE = "NONE"
    HARD = "HARD"


class AvcIntraUhdQualityTuningLevel(str):
    SINGLE_PASS = "SINGLE_PASS"
    MULTI_PASS = "MULTI_PASS"


class BillingTagsSource(str):
    QUEUE = "QUEUE"
    PRESET = "PRESET"
    JOB_TEMPLATE = "JOB_TEMPLATE"
    JOB = "JOB"


class BurnInSubtitleStylePassthrough(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class BurninSubtitleAlignment(str):
    CENTERED = "CENTERED"
    LEFT = "LEFT"
    AUTO = "AUTO"


class BurninSubtitleApplyFontColor(str):
    WHITE_TEXT_ONLY = "WHITE_TEXT_ONLY"
    ALL_TEXT = "ALL_TEXT"


class BurninSubtitleBackgroundColor(str):
    NONE = "NONE"
    BLACK = "BLACK"
    WHITE = "WHITE"
    AUTO = "AUTO"


class BurninSubtitleFallbackFont(str):
    BEST_MATCH = "BEST_MATCH"
    MONOSPACED_SANSSERIF = "MONOSPACED_SANSSERIF"
    MONOSPACED_SERIF = "MONOSPACED_SERIF"
    PROPORTIONAL_SANSSERIF = "PROPORTIONAL_SANSSERIF"
    PROPORTIONAL_SERIF = "PROPORTIONAL_SERIF"


class BurninSubtitleFontColor(str):
    WHITE = "WHITE"
    BLACK = "BLACK"
    YELLOW = "YELLOW"
    RED = "RED"
    GREEN = "GREEN"
    BLUE = "BLUE"
    HEX = "HEX"
    AUTO = "AUTO"


class BurninSubtitleOutlineColor(str):
    BLACK = "BLACK"
    WHITE = "WHITE"
    YELLOW = "YELLOW"
    RED = "RED"
    GREEN = "GREEN"
    BLUE = "BLUE"
    AUTO = "AUTO"


class BurninSubtitleShadowColor(str):
    NONE = "NONE"
    BLACK = "BLACK"
    WHITE = "WHITE"
    AUTO = "AUTO"


class BurninSubtitleTeletextSpacing(str):
    FIXED_GRID = "FIXED_GRID"
    PROPORTIONAL = "PROPORTIONAL"
    AUTO = "AUTO"


class CaptionDestinationType(str):
    BURN_IN = "BURN_IN"
    DVB_SUB = "DVB_SUB"
    EMBEDDED = "EMBEDDED"
    EMBEDDED_PLUS_SCTE20 = "EMBEDDED_PLUS_SCTE20"
    IMSC = "IMSC"
    SCTE20_PLUS_EMBEDDED = "SCTE20_PLUS_EMBEDDED"
    SCC = "SCC"
    SRT = "SRT"
    SMI = "SMI"
    TELETEXT = "TELETEXT"
    TTML = "TTML"
    WEBVTT = "WEBVTT"


class CaptionSourceType(str):
    ANCILLARY = "ANCILLARY"
    DVB_SUB = "DVB_SUB"
    EMBEDDED = "EMBEDDED"
    SCTE20 = "SCTE20"
    SCC = "SCC"
    TTML = "TTML"
    STL = "STL"
    SRT = "SRT"
    SMI = "SMI"
    SMPTE_TT = "SMPTE_TT"
    TELETEXT = "TELETEXT"
    NULL_SOURCE = "NULL_SOURCE"
    IMSC = "IMSC"
    WEBVTT = "WEBVTT"


class CmafClientCache(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class CmafCodecSpecification(str):
    RFC_6381 = "RFC_6381"
    RFC_4281 = "RFC_4281"


class CmafEncryptionType(str):
    SAMPLE_AES = "SAMPLE_AES"
    AES_CTR = "AES_CTR"


class CmafImageBasedTrickPlay(str):
    NONE = "NONE"
    THUMBNAIL = "THUMBNAIL"
    THUMBNAIL_AND_FULLFRAME = "THUMBNAIL_AND_FULLFRAME"
    ADVANCED = "ADVANCED"


class CmafInitializationVectorInManifest(str):
    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"


class CmafIntervalCadence(str):
    FOLLOW_IFRAME = "FOLLOW_IFRAME"
    FOLLOW_CUSTOM = "FOLLOW_CUSTOM"


class CmafKeyProviderType(str):
    SPEKE = "SPEKE"
    STATIC_KEY = "STATIC_KEY"


class CmafManifestCompression(str):
    GZIP = "GZIP"
    NONE = "NONE"


class CmafManifestDurationFormat(str):
    FLOATING_POINT = "FLOATING_POINT"
    INTEGER = "INTEGER"


class CmafMpdProfile(str):
    MAIN_PROFILE = "MAIN_PROFILE"
    ON_DEMAND_PROFILE = "ON_DEMAND_PROFILE"


class CmafPtsOffsetHandlingForBFrames(str):
    ZERO_BASED = "ZERO_BASED"
    MATCH_INITIAL_PTS = "MATCH_INITIAL_PTS"


class CmafSegmentControl(str):
    SINGLE_FILE = "SINGLE_FILE"
    SEGMENTED_FILES = "SEGMENTED_FILES"


class CmafSegmentLengthControl(str):
    EXACT = "EXACT"
    GOP_MULTIPLE = "GOP_MULTIPLE"


class CmafStreamInfResolution(str):
    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"


class CmafTargetDurationCompatibilityMode(str):
    LEGACY = "LEGACY"
    SPEC_COMPLIANT = "SPEC_COMPLIANT"


class CmafWriteDASHManifest(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class CmafWriteHLSManifest(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class CmafWriteSegmentTimelineInRepresentation(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class CmfcAudioDuration(str):
    DEFAULT_CODEC_DURATION = "DEFAULT_CODEC_DURATION"
    MATCH_VIDEO_DURATION = "MATCH_VIDEO_DURATION"


class CmfcAudioTrackType(str):
    ALTERNATE_AUDIO_AUTO_SELECT_DEFAULT = "ALTERNATE_AUDIO_AUTO_SELECT_DEFAULT"
    ALTERNATE_AUDIO_AUTO_SELECT = "ALTERNATE_AUDIO_AUTO_SELECT"
    ALTERNATE_AUDIO_NOT_AUTO_SELECT = "ALTERNATE_AUDIO_NOT_AUTO_SELECT"


class CmfcDescriptiveVideoServiceFlag(str):
    DONT_FLAG = "DONT_FLAG"
    FLAG = "FLAG"


class CmfcIFrameOnlyManifest(str):
    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"


class CmfcScte35Esam(str):
    INSERT = "INSERT"
    NONE = "NONE"


class CmfcScte35Source(str):
    PASSTHROUGH = "PASSTHROUGH"
    NONE = "NONE"


class CmfcTimedMetadata(str):
    PASSTHROUGH = "PASSTHROUGH"
    NONE = "NONE"


class ColorMetadata(str):
    IGNORE = "IGNORE"
    INSERT = "INSERT"


class ColorSpace(str):
    FOLLOW = "FOLLOW"
    REC_601 = "REC_601"
    REC_709 = "REC_709"
    HDR10 = "HDR10"
    HLG_2020 = "HLG_2020"


class ColorSpaceConversion(str):
    NONE = "NONE"
    FORCE_601 = "FORCE_601"
    FORCE_709 = "FORCE_709"
    FORCE_HDR10 = "FORCE_HDR10"
    FORCE_HLG_2020 = "FORCE_HLG_2020"


class ColorSpaceUsage(str):
    FORCE = "FORCE"
    FALLBACK = "FALLBACK"


class Commitment(str):
    ONE_YEAR = "ONE_YEAR"


class ContainerType(str):
    F4V = "F4V"
    ISMV = "ISMV"
    M2TS = "M2TS"
    M3U8 = "M3U8"
    CMFC = "CMFC"
    MOV = "MOV"
    MP4 = "MP4"
    MPD = "MPD"
    MXF = "MXF"
    WEBM = "WEBM"
    RAW = "RAW"


class CopyProtectionAction(str):
    PASSTHROUGH = "PASSTHROUGH"
    STRIP = "STRIP"


class DashIsoGroupAudioChannelConfigSchemeIdUri(str):
    MPEG_CHANNEL_CONFIGURATION = "MPEG_CHANNEL_CONFIGURATION"
    DOLBY_CHANNEL_CONFIGURATION = "DOLBY_CHANNEL_CONFIGURATION"


class DashIsoHbbtvCompliance(str):
    HBBTV_1_5 = "HBBTV_1_5"
    NONE = "NONE"


class DashIsoImageBasedTrickPlay(str):
    NONE = "NONE"
    THUMBNAIL = "THUMBNAIL"
    THUMBNAIL_AND_FULLFRAME = "THUMBNAIL_AND_FULLFRAME"
    ADVANCED = "ADVANCED"


class DashIsoIntervalCadence(str):
    FOLLOW_IFRAME = "FOLLOW_IFRAME"
    FOLLOW_CUSTOM = "FOLLOW_CUSTOM"


class DashIsoMpdProfile(str):
    MAIN_PROFILE = "MAIN_PROFILE"
    ON_DEMAND_PROFILE = "ON_DEMAND_PROFILE"


class DashIsoPlaybackDeviceCompatibility(str):
    CENC_V1 = "CENC_V1"
    UNENCRYPTED_SEI = "UNENCRYPTED_SEI"


class DashIsoPtsOffsetHandlingForBFrames(str):
    ZERO_BASED = "ZERO_BASED"
    MATCH_INITIAL_PTS = "MATCH_INITIAL_PTS"


class DashIsoSegmentControl(str):
    SINGLE_FILE = "SINGLE_FILE"
    SEGMENTED_FILES = "SEGMENTED_FILES"


class DashIsoSegmentLengthControl(str):
    EXACT = "EXACT"
    GOP_MULTIPLE = "GOP_MULTIPLE"


class DashIsoWriteSegmentTimelineInRepresentation(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class DecryptionMode(str):
    AES_CTR = "AES_CTR"
    AES_CBC = "AES_CBC"
    AES_GCM = "AES_GCM"


class DeinterlaceAlgorithm(str):
    INTERPOLATE = "INTERPOLATE"
    INTERPOLATE_TICKER = "INTERPOLATE_TICKER"
    BLEND = "BLEND"
    BLEND_TICKER = "BLEND_TICKER"


class DeinterlacerControl(str):
    FORCE_ALL_FRAMES = "FORCE_ALL_FRAMES"
    NORMAL = "NORMAL"


class DeinterlacerMode(str):
    DEINTERLACE = "DEINTERLACE"
    INVERSE_TELECINE = "INVERSE_TELECINE"
    ADAPTIVE = "ADAPTIVE"


class DescribeEndpointsMode(str):
    DEFAULT = "DEFAULT"
    GET_ONLY = "GET_ONLY"


class DolbyVisionLevel6Mode(str):
    PASSTHROUGH = "PASSTHROUGH"
    RECALCULATE = "RECALCULATE"
    SPECIFY = "SPECIFY"


class DolbyVisionProfile(str):
    PROFILE_5 = "PROFILE_5"


class DropFrameTimecode(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class DvbSubSubtitleFallbackFont(str):
    BEST_MATCH = "BEST_MATCH"
    MONOSPACED_SANSSERIF = "MONOSPACED_SANSSERIF"
    MONOSPACED_SERIF = "MONOSPACED_SERIF"
    PROPORTIONAL_SANSSERIF = "PROPORTIONAL_SANSSERIF"
    PROPORTIONAL_SERIF = "PROPORTIONAL_SERIF"


class DvbSubtitleAlignment(str):
    CENTERED = "CENTERED"
    LEFT = "LEFT"
    AUTO = "AUTO"


class DvbSubtitleApplyFontColor(str):
    WHITE_TEXT_ONLY = "WHITE_TEXT_ONLY"
    ALL_TEXT = "ALL_TEXT"


class DvbSubtitleBackgroundColor(str):
    NONE = "NONE"
    BLACK = "BLACK"
    WHITE = "WHITE"
    AUTO = "AUTO"


class DvbSubtitleFontColor(str):
    WHITE = "WHITE"
    BLACK = "BLACK"
    YELLOW = "YELLOW"
    RED = "RED"
    GREEN = "GREEN"
    BLUE = "BLUE"
    HEX = "HEX"
    AUTO = "AUTO"


class DvbSubtitleOutlineColor(str):
    BLACK = "BLACK"
    WHITE = "WHITE"
    YELLOW = "YELLOW"
    RED = "RED"
    GREEN = "GREEN"
    BLUE = "BLUE"
    AUTO = "AUTO"


class DvbSubtitleShadowColor(str):
    NONE = "NONE"
    BLACK = "BLACK"
    WHITE = "WHITE"
    AUTO = "AUTO"


class DvbSubtitleStylePassthrough(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class DvbSubtitleTeletextSpacing(str):
    FIXED_GRID = "FIXED_GRID"
    PROPORTIONAL = "PROPORTIONAL"
    AUTO = "AUTO"


class DvbSubtitlingType(str):
    HEARING_IMPAIRED = "HEARING_IMPAIRED"
    STANDARD = "STANDARD"


class DvbddsHandling(str):
    NONE = "NONE"
    SPECIFIED = "SPECIFIED"
    NO_DISPLAY_WINDOW = "NO_DISPLAY_WINDOW"


class Eac3AtmosBitstreamMode(str):
    COMPLETE_MAIN = "COMPLETE_MAIN"


class Eac3AtmosCodingMode(str):
    CODING_MODE_AUTO = "CODING_MODE_AUTO"
    CODING_MODE_5_1_4 = "CODING_MODE_5_1_4"
    CODING_MODE_7_1_4 = "CODING_MODE_7_1_4"
    CODING_MODE_9_1_6 = "CODING_MODE_9_1_6"


class Eac3AtmosDialogueIntelligence(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class Eac3AtmosDownmixControl(str):
    SPECIFIED = "SPECIFIED"
    INITIALIZE_FROM_SOURCE = "INITIALIZE_FROM_SOURCE"


class Eac3AtmosDynamicRangeCompressionLine(str):
    NONE = "NONE"
    FILM_STANDARD = "FILM_STANDARD"
    FILM_LIGHT = "FILM_LIGHT"
    MUSIC_STANDARD = "MUSIC_STANDARD"
    MUSIC_LIGHT = "MUSIC_LIGHT"
    SPEECH = "SPEECH"


class Eac3AtmosDynamicRangeCompressionRf(str):
    NONE = "NONE"
    FILM_STANDARD = "FILM_STANDARD"
    FILM_LIGHT = "FILM_LIGHT"
    MUSIC_STANDARD = "MUSIC_STANDARD"
    MUSIC_LIGHT = "MUSIC_LIGHT"
    SPEECH = "SPEECH"


class Eac3AtmosDynamicRangeControl(str):
    SPECIFIED = "SPECIFIED"
    INITIALIZE_FROM_SOURCE = "INITIALIZE_FROM_SOURCE"


class Eac3AtmosMeteringMode(str):
    LEQ_A = "LEQ_A"
    ITU_BS_1770_1 = "ITU_BS_1770_1"
    ITU_BS_1770_2 = "ITU_BS_1770_2"
    ITU_BS_1770_3 = "ITU_BS_1770_3"
    ITU_BS_1770_4 = "ITU_BS_1770_4"


class Eac3AtmosStereoDownmix(str):
    NOT_INDICATED = "NOT_INDICATED"
    STEREO = "STEREO"
    SURROUND = "SURROUND"
    DPL2 = "DPL2"


class Eac3AtmosSurroundExMode(str):
    NOT_INDICATED = "NOT_INDICATED"
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class Eac3AttenuationControl(str):
    ATTENUATE_3_DB = "ATTENUATE_3_DB"
    NONE = "NONE"


class Eac3BitstreamMode(str):
    COMPLETE_MAIN = "COMPLETE_MAIN"
    COMMENTARY = "COMMENTARY"
    EMERGENCY = "EMERGENCY"
    HEARING_IMPAIRED = "HEARING_IMPAIRED"
    VISUALLY_IMPAIRED = "VISUALLY_IMPAIRED"


class Eac3CodingMode(str):
    CODING_MODE_1_0 = "CODING_MODE_1_0"
    CODING_MODE_2_0 = "CODING_MODE_2_0"
    CODING_MODE_3_2 = "CODING_MODE_3_2"


class Eac3DcFilter(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class Eac3DynamicRangeCompressionLine(str):
    NONE = "NONE"
    FILM_STANDARD = "FILM_STANDARD"
    FILM_LIGHT = "FILM_LIGHT"
    MUSIC_STANDARD = "MUSIC_STANDARD"
    MUSIC_LIGHT = "MUSIC_LIGHT"
    SPEECH = "SPEECH"


class Eac3DynamicRangeCompressionRf(str):
    NONE = "NONE"
    FILM_STANDARD = "FILM_STANDARD"
    FILM_LIGHT = "FILM_LIGHT"
    MUSIC_STANDARD = "MUSIC_STANDARD"
    MUSIC_LIGHT = "MUSIC_LIGHT"
    SPEECH = "SPEECH"


class Eac3LfeControl(str):
    LFE = "LFE"
    NO_LFE = "NO_LFE"


class Eac3LfeFilter(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class Eac3MetadataControl(str):
    FOLLOW_INPUT = "FOLLOW_INPUT"
    USE_CONFIGURED = "USE_CONFIGURED"


class Eac3PassthroughControl(str):
    WHEN_POSSIBLE = "WHEN_POSSIBLE"
    NO_PASSTHROUGH = "NO_PASSTHROUGH"


class Eac3PhaseControl(str):
    SHIFT_90_DEGREES = "SHIFT_90_DEGREES"
    NO_SHIFT = "NO_SHIFT"


class Eac3StereoDownmix(str):
    NOT_INDICATED = "NOT_INDICATED"
    LO_RO = "LO_RO"
    LT_RT = "LT_RT"
    DPL2 = "DPL2"


class Eac3SurroundExMode(str):
    NOT_INDICATED = "NOT_INDICATED"
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class Eac3SurroundMode(str):
    NOT_INDICATED = "NOT_INDICATED"
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class EmbeddedConvert608To708(str):
    UPCONVERT = "UPCONVERT"
    DISABLED = "DISABLED"


class EmbeddedTerminateCaptions(str):
    END_OF_INPUT = "END_OF_INPUT"
    DISABLED = "DISABLED"


class F4vMoovPlacement(str):
    PROGRESSIVE_DOWNLOAD = "PROGRESSIVE_DOWNLOAD"
    NORMAL = "NORMAL"


class FileSourceConvert608To708(str):
    UPCONVERT = "UPCONVERT"
    DISABLED = "DISABLED"


class FileSourceTimeDeltaUnits(str):
    SECONDS = "SECONDS"
    MILLISECONDS = "MILLISECONDS"


class FontScript(str):
    AUTOMATIC = "AUTOMATIC"
    HANS = "HANS"
    HANT = "HANT"


class H264AdaptiveQuantization(str):
    OFF = "OFF"
    AUTO = "AUTO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    HIGHER = "HIGHER"
    MAX = "MAX"


class H264CodecLevel(str):
    AUTO = "AUTO"
    LEVEL_1 = "LEVEL_1"
    LEVEL_1_1 = "LEVEL_1_1"
    LEVEL_1_2 = "LEVEL_1_2"
    LEVEL_1_3 = "LEVEL_1_3"
    LEVEL_2 = "LEVEL_2"
    LEVEL_2_1 = "LEVEL_2_1"
    LEVEL_2_2 = "LEVEL_2_2"
    LEVEL_3 = "LEVEL_3"
    LEVEL_3_1 = "LEVEL_3_1"
    LEVEL_3_2 = "LEVEL_3_2"
    LEVEL_4 = "LEVEL_4"
    LEVEL_4_1 = "LEVEL_4_1"
    LEVEL_4_2 = "LEVEL_4_2"
    LEVEL_5 = "LEVEL_5"
    LEVEL_5_1 = "LEVEL_5_1"
    LEVEL_5_2 = "LEVEL_5_2"


class H264CodecProfile(str):
    BASELINE = "BASELINE"
    HIGH = "HIGH"
    HIGH_10BIT = "HIGH_10BIT"
    HIGH_422 = "HIGH_422"
    HIGH_422_10BIT = "HIGH_422_10BIT"
    MAIN = "MAIN"


class H264DynamicSubGop(str):
    ADAPTIVE = "ADAPTIVE"
    STATIC = "STATIC"


class H264EntropyEncoding(str):
    CABAC = "CABAC"
    CAVLC = "CAVLC"


class H264FieldEncoding(str):
    PAFF = "PAFF"
    FORCE_FIELD = "FORCE_FIELD"
    MBAFF = "MBAFF"


class H264FlickerAdaptiveQuantization(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class H264FramerateControl(str):
    INITIALIZE_FROM_SOURCE = "INITIALIZE_FROM_SOURCE"
    SPECIFIED = "SPECIFIED"


class H264FramerateConversionAlgorithm(str):
    DUPLICATE_DROP = "DUPLICATE_DROP"
    INTERPOLATE = "INTERPOLATE"
    FRAMEFORMER = "FRAMEFORMER"


class H264GopBReference(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class H264GopSizeUnits(str):
    FRAMES = "FRAMES"
    SECONDS = "SECONDS"
    AUTO = "AUTO"


class H264InterlaceMode(str):
    PROGRESSIVE = "PROGRESSIVE"
    TOP_FIELD = "TOP_FIELD"
    BOTTOM_FIELD = "BOTTOM_FIELD"
    FOLLOW_TOP_FIELD = "FOLLOW_TOP_FIELD"
    FOLLOW_BOTTOM_FIELD = "FOLLOW_BOTTOM_FIELD"


class H264ParControl(str):
    INITIALIZE_FROM_SOURCE = "INITIALIZE_FROM_SOURCE"
    SPECIFIED = "SPECIFIED"


class H264QualityTuningLevel(str):
    SINGLE_PASS = "SINGLE_PASS"
    SINGLE_PASS_HQ = "SINGLE_PASS_HQ"
    MULTI_PASS_HQ = "MULTI_PASS_HQ"


class H264RateControlMode(str):
    VBR = "VBR"
    CBR = "CBR"
    QVBR = "QVBR"


class H264RepeatPps(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class H264ScanTypeConversionMode(str):
    INTERLACED = "INTERLACED"
    INTERLACED_OPTIMIZE = "INTERLACED_OPTIMIZE"


class H264SceneChangeDetect(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"
    TRANSITION_DETECTION = "TRANSITION_DETECTION"


class H264SlowPal(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class H264SpatialAdaptiveQuantization(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class H264Syntax(str):
    DEFAULT = "DEFAULT"
    RP2027 = "RP2027"


class H264Telecine(str):
    NONE = "NONE"
    SOFT = "SOFT"
    HARD = "HARD"


class H264TemporalAdaptiveQuantization(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class H264UnregisteredSeiTimecode(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class H265AdaptiveQuantization(str):
    OFF = "OFF"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    HIGHER = "HIGHER"
    MAX = "MAX"
    AUTO = "AUTO"


class H265AlternateTransferFunctionSei(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class H265CodecLevel(str):
    AUTO = "AUTO"
    LEVEL_1 = "LEVEL_1"
    LEVEL_2 = "LEVEL_2"
    LEVEL_2_1 = "LEVEL_2_1"
    LEVEL_3 = "LEVEL_3"
    LEVEL_3_1 = "LEVEL_3_1"
    LEVEL_4 = "LEVEL_4"
    LEVEL_4_1 = "LEVEL_4_1"
    LEVEL_5 = "LEVEL_5"
    LEVEL_5_1 = "LEVEL_5_1"
    LEVEL_5_2 = "LEVEL_5_2"
    LEVEL_6 = "LEVEL_6"
    LEVEL_6_1 = "LEVEL_6_1"
    LEVEL_6_2 = "LEVEL_6_2"


class H265CodecProfile(str):
    MAIN_MAIN = "MAIN_MAIN"
    MAIN_HIGH = "MAIN_HIGH"
    MAIN10_MAIN = "MAIN10_MAIN"
    MAIN10_HIGH = "MAIN10_HIGH"
    MAIN_422_8BIT_MAIN = "MAIN_422_8BIT_MAIN"
    MAIN_422_8BIT_HIGH = "MAIN_422_8BIT_HIGH"
    MAIN_422_10BIT_MAIN = "MAIN_422_10BIT_MAIN"
    MAIN_422_10BIT_HIGH = "MAIN_422_10BIT_HIGH"


class H265DynamicSubGop(str):
    ADAPTIVE = "ADAPTIVE"
    STATIC = "STATIC"


class H265FlickerAdaptiveQuantization(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class H265FramerateControl(str):
    INITIALIZE_FROM_SOURCE = "INITIALIZE_FROM_SOURCE"
    SPECIFIED = "SPECIFIED"


class H265FramerateConversionAlgorithm(str):
    DUPLICATE_DROP = "DUPLICATE_DROP"
    INTERPOLATE = "INTERPOLATE"
    FRAMEFORMER = "FRAMEFORMER"


class H265GopBReference(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class H265GopSizeUnits(str):
    FRAMES = "FRAMES"
    SECONDS = "SECONDS"
    AUTO = "AUTO"


class H265InterlaceMode(str):
    PROGRESSIVE = "PROGRESSIVE"
    TOP_FIELD = "TOP_FIELD"
    BOTTOM_FIELD = "BOTTOM_FIELD"
    FOLLOW_TOP_FIELD = "FOLLOW_TOP_FIELD"
    FOLLOW_BOTTOM_FIELD = "FOLLOW_BOTTOM_FIELD"


class H265ParControl(str):
    INITIALIZE_FROM_SOURCE = "INITIALIZE_FROM_SOURCE"
    SPECIFIED = "SPECIFIED"


class H265QualityTuningLevel(str):
    SINGLE_PASS = "SINGLE_PASS"
    SINGLE_PASS_HQ = "SINGLE_PASS_HQ"
    MULTI_PASS_HQ = "MULTI_PASS_HQ"


class H265RateControlMode(str):
    VBR = "VBR"
    CBR = "CBR"
    QVBR = "QVBR"


class H265SampleAdaptiveOffsetFilterMode(str):
    DEFAULT = "DEFAULT"
    ADAPTIVE = "ADAPTIVE"
    OFF = "OFF"


class H265ScanTypeConversionMode(str):
    INTERLACED = "INTERLACED"
    INTERLACED_OPTIMIZE = "INTERLACED_OPTIMIZE"


class H265SceneChangeDetect(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"
    TRANSITION_DETECTION = "TRANSITION_DETECTION"


class H265SlowPal(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class H265SpatialAdaptiveQuantization(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class H265Telecine(str):
    NONE = "NONE"
    SOFT = "SOFT"
    HARD = "HARD"


class H265TemporalAdaptiveQuantization(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class H265TemporalIds(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class H265Tiles(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class H265UnregisteredSeiTimecode(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class H265WriteMp4PackagingType(str):
    HVC1 = "HVC1"
    HEV1 = "HEV1"


class HlsAdMarkers(str):
    ELEMENTAL = "ELEMENTAL"
    ELEMENTAL_SCTE35 = "ELEMENTAL_SCTE35"


class HlsAudioOnlyContainer(str):
    AUTOMATIC = "AUTOMATIC"
    M2TS = "M2TS"


class HlsAudioOnlyHeader(str):
    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"


class HlsAudioTrackType(str):
    ALTERNATE_AUDIO_AUTO_SELECT_DEFAULT = "ALTERNATE_AUDIO_AUTO_SELECT_DEFAULT"
    ALTERNATE_AUDIO_AUTO_SELECT = "ALTERNATE_AUDIO_AUTO_SELECT"
    ALTERNATE_AUDIO_NOT_AUTO_SELECT = "ALTERNATE_AUDIO_NOT_AUTO_SELECT"
    AUDIO_ONLY_VARIANT_STREAM = "AUDIO_ONLY_VARIANT_STREAM"


class HlsCaptionLanguageSetting(str):
    INSERT = "INSERT"
    OMIT = "OMIT"
    NONE = "NONE"


class HlsClientCache(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class HlsCodecSpecification(str):
    RFC_6381 = "RFC_6381"
    RFC_4281 = "RFC_4281"


class HlsDescriptiveVideoServiceFlag(str):
    DONT_FLAG = "DONT_FLAG"
    FLAG = "FLAG"


class HlsDirectoryStructure(str):
    SINGLE_DIRECTORY = "SINGLE_DIRECTORY"
    SUBDIRECTORY_PER_STREAM = "SUBDIRECTORY_PER_STREAM"


class HlsEncryptionType(str):
    AES128 = "AES128"
    SAMPLE_AES = "SAMPLE_AES"


class HlsIFrameOnlyManifest(str):
    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"


class HlsImageBasedTrickPlay(str):
    NONE = "NONE"
    THUMBNAIL = "THUMBNAIL"
    THUMBNAIL_AND_FULLFRAME = "THUMBNAIL_AND_FULLFRAME"
    ADVANCED = "ADVANCED"


class HlsInitializationVectorInManifest(str):
    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"


class HlsIntervalCadence(str):
    FOLLOW_IFRAME = "FOLLOW_IFRAME"
    FOLLOW_CUSTOM = "FOLLOW_CUSTOM"


class HlsKeyProviderType(str):
    SPEKE = "SPEKE"
    STATIC_KEY = "STATIC_KEY"


class HlsManifestCompression(str):
    GZIP = "GZIP"
    NONE = "NONE"


class HlsManifestDurationFormat(str):
    FLOATING_POINT = "FLOATING_POINT"
    INTEGER = "INTEGER"


class HlsOfflineEncrypted(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class HlsOutputSelection(str):
    MANIFESTS_AND_SEGMENTS = "MANIFESTS_AND_SEGMENTS"
    SEGMENTS_ONLY = "SEGMENTS_ONLY"


class HlsProgramDateTime(str):
    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"


class HlsSegmentControl(str):
    SINGLE_FILE = "SINGLE_FILE"
    SEGMENTED_FILES = "SEGMENTED_FILES"


class HlsSegmentLengthControl(str):
    EXACT = "EXACT"
    GOP_MULTIPLE = "GOP_MULTIPLE"


class HlsStreamInfResolution(str):
    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"


class HlsTargetDurationCompatibilityMode(str):
    LEGACY = "LEGACY"
    SPEC_COMPLIANT = "SPEC_COMPLIANT"


class HlsTimedMetadataId3Frame(str):
    NONE = "NONE"
    PRIV = "PRIV"
    TDRL = "TDRL"


class ImscAccessibilitySubs(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class ImscStylePassthrough(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class InputDeblockFilter(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class InputDenoiseFilter(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class InputFilterEnable(str):
    AUTO = "AUTO"
    DISABLE = "DISABLE"
    FORCE = "FORCE"


class InputPolicy(str):
    ALLOWED = "ALLOWED"
    DISALLOWED = "DISALLOWED"


class InputPsiControl(str):
    IGNORE_PSI = "IGNORE_PSI"
    USE_PSI = "USE_PSI"


class InputRotate(str):
    DEGREE_0 = "DEGREE_0"
    DEGREES_90 = "DEGREES_90"
    DEGREES_180 = "DEGREES_180"
    DEGREES_270 = "DEGREES_270"
    AUTO = "AUTO"


class InputSampleRange(str):
    FOLLOW = "FOLLOW"
    FULL_RANGE = "FULL_RANGE"
    LIMITED_RANGE = "LIMITED_RANGE"


class InputScanType(str):
    AUTO = "AUTO"
    PSF = "PSF"


class InputTimecodeSource(str):
    EMBEDDED = "EMBEDDED"
    ZEROBASED = "ZEROBASED"
    SPECIFIEDSTART = "SPECIFIEDSTART"


class JobPhase(str):
    PROBING = "PROBING"
    TRANSCODING = "TRANSCODING"
    UPLOADING = "UPLOADING"


class JobStatus(str):
    SUBMITTED = "SUBMITTED"
    PROGRESSING = "PROGRESSING"
    COMPLETE = "COMPLETE"
    CANCELED = "CANCELED"
    ERROR = "ERROR"


class JobTemplateListBy(str):
    NAME = "NAME"
    CREATION_DATE = "CREATION_DATE"
    SYSTEM = "SYSTEM"


class LanguageCode(str):
    ENG = "ENG"
    SPA = "SPA"
    FRA = "FRA"
    DEU = "DEU"
    GER = "GER"
    ZHO = "ZHO"
    ARA = "ARA"
    HIN = "HIN"
    JPN = "JPN"
    RUS = "RUS"
    POR = "POR"
    ITA = "ITA"
    URD = "URD"
    VIE = "VIE"
    KOR = "KOR"
    PAN = "PAN"
    ABK = "ABK"
    AAR = "AAR"
    AFR = "AFR"
    AKA = "AKA"
    SQI = "SQI"
    AMH = "AMH"
    ARG = "ARG"
    HYE = "HYE"
    ASM = "ASM"
    AVA = "AVA"
    AVE = "AVE"
    AYM = "AYM"
    AZE = "AZE"
    BAM = "BAM"
    BAK = "BAK"
    EUS = "EUS"
    BEL = "BEL"
    BEN = "BEN"
    BIH = "BIH"
    BIS = "BIS"
    BOS = "BOS"
    BRE = "BRE"
    BUL = "BUL"
    MYA = "MYA"
    CAT = "CAT"
    KHM = "KHM"
    CHA = "CHA"
    CHE = "CHE"
    NYA = "NYA"
    CHU = "CHU"
    CHV = "CHV"
    COR = "COR"
    COS = "COS"
    CRE = "CRE"
    HRV = "HRV"
    CES = "CES"
    DAN = "DAN"
    DIV = "DIV"
    NLD = "NLD"
    DZO = "DZO"
    ENM = "ENM"
    EPO = "EPO"
    EST = "EST"
    EWE = "EWE"
    FAO = "FAO"
    FIJ = "FIJ"
    FIN = "FIN"
    FRM = "FRM"
    FUL = "FUL"
    GLA = "GLA"
    GLG = "GLG"
    LUG = "LUG"
    KAT = "KAT"
    ELL = "ELL"
    GRN = "GRN"
    GUJ = "GUJ"
    HAT = "HAT"
    HAU = "HAU"
    HEB = "HEB"
    HER = "HER"
    HMO = "HMO"
    HUN = "HUN"
    ISL = "ISL"
    IDO = "IDO"
    IBO = "IBO"
    IND = "IND"
    INA = "INA"
    ILE = "ILE"
    IKU = "IKU"
    IPK = "IPK"
    GLE = "GLE"
    JAV = "JAV"
    KAL = "KAL"
    KAN = "KAN"
    KAU = "KAU"
    KAS = "KAS"
    KAZ = "KAZ"
    KIK = "KIK"
    KIN = "KIN"
    KIR = "KIR"
    KOM = "KOM"
    KON = "KON"
    KUA = "KUA"
    KUR = "KUR"
    LAO = "LAO"
    LAT = "LAT"
    LAV = "LAV"
    LIM = "LIM"
    LIN = "LIN"
    LIT = "LIT"
    LUB = "LUB"
    LTZ = "LTZ"
    MKD = "MKD"
    MLG = "MLG"
    MSA = "MSA"
    MAL = "MAL"
    MLT = "MLT"
    GLV = "GLV"
    MRI = "MRI"
    MAR = "MAR"
    MAH = "MAH"
    MON = "MON"
    NAU = "NAU"
    NAV = "NAV"
    NDE = "NDE"
    NBL = "NBL"
    NDO = "NDO"
    NEP = "NEP"
    SME = "SME"
    NOR = "NOR"
    NOB = "NOB"
    NNO = "NNO"
    OCI = "OCI"
    OJI = "OJI"
    ORI = "ORI"
    ORM = "ORM"
    OSS = "OSS"
    PLI = "PLI"
    FAS = "FAS"
    POL = "POL"
    PUS = "PUS"
    QUE = "QUE"
    QAA = "QAA"
    RON = "RON"
    ROH = "ROH"
    RUN = "RUN"
    SMO = "SMO"
    SAG = "SAG"
    SAN = "SAN"
    SRD = "SRD"
    SRB = "SRB"
    SNA = "SNA"
    III = "III"
    SND = "SND"
    SIN = "SIN"
    SLK = "SLK"
    SLV = "SLV"
    SOM = "SOM"
    SOT = "SOT"
    SUN = "SUN"
    SWA = "SWA"
    SSW = "SSW"
    SWE = "SWE"
    TGL = "TGL"
    TAH = "TAH"
    TGK = "TGK"
    TAM = "TAM"
    TAT = "TAT"
    TEL = "TEL"
    THA = "THA"
    BOD = "BOD"
    TIR = "TIR"
    TON = "TON"
    TSO = "TSO"
    TSN = "TSN"
    TUR = "TUR"
    TUK = "TUK"
    TWI = "TWI"
    UIG = "UIG"
    UKR = "UKR"
    UZB = "UZB"
    VEN = "VEN"
    VOL = "VOL"
    WLN = "WLN"
    CYM = "CYM"
    FRY = "FRY"
    WOL = "WOL"
    XHO = "XHO"
    YID = "YID"
    YOR = "YOR"
    ZHA = "ZHA"
    ZUL = "ZUL"
    ORJ = "ORJ"
    QPC = "QPC"
    TNG = "TNG"
    SRP = "SRP"


class M2tsAudioBufferModel(str):
    DVB = "DVB"
    ATSC = "ATSC"


class M2tsAudioDuration(str):
    DEFAULT_CODEC_DURATION = "DEFAULT_CODEC_DURATION"
    MATCH_VIDEO_DURATION = "MATCH_VIDEO_DURATION"


class M2tsBufferModel(str):
    MULTIPLEX = "MULTIPLEX"
    NONE = "NONE"


class M2tsDataPtsControl(str):
    AUTO = "AUTO"
    ALIGN_TO_VIDEO = "ALIGN_TO_VIDEO"


class M2tsEbpAudioInterval(str):
    VIDEO_AND_FIXED_INTERVALS = "VIDEO_AND_FIXED_INTERVALS"
    VIDEO_INTERVAL = "VIDEO_INTERVAL"


class M2tsEbpPlacement(str):
    VIDEO_AND_AUDIO_PIDS = "VIDEO_AND_AUDIO_PIDS"
    VIDEO_PID = "VIDEO_PID"


class M2tsEsRateInPes(str):
    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"


class M2tsForceTsVideoEbpOrder(str):
    FORCE = "FORCE"
    DEFAULT = "DEFAULT"


class M2tsNielsenId3(str):
    INSERT = "INSERT"
    NONE = "NONE"


class M2tsPcrControl(str):
    PCR_EVERY_PES_PACKET = "PCR_EVERY_PES_PACKET"
    CONFIGURED_PCR_PERIOD = "CONFIGURED_PCR_PERIOD"


class M2tsRateMode(str):
    VBR = "VBR"
    CBR = "CBR"


class M2tsScte35Source(str):
    PASSTHROUGH = "PASSTHROUGH"
    NONE = "NONE"


class M2tsSegmentationMarkers(str):
    NONE = "NONE"
    RAI_SEGSTART = "RAI_SEGSTART"
    RAI_ADAPT = "RAI_ADAPT"
    PSI_SEGSTART = "PSI_SEGSTART"
    EBP = "EBP"
    EBP_LEGACY = "EBP_LEGACY"


class M2tsSegmentationStyle(str):
    MAINTAIN_CADENCE = "MAINTAIN_CADENCE"
    RESET_CADENCE = "RESET_CADENCE"


class M3u8AudioDuration(str):
    DEFAULT_CODEC_DURATION = "DEFAULT_CODEC_DURATION"
    MATCH_VIDEO_DURATION = "MATCH_VIDEO_DURATION"


class M3u8DataPtsControl(str):
    AUTO = "AUTO"
    ALIGN_TO_VIDEO = "ALIGN_TO_VIDEO"


class M3u8NielsenId3(str):
    INSERT = "INSERT"
    NONE = "NONE"


class M3u8PcrControl(str):
    PCR_EVERY_PES_PACKET = "PCR_EVERY_PES_PACKET"
    CONFIGURED_PCR_PERIOD = "CONFIGURED_PCR_PERIOD"


class M3u8Scte35Source(str):
    PASSTHROUGH = "PASSTHROUGH"
    NONE = "NONE"


class MotionImageInsertionMode(str):
    MOV = "MOV"
    PNG = "PNG"


class MotionImagePlayback(str):
    ONCE = "ONCE"
    REPEAT = "REPEAT"


class MovClapAtom(str):
    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"


class MovCslgAtom(str):
    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"


class MovMpeg2FourCCControl(str):
    XDCAM = "XDCAM"
    MPEG = "MPEG"


class MovPaddingControl(str):
    OMNEON = "OMNEON"
    NONE = "NONE"


class MovReference(str):
    SELF_CONTAINED = "SELF_CONTAINED"
    EXTERNAL = "EXTERNAL"


class Mp3RateControlMode(str):
    CBR = "CBR"
    VBR = "VBR"


class Mp4CslgAtom(str):
    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"


class Mp4FreeSpaceBox(str):
    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"


class Mp4MoovPlacement(str):
    PROGRESSIVE_DOWNLOAD = "PROGRESSIVE_DOWNLOAD"
    NORMAL = "NORMAL"


class MpdAccessibilityCaptionHints(str):
    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"


class MpdAudioDuration(str):
    DEFAULT_CODEC_DURATION = "DEFAULT_CODEC_DURATION"
    MATCH_VIDEO_DURATION = "MATCH_VIDEO_DURATION"


class MpdCaptionContainerType(str):
    RAW = "RAW"
    FRAGMENTED_MP4 = "FRAGMENTED_MP4"


class MpdScte35Esam(str):
    INSERT = "INSERT"
    NONE = "NONE"


class MpdScte35Source(str):
    PASSTHROUGH = "PASSTHROUGH"
    NONE = "NONE"


class MpdTimedMetadata(str):
    PASSTHROUGH = "PASSTHROUGH"
    NONE = "NONE"


class Mpeg2AdaptiveQuantization(str):
    OFF = "OFF"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Mpeg2CodecLevel(str):
    AUTO = "AUTO"
    LOW = "LOW"
    MAIN = "MAIN"
    HIGH1440 = "HIGH1440"
    HIGH = "HIGH"


class Mpeg2CodecProfile(str):
    MAIN = "MAIN"
    PROFILE_422 = "PROFILE_422"


class Mpeg2DynamicSubGop(str):
    ADAPTIVE = "ADAPTIVE"
    STATIC = "STATIC"


class Mpeg2FramerateControl(str):
    INITIALIZE_FROM_SOURCE = "INITIALIZE_FROM_SOURCE"
    SPECIFIED = "SPECIFIED"


class Mpeg2FramerateConversionAlgorithm(str):
    DUPLICATE_DROP = "DUPLICATE_DROP"
    INTERPOLATE = "INTERPOLATE"
    FRAMEFORMER = "FRAMEFORMER"


class Mpeg2GopSizeUnits(str):
    FRAMES = "FRAMES"
    SECONDS = "SECONDS"


class Mpeg2InterlaceMode(str):
    PROGRESSIVE = "PROGRESSIVE"
    TOP_FIELD = "TOP_FIELD"
    BOTTOM_FIELD = "BOTTOM_FIELD"
    FOLLOW_TOP_FIELD = "FOLLOW_TOP_FIELD"
    FOLLOW_BOTTOM_FIELD = "FOLLOW_BOTTOM_FIELD"


class Mpeg2IntraDcPrecision(str):
    AUTO = "AUTO"
    INTRA_DC_PRECISION_8 = "INTRA_DC_PRECISION_8"
    INTRA_DC_PRECISION_9 = "INTRA_DC_PRECISION_9"
    INTRA_DC_PRECISION_10 = "INTRA_DC_PRECISION_10"
    INTRA_DC_PRECISION_11 = "INTRA_DC_PRECISION_11"


class Mpeg2ParControl(str):
    INITIALIZE_FROM_SOURCE = "INITIALIZE_FROM_SOURCE"
    SPECIFIED = "SPECIFIED"


class Mpeg2QualityTuningLevel(str):
    SINGLE_PASS = "SINGLE_PASS"
    MULTI_PASS = "MULTI_PASS"


class Mpeg2RateControlMode(str):
    VBR = "VBR"
    CBR = "CBR"


class Mpeg2ScanTypeConversionMode(str):
    INTERLACED = "INTERLACED"
    INTERLACED_OPTIMIZE = "INTERLACED_OPTIMIZE"


class Mpeg2SceneChangeDetect(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class Mpeg2SlowPal(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class Mpeg2SpatialAdaptiveQuantization(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class Mpeg2Syntax(str):
    DEFAULT = "DEFAULT"
    D_10 = "D_10"


class Mpeg2Telecine(str):
    NONE = "NONE"
    SOFT = "SOFT"
    HARD = "HARD"


class Mpeg2TemporalAdaptiveQuantization(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class MsSmoothAudioDeduplication(str):
    COMBINE_DUPLICATE_STREAMS = "COMBINE_DUPLICATE_STREAMS"
    NONE = "NONE"


class MsSmoothFragmentLengthControl(str):
    EXACT = "EXACT"
    GOP_MULTIPLE = "GOP_MULTIPLE"


class MsSmoothManifestEncoding(str):
    UTF8 = "UTF8"
    UTF16 = "UTF16"


class MxfAfdSignaling(str):
    NO_COPY = "NO_COPY"
    COPY_FROM_VIDEO = "COPY_FROM_VIDEO"


class MxfProfile(str):
    D_10 = "D_10"
    XDCAM = "XDCAM"
    OP1A = "OP1A"
    XAVC = "XAVC"


class MxfXavcDurationMode(str):
    ALLOW_ANY_DURATION = "ALLOW_ANY_DURATION"
    DROP_FRAMES_FOR_COMPLIANCE = "DROP_FRAMES_FOR_COMPLIANCE"


class NielsenActiveWatermarkProcessType(str):
    NAES2_AND_NW = "NAES2_AND_NW"
    CBET = "CBET"
    NAES2_AND_NW_AND_CBET = "NAES2_AND_NW_AND_CBET"


class NielsenSourceWatermarkStatusType(str):
    CLEAN = "CLEAN"
    WATERMARKED = "WATERMARKED"


class NielsenUniqueTicPerAudioTrackType(str):
    RESERVE_UNIQUE_TICS_PER_TRACK = "RESERVE_UNIQUE_TICS_PER_TRACK"
    SAME_TICS_PER_TRACK = "SAME_TICS_PER_TRACK"


class NoiseFilterPostTemporalSharpening(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"
    AUTO = "AUTO"


class NoiseFilterPostTemporalSharpeningStrength(str):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class NoiseReducerFilter(str):
    BILATERAL = "BILATERAL"
    MEAN = "MEAN"
    GAUSSIAN = "GAUSSIAN"
    LANCZOS = "LANCZOS"
    SHARPEN = "SHARPEN"
    CONSERVE = "CONSERVE"
    SPATIAL = "SPATIAL"
    TEMPORAL = "TEMPORAL"


class Order(str):
    ASCENDING = "ASCENDING"
    DESCENDING = "DESCENDING"


class OutputGroupType(str):
    HLS_GROUP_SETTINGS = "HLS_GROUP_SETTINGS"
    DASH_ISO_GROUP_SETTINGS = "DASH_ISO_GROUP_SETTINGS"
    FILE_GROUP_SETTINGS = "FILE_GROUP_SETTINGS"
    MS_SMOOTH_GROUP_SETTINGS = "MS_SMOOTH_GROUP_SETTINGS"
    CMAF_GROUP_SETTINGS = "CMAF_GROUP_SETTINGS"


class OutputSdt(str):
    SDT_FOLLOW = "SDT_FOLLOW"
    SDT_FOLLOW_IF_PRESENT = "SDT_FOLLOW_IF_PRESENT"
    SDT_MANUAL = "SDT_MANUAL"
    SDT_NONE = "SDT_NONE"


class PresetListBy(str):
    NAME = "NAME"
    CREATION_DATE = "CREATION_DATE"
    SYSTEM = "SYSTEM"


class PricingPlan(str):
    ON_DEMAND = "ON_DEMAND"
    RESERVED = "RESERVED"


class ProresChromaSampling(str):
    PRESERVE_444_SAMPLING = "PRESERVE_444_SAMPLING"
    SUBSAMPLE_TO_422 = "SUBSAMPLE_TO_422"


class ProresCodecProfile(str):
    APPLE_PRORES_422 = "APPLE_PRORES_422"
    APPLE_PRORES_422_HQ = "APPLE_PRORES_422_HQ"
    APPLE_PRORES_422_LT = "APPLE_PRORES_422_LT"
    APPLE_PRORES_422_PROXY = "APPLE_PRORES_422_PROXY"
    APPLE_PRORES_4444 = "APPLE_PRORES_4444"
    APPLE_PRORES_4444_XQ = "APPLE_PRORES_4444_XQ"


class ProresFramerateControl(str):
    INITIALIZE_FROM_SOURCE = "INITIALIZE_FROM_SOURCE"
    SPECIFIED = "SPECIFIED"


class ProresFramerateConversionAlgorithm(str):
    DUPLICATE_DROP = "DUPLICATE_DROP"
    INTERPOLATE = "INTERPOLATE"
    FRAMEFORMER = "FRAMEFORMER"


class ProresInterlaceMode(str):
    PROGRESSIVE = "PROGRESSIVE"
    TOP_FIELD = "TOP_FIELD"
    BOTTOM_FIELD = "BOTTOM_FIELD"
    FOLLOW_TOP_FIELD = "FOLLOW_TOP_FIELD"
    FOLLOW_BOTTOM_FIELD = "FOLLOW_BOTTOM_FIELD"


class ProresParControl(str):
    INITIALIZE_FROM_SOURCE = "INITIALIZE_FROM_SOURCE"
    SPECIFIED = "SPECIFIED"


class ProresScanTypeConversionMode(str):
    INTERLACED = "INTERLACED"
    INTERLACED_OPTIMIZE = "INTERLACED_OPTIMIZE"


class ProresSlowPal(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class ProresTelecine(str):
    NONE = "NONE"
    HARD = "HARD"


class QueueListBy(str):
    NAME = "NAME"
    CREATION_DATE = "CREATION_DATE"


class QueueStatus(str):
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"


class RenewalType(str):
    AUTO_RENEW = "AUTO_RENEW"
    EXPIRE = "EXPIRE"


class ReservationPlanStatus(str):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"


class RespondToAfd(str):
    NONE = "NONE"
    RESPOND = "RESPOND"
    PASSTHROUGH = "PASSTHROUGH"


class S3ObjectCannedAcl(str):
    PUBLIC_READ = "PUBLIC_READ"
    AUTHENTICATED_READ = "AUTHENTICATED_READ"
    BUCKET_OWNER_READ = "BUCKET_OWNER_READ"
    BUCKET_OWNER_FULL_CONTROL = "BUCKET_OWNER_FULL_CONTROL"


class S3ServerSideEncryptionType(str):
    SERVER_SIDE_ENCRYPTION_S3 = "SERVER_SIDE_ENCRYPTION_S3"
    SERVER_SIDE_ENCRYPTION_KMS = "SERVER_SIDE_ENCRYPTION_KMS"


class SampleRangeConversion(str):
    LIMITED_RANGE_SQUEEZE = "LIMITED_RANGE_SQUEEZE"
    NONE = "NONE"


class ScalingBehavior(str):
    DEFAULT = "DEFAULT"
    STRETCH_TO_OUTPUT = "STRETCH_TO_OUTPUT"


class SccDestinationFramerate(str):
    FRAMERATE_23_97 = "FRAMERATE_23_97"
    FRAMERATE_24 = "FRAMERATE_24"
    FRAMERATE_25 = "FRAMERATE_25"
    FRAMERATE_29_97_DROPFRAME = "FRAMERATE_29_97_DROPFRAME"
    FRAMERATE_29_97_NON_DROPFRAME = "FRAMERATE_29_97_NON_DROPFRAME"


class SimulateReservedQueue(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class SrtStylePassthrough(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class StatusUpdateInterval(str):
    SECONDS_10 = "SECONDS_10"
    SECONDS_12 = "SECONDS_12"
    SECONDS_15 = "SECONDS_15"
    SECONDS_20 = "SECONDS_20"
    SECONDS_30 = "SECONDS_30"
    SECONDS_60 = "SECONDS_60"
    SECONDS_120 = "SECONDS_120"
    SECONDS_180 = "SECONDS_180"
    SECONDS_240 = "SECONDS_240"
    SECONDS_300 = "SECONDS_300"
    SECONDS_360 = "SECONDS_360"
    SECONDS_420 = "SECONDS_420"
    SECONDS_480 = "SECONDS_480"
    SECONDS_540 = "SECONDS_540"
    SECONDS_600 = "SECONDS_600"


class TeletextPageType(str):
    PAGE_TYPE_INITIAL = "PAGE_TYPE_INITIAL"
    PAGE_TYPE_SUBTITLE = "PAGE_TYPE_SUBTITLE"
    PAGE_TYPE_ADDL_INFO = "PAGE_TYPE_ADDL_INFO"
    PAGE_TYPE_PROGRAM_SCHEDULE = "PAGE_TYPE_PROGRAM_SCHEDULE"
    PAGE_TYPE_HEARING_IMPAIRED_SUBTITLE = "PAGE_TYPE_HEARING_IMPAIRED_SUBTITLE"


class TimecodeBurninPosition(str):
    TOP_CENTER = "TOP_CENTER"
    TOP_LEFT = "TOP_LEFT"
    TOP_RIGHT = "TOP_RIGHT"
    MIDDLE_LEFT = "MIDDLE_LEFT"
    MIDDLE_CENTER = "MIDDLE_CENTER"
    MIDDLE_RIGHT = "MIDDLE_RIGHT"
    BOTTOM_LEFT = "BOTTOM_LEFT"
    BOTTOM_CENTER = "BOTTOM_CENTER"
    BOTTOM_RIGHT = "BOTTOM_RIGHT"


class TimecodeSource(str):
    EMBEDDED = "EMBEDDED"
    ZEROBASED = "ZEROBASED"
    SPECIFIEDSTART = "SPECIFIEDSTART"


class TimedMetadata(str):
    PASSTHROUGH = "PASSTHROUGH"
    NONE = "NONE"


class TtmlStylePassthrough(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class Type(str):
    SYSTEM = "SYSTEM"
    CUSTOM = "CUSTOM"


class Vc3Class(str):
    CLASS_145_8BIT = "CLASS_145_8BIT"
    CLASS_220_8BIT = "CLASS_220_8BIT"
    CLASS_220_10BIT = "CLASS_220_10BIT"


class Vc3FramerateControl(str):
    INITIALIZE_FROM_SOURCE = "INITIALIZE_FROM_SOURCE"
    SPECIFIED = "SPECIFIED"


class Vc3FramerateConversionAlgorithm(str):
    DUPLICATE_DROP = "DUPLICATE_DROP"
    INTERPOLATE = "INTERPOLATE"
    FRAMEFORMER = "FRAMEFORMER"


class Vc3InterlaceMode(str):
    INTERLACED = "INTERLACED"
    PROGRESSIVE = "PROGRESSIVE"


class Vc3ScanTypeConversionMode(str):
    INTERLACED = "INTERLACED"
    INTERLACED_OPTIMIZE = "INTERLACED_OPTIMIZE"


class Vc3SlowPal(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class Vc3Telecine(str):
    NONE = "NONE"
    HARD = "HARD"


class VchipAction(str):
    PASSTHROUGH = "PASSTHROUGH"
    STRIP = "STRIP"


class VideoCodec(str):
    AV1 = "AV1"
    AVC_INTRA = "AVC_INTRA"
    FRAME_CAPTURE = "FRAME_CAPTURE"
    H_264 = "H_264"
    H_265 = "H_265"
    MPEG2 = "MPEG2"
    PRORES = "PRORES"
    VC3 = "VC3"
    VP8 = "VP8"
    VP9 = "VP9"
    XAVC = "XAVC"


class VideoTimecodeInsertion(str):
    DISABLED = "DISABLED"
    PIC_TIMING_SEI = "PIC_TIMING_SEI"


class Vp8FramerateControl(str):
    INITIALIZE_FROM_SOURCE = "INITIALIZE_FROM_SOURCE"
    SPECIFIED = "SPECIFIED"


class Vp8FramerateConversionAlgorithm(str):
    DUPLICATE_DROP = "DUPLICATE_DROP"
    INTERPOLATE = "INTERPOLATE"
    FRAMEFORMER = "FRAMEFORMER"


class Vp8ParControl(str):
    INITIALIZE_FROM_SOURCE = "INITIALIZE_FROM_SOURCE"
    SPECIFIED = "SPECIFIED"


class Vp8QualityTuningLevel(str):
    MULTI_PASS = "MULTI_PASS"
    MULTI_PASS_HQ = "MULTI_PASS_HQ"


class Vp8RateControlMode(str):
    VBR = "VBR"


class Vp9FramerateControl(str):
    INITIALIZE_FROM_SOURCE = "INITIALIZE_FROM_SOURCE"
    SPECIFIED = "SPECIFIED"


class Vp9FramerateConversionAlgorithm(str):
    DUPLICATE_DROP = "DUPLICATE_DROP"
    INTERPOLATE = "INTERPOLATE"
    FRAMEFORMER = "FRAMEFORMER"


class Vp9ParControl(str):
    INITIALIZE_FROM_SOURCE = "INITIALIZE_FROM_SOURCE"
    SPECIFIED = "SPECIFIED"


class Vp9QualityTuningLevel(str):
    MULTI_PASS = "MULTI_PASS"
    MULTI_PASS_HQ = "MULTI_PASS_HQ"


class Vp9RateControlMode(str):
    VBR = "VBR"


class WatermarkingStrength(str):
    LIGHTEST = "LIGHTEST"
    LIGHTER = "LIGHTER"
    DEFAULT = "DEFAULT"
    STRONGER = "STRONGER"
    STRONGEST = "STRONGEST"


class WavFormat(str):
    RIFF = "RIFF"
    RF64 = "RF64"


class WebvttAccessibilitySubs(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class WebvttStylePassthrough(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class Xavc4kIntraCbgProfileClass(str):
    CLASS_100 = "CLASS_100"
    CLASS_300 = "CLASS_300"
    CLASS_480 = "CLASS_480"


class Xavc4kIntraVbrProfileClass(str):
    CLASS_100 = "CLASS_100"
    CLASS_300 = "CLASS_300"
    CLASS_480 = "CLASS_480"


class Xavc4kProfileBitrateClass(str):
    BITRATE_CLASS_100 = "BITRATE_CLASS_100"
    BITRATE_CLASS_140 = "BITRATE_CLASS_140"
    BITRATE_CLASS_200 = "BITRATE_CLASS_200"


class Xavc4kProfileCodecProfile(str):
    HIGH = "HIGH"
    HIGH_422 = "HIGH_422"


class Xavc4kProfileQualityTuningLevel(str):
    SINGLE_PASS = "SINGLE_PASS"
    SINGLE_PASS_HQ = "SINGLE_PASS_HQ"
    MULTI_PASS_HQ = "MULTI_PASS_HQ"


class XavcAdaptiveQuantization(str):
    OFF = "OFF"
    AUTO = "AUTO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    HIGHER = "HIGHER"
    MAX = "MAX"


class XavcEntropyEncoding(str):
    AUTO = "AUTO"
    CABAC = "CABAC"
    CAVLC = "CAVLC"


class XavcFlickerAdaptiveQuantization(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class XavcFramerateControl(str):
    INITIALIZE_FROM_SOURCE = "INITIALIZE_FROM_SOURCE"
    SPECIFIED = "SPECIFIED"


class XavcFramerateConversionAlgorithm(str):
    DUPLICATE_DROP = "DUPLICATE_DROP"
    INTERPOLATE = "INTERPOLATE"
    FRAMEFORMER = "FRAMEFORMER"


class XavcGopBReference(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class XavcHdIntraCbgProfileClass(str):
    CLASS_50 = "CLASS_50"
    CLASS_100 = "CLASS_100"
    CLASS_200 = "CLASS_200"


class XavcHdProfileBitrateClass(str):
    BITRATE_CLASS_25 = "BITRATE_CLASS_25"
    BITRATE_CLASS_35 = "BITRATE_CLASS_35"
    BITRATE_CLASS_50 = "BITRATE_CLASS_50"


class XavcHdProfileQualityTuningLevel(str):
    SINGLE_PASS = "SINGLE_PASS"
    SINGLE_PASS_HQ = "SINGLE_PASS_HQ"
    MULTI_PASS_HQ = "MULTI_PASS_HQ"


class XavcHdProfileTelecine(str):
    NONE = "NONE"
    HARD = "HARD"


class XavcInterlaceMode(str):
    PROGRESSIVE = "PROGRESSIVE"
    TOP_FIELD = "TOP_FIELD"
    BOTTOM_FIELD = "BOTTOM_FIELD"
    FOLLOW_TOP_FIELD = "FOLLOW_TOP_FIELD"
    FOLLOW_BOTTOM_FIELD = "FOLLOW_BOTTOM_FIELD"


class XavcProfile(str):
    XAVC_HD_INTRA_CBG = "XAVC_HD_INTRA_CBG"
    XAVC_4K_INTRA_CBG = "XAVC_4K_INTRA_CBG"
    XAVC_4K_INTRA_VBR = "XAVC_4K_INTRA_VBR"
    XAVC_HD = "XAVC_HD"
    XAVC_4K = "XAVC_4K"


class XavcSlowPal(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class XavcSpatialAdaptiveQuantization(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class XavcTemporalAdaptiveQuantization(str):
    DISABLED = "DISABLED"
    ENABLED = "ENABLED"


class BadRequestException(ServiceException):
    Message: Optional[_string]


class ConflictException(ServiceException):
    Message: Optional[_string]


class ForbiddenException(ServiceException):
    Message: Optional[_string]


class InternalServerErrorException(ServiceException):
    Message: Optional[_string]


class NotFoundException(ServiceException):
    Message: Optional[_string]


class TooManyRequestsException(ServiceException):
    Message: Optional[_string]


class AacSettings(TypedDict, total=False):
    AudioDescriptionBroadcasterMix: Optional[AacAudioDescriptionBroadcasterMix]
    Bitrate: Optional[_integerMin6000Max1024000]
    CodecProfile: Optional[AacCodecProfile]
    CodingMode: Optional[AacCodingMode]
    RateControlMode: Optional[AacRateControlMode]
    RawFormat: Optional[AacRawFormat]
    SampleRate: Optional[_integerMin8000Max96000]
    Specification: Optional[AacSpecification]
    VbrQuality: Optional[AacVbrQuality]


class Ac3Settings(TypedDict, total=False):
    Bitrate: Optional[_integerMin64000Max640000]
    BitstreamMode: Optional[Ac3BitstreamMode]
    CodingMode: Optional[Ac3CodingMode]
    Dialnorm: Optional[_integerMin1Max31]
    DynamicRangeCompressionLine: Optional[Ac3DynamicRangeCompressionLine]
    DynamicRangeCompressionProfile: Optional[Ac3DynamicRangeCompressionProfile]
    DynamicRangeCompressionRf: Optional[Ac3DynamicRangeCompressionRf]
    LfeFilter: Optional[Ac3LfeFilter]
    MetadataControl: Optional[Ac3MetadataControl]
    SampleRate: Optional[_integerMin48000Max48000]


class AccelerationSettings(TypedDict, total=False):
    Mode: AccelerationMode


class AiffSettings(TypedDict, total=False):
    BitDepth: Optional[_integerMin16Max24]
    Channels: Optional[_integerMin1Max64]
    SampleRate: Optional[_integerMin8000Max192000]


class AncillarySourceSettings(TypedDict, total=False):
    Convert608To708: Optional[AncillaryConvert608To708]
    SourceAncillaryChannelNumber: Optional[_integerMin1Max4]
    TerminateCaptions: Optional[AncillaryTerminateCaptions]


class AssociateCertificateRequest(ServiceRequest):
    Arn: _string


class AssociateCertificateResponse(TypedDict, total=False):
    pass


class AudioChannelTaggingSettings(TypedDict, total=False):
    ChannelTag: Optional[AudioChannelTag]


class WavSettings(TypedDict, total=False):
    BitDepth: Optional[_integerMin16Max24]
    Channels: Optional[_integerMin1Max64]
    Format: Optional[WavFormat]
    SampleRate: Optional[_integerMin8000Max192000]


class VorbisSettings(TypedDict, total=False):
    Channels: Optional[_integerMin1Max2]
    SampleRate: Optional[_integerMin22050Max48000]
    VbrQuality: Optional[_integerMinNegative1Max10]


class OpusSettings(TypedDict, total=False):
    Bitrate: Optional[_integerMin32000Max192000]
    Channels: Optional[_integerMin1Max2]
    SampleRate: Optional[_integerMin16000Max48000]


class Mp3Settings(TypedDict, total=False):
    Bitrate: Optional[_integerMin16000Max320000]
    Channels: Optional[_integerMin1Max2]
    RateControlMode: Optional[Mp3RateControlMode]
    SampleRate: Optional[_integerMin22050Max48000]
    VbrQuality: Optional[_integerMin0Max9]


class Mp2Settings(TypedDict, total=False):
    Bitrate: Optional[_integerMin32000Max384000]
    Channels: Optional[_integerMin1Max2]
    SampleRate: Optional[_integerMin32000Max48000]


class Eac3Settings(TypedDict, total=False):
    AttenuationControl: Optional[Eac3AttenuationControl]
    Bitrate: Optional[_integerMin64000Max640000]
    BitstreamMode: Optional[Eac3BitstreamMode]
    CodingMode: Optional[Eac3CodingMode]
    DcFilter: Optional[Eac3DcFilter]
    Dialnorm: Optional[_integerMin1Max31]
    DynamicRangeCompressionLine: Optional[Eac3DynamicRangeCompressionLine]
    DynamicRangeCompressionRf: Optional[Eac3DynamicRangeCompressionRf]
    LfeControl: Optional[Eac3LfeControl]
    LfeFilter: Optional[Eac3LfeFilter]
    LoRoCenterMixLevel: Optional[_doubleMinNegative60Max3]
    LoRoSurroundMixLevel: Optional[_doubleMinNegative60MaxNegative1]
    LtRtCenterMixLevel: Optional[_doubleMinNegative60Max3]
    LtRtSurroundMixLevel: Optional[_doubleMinNegative60MaxNegative1]
    MetadataControl: Optional[Eac3MetadataControl]
    PassthroughControl: Optional[Eac3PassthroughControl]
    PhaseControl: Optional[Eac3PhaseControl]
    SampleRate: Optional[_integerMin48000Max48000]
    StereoDownmix: Optional[Eac3StereoDownmix]
    SurroundExMode: Optional[Eac3SurroundExMode]
    SurroundMode: Optional[Eac3SurroundMode]


class Eac3AtmosSettings(TypedDict, total=False):
    Bitrate: Optional[_integerMin384000Max1024000]
    BitstreamMode: Optional[Eac3AtmosBitstreamMode]
    CodingMode: Optional[Eac3AtmosCodingMode]
    DialogueIntelligence: Optional[Eac3AtmosDialogueIntelligence]
    DownmixControl: Optional[Eac3AtmosDownmixControl]
    DynamicRangeCompressionLine: Optional[Eac3AtmosDynamicRangeCompressionLine]
    DynamicRangeCompressionRf: Optional[Eac3AtmosDynamicRangeCompressionRf]
    DynamicRangeControl: Optional[Eac3AtmosDynamicRangeControl]
    LoRoCenterMixLevel: Optional[_doubleMinNegative6Max3]
    LoRoSurroundMixLevel: Optional[_doubleMinNegative60MaxNegative1]
    LtRtCenterMixLevel: Optional[_doubleMinNegative6Max3]
    LtRtSurroundMixLevel: Optional[_doubleMinNegative60MaxNegative1]
    MeteringMode: Optional[Eac3AtmosMeteringMode]
    SampleRate: Optional[_integerMin48000Max48000]
    SpeechThreshold: Optional[_integerMin0Max100]
    StereoDownmix: Optional[Eac3AtmosStereoDownmix]
    SurroundExMode: Optional[Eac3AtmosSurroundExMode]


class AudioCodecSettings(TypedDict, total=False):
    AacSettings: Optional[AacSettings]
    Ac3Settings: Optional[Ac3Settings]
    AiffSettings: Optional[AiffSettings]
    Codec: Optional[AudioCodec]
    Eac3AtmosSettings: Optional[Eac3AtmosSettings]
    Eac3Settings: Optional[Eac3Settings]
    Mp2Settings: Optional[Mp2Settings]
    Mp3Settings: Optional[Mp3Settings]
    OpusSettings: Optional[OpusSettings]
    VorbisSettings: Optional[VorbisSettings]
    WavSettings: Optional[WavSettings]


_listOf__doubleMinNegative60Max6 = List[_doubleMinNegative60Max6]
_listOf__integerMinNegative60Max6 = List[_integerMinNegative60Max6]


class OutputChannelMapping(TypedDict, total=False):
    InputChannels: Optional[_listOf__integerMinNegative60Max6]
    InputChannelsFineTune: Optional[_listOf__doubleMinNegative60Max6]


_listOfOutputChannelMapping = List[OutputChannelMapping]


class ChannelMapping(TypedDict, total=False):
    OutputChannels: Optional[_listOfOutputChannelMapping]


class RemixSettings(TypedDict, total=False):
    ChannelMapping: Optional[ChannelMapping]
    ChannelsIn: Optional[_integerMin1Max64]
    ChannelsOut: Optional[_integerMin1Max64]


class AudioNormalizationSettings(TypedDict, total=False):
    Algorithm: Optional[AudioNormalizationAlgorithm]
    AlgorithmControl: Optional[AudioNormalizationAlgorithmControl]
    CorrectionGateLevel: Optional[_integerMinNegative70Max0]
    LoudnessLogging: Optional[AudioNormalizationLoudnessLogging]
    PeakCalculation: Optional[AudioNormalizationPeakCalculation]
    TargetLkfs: Optional[_doubleMinNegative59Max0]


class AudioDescription(TypedDict, total=False):
    AudioChannelTaggingSettings: Optional[AudioChannelTaggingSettings]
    AudioNormalizationSettings: Optional[AudioNormalizationSettings]
    AudioSourceName: Optional[_string]
    AudioType: Optional[_integerMin0Max255]
    AudioTypeControl: Optional[AudioTypeControl]
    CodecSettings: Optional[AudioCodecSettings]
    CustomLanguageCode: Optional[_stringPatternAZaZ23AZaZ]
    LanguageCode: Optional[LanguageCode]
    LanguageCodeControl: Optional[AudioLanguageCodeControl]
    RemixSettings: Optional[RemixSettings]
    StreamName: Optional[_stringPatternWS]


_listOf__integerMin1Max2147483647 = List[_integerMin1Max2147483647]


class HlsRenditionGroupSettings(TypedDict, total=False):
    RenditionGroupId: Optional[_string]
    RenditionLanguageCode: Optional[LanguageCode]
    RenditionName: Optional[_string]


class AudioSelector(TypedDict, total=False):
    CustomLanguageCode: Optional[_stringMin3Max3PatternAZaZ3]
    DefaultSelection: Optional[AudioDefaultSelection]
    ExternalAudioFileInput: Optional[
        _stringPatternS3MM2PPWWEEBBMMMM2VVMMPPEEGGMMPP3AAVVIIMMPP4FFLLVVMMPPTTMMPPGGMM4VVTTRRPPFF4VVMM2TTSSTTSS264HH264MMKKVVMMKKAAMMOOVVMMTTSSMM2TTWWMMVVaAAASSFFVVOOBB3GGPP3GGPPPPMMXXFFDDIIVVXXXXVVIIDDRRAAWWDDVVGGXXFFMM1VV3GG2VVMMFFMM3UU8LLCCHHGGXXFFMMPPEEGG2MMXXFFMMPPEEGG2MMXXFFHHDDWWAAVVYY4MMAAAACCAAIIFFFFMMPP2AACC3EECC3DDTTSSEEAATTMMOOSSOOGGGGaAHttpsMM2VVMMPPEEGGMMPP3AAVVIIMMPP4FFLLVVMMPPTTMMPPGGMM4VVTTRRPPFF4VVMM2TTSSTTSS264HH264MMKKVVMMKKAAMMOOVVMMTTSSMM2TTWWMMVVaAAASSFFVVOOBB3GGPP3GGPPPPMMXXFFDDIIVVXXXXVVIIDDRRAAWWDDVVGGXXFFMM1VV3GG2VVMMFFMM3UU8LLCCHHGGXXFFMMPPEEGG2MMXXFFMMPPEEGG2MMXXFFHHDDWWAAVVYY4MMAAAACCAAIIFFFFMMPP2AACC3EECC3DDTTSSEEAATTMMOOSSOOGGGGaA
    ]
    HlsRenditionGroupSettings: Optional[HlsRenditionGroupSettings]
    LanguageCode: Optional[LanguageCode]
    Offset: Optional[_integerMinNegative2147483648Max2147483647]
    Pids: Optional[_listOf__integerMin1Max2147483647]
    ProgramSelection: Optional[_integerMin0Max8]
    RemixSettings: Optional[RemixSettings]
    SelectorType: Optional[AudioSelectorType]
    Tracks: Optional[_listOf__integerMin1Max2147483647]


_listOf__stringMin1 = List[_stringMin1]


class AudioSelectorGroup(TypedDict, total=False):
    AudioSelectorNames: Optional[_listOf__stringMin1]


class AutomatedAbrSettings(TypedDict, total=False):
    MaxAbrBitrate: Optional[_integerMin100000Max100000000]
    MaxRenditions: Optional[_integerMin3Max15]
    MinAbrBitrate: Optional[_integerMin100000Max100000000]


class AutomatedEncodingSettings(TypedDict, total=False):
    AbrSettings: Optional[AutomatedAbrSettings]


class Av1QvbrSettings(TypedDict, total=False):
    QvbrQualityLevel: Optional[_integerMin1Max10]
    QvbrQualityLevelFineTune: Optional[_doubleMin0Max1]


class Av1Settings(TypedDict, total=False):
    AdaptiveQuantization: Optional[Av1AdaptiveQuantization]
    BitDepth: Optional[Av1BitDepth]
    FramerateControl: Optional[Av1FramerateControl]
    FramerateConversionAlgorithm: Optional[Av1FramerateConversionAlgorithm]
    FramerateDenominator: Optional[_integerMin1Max2147483647]
    FramerateNumerator: Optional[_integerMin1Max2147483647]
    GopSize: Optional[_doubleMin0]
    MaxBitrate: Optional[_integerMin1000Max1152000000]
    NumberBFramesBetweenReferenceFrames: Optional[_integerMin0Max15]
    QvbrSettings: Optional[Av1QvbrSettings]
    RateControlMode: Optional[Av1RateControlMode]
    Slices: Optional[_integerMin1Max32]
    SpatialAdaptiveQuantization: Optional[Av1SpatialAdaptiveQuantization]


class AvailBlanking(TypedDict, total=False):
    AvailBlankingImage: Optional[_stringMin14PatternS3BmpBMPPngPNGHttpsBmpBMPPngPNG]


class AvcIntraUhdSettings(TypedDict, total=False):
    QualityTuningLevel: Optional[AvcIntraUhdQualityTuningLevel]


class AvcIntraSettings(TypedDict, total=False):
    AvcIntraClass: Optional[AvcIntraClass]
    AvcIntraUhdSettings: Optional[AvcIntraUhdSettings]
    FramerateControl: Optional[AvcIntraFramerateControl]
    FramerateConversionAlgorithm: Optional[AvcIntraFramerateConversionAlgorithm]
    FramerateDenominator: Optional[_integerMin1Max1001]
    FramerateNumerator: Optional[_integerMin24Max60000]
    InterlaceMode: Optional[AvcIntraInterlaceMode]
    ScanTypeConversionMode: Optional[AvcIntraScanTypeConversionMode]
    SlowPal: Optional[AvcIntraSlowPal]
    Telecine: Optional[AvcIntraTelecine]


class BurninDestinationSettings(TypedDict, total=False):
    Alignment: Optional[BurninSubtitleAlignment]
    ApplyFontColor: Optional[BurninSubtitleApplyFontColor]
    BackgroundColor: Optional[BurninSubtitleBackgroundColor]
    BackgroundOpacity: Optional[_integerMin0Max255]
    FallbackFont: Optional[BurninSubtitleFallbackFont]
    FontColor: Optional[BurninSubtitleFontColor]
    FontOpacity: Optional[_integerMin0Max255]
    FontResolution: Optional[_integerMin96Max600]
    FontScript: Optional[FontScript]
    FontSize: Optional[_integerMin0Max96]
    HexFontColor: Optional[_stringMin6Max8Pattern09aFAF609aFAF2]
    OutlineColor: Optional[BurninSubtitleOutlineColor]
    OutlineSize: Optional[_integerMin0Max10]
    ShadowColor: Optional[BurninSubtitleShadowColor]
    ShadowOpacity: Optional[_integerMin0Max255]
    ShadowXOffset: Optional[_integerMinNegative2147483648Max2147483647]
    ShadowYOffset: Optional[_integerMinNegative2147483648Max2147483647]
    StylePassthrough: Optional[BurnInSubtitleStylePassthrough]
    TeletextSpacing: Optional[BurninSubtitleTeletextSpacing]
    XPosition: Optional[_integerMin0Max2147483647]
    YPosition: Optional[_integerMin0Max2147483647]


class CancelJobRequest(ServiceRequest):
    Id: _string


class CancelJobResponse(TypedDict, total=False):
    pass


class WebvttDestinationSettings(TypedDict, total=False):
    Accessibility: Optional[WebvttAccessibilitySubs]
    StylePassthrough: Optional[WebvttStylePassthrough]


class TtmlDestinationSettings(TypedDict, total=False):
    StylePassthrough: Optional[TtmlStylePassthrough]


_listOfTeletextPageType = List[TeletextPageType]


class TeletextDestinationSettings(TypedDict, total=False):
    PageNumber: Optional[_stringMin3Max3Pattern1809aFAF09aEAE]
    PageTypes: Optional[_listOfTeletextPageType]


class SrtDestinationSettings(TypedDict, total=False):
    StylePassthrough: Optional[SrtStylePassthrough]


class SccDestinationSettings(TypedDict, total=False):
    Framerate: Optional[SccDestinationFramerate]


class ImscDestinationSettings(TypedDict, total=False):
    Accessibility: Optional[ImscAccessibilitySubs]
    StylePassthrough: Optional[ImscStylePassthrough]


class EmbeddedDestinationSettings(TypedDict, total=False):
    Destination608ChannelNumber: Optional[_integerMin1Max4]
    Destination708ServiceNumber: Optional[_integerMin1Max6]


class DvbSubDestinationSettings(TypedDict, total=False):
    Alignment: Optional[DvbSubtitleAlignment]
    ApplyFontColor: Optional[DvbSubtitleApplyFontColor]
    BackgroundColor: Optional[DvbSubtitleBackgroundColor]
    BackgroundOpacity: Optional[_integerMin0Max255]
    DdsHandling: Optional[DvbddsHandling]
    DdsXCoordinate: Optional[_integerMin0Max2147483647]
    DdsYCoordinate: Optional[_integerMin0Max2147483647]
    FallbackFont: Optional[DvbSubSubtitleFallbackFont]
    FontColor: Optional[DvbSubtitleFontColor]
    FontOpacity: Optional[_integerMin0Max255]
    FontResolution: Optional[_integerMin96Max600]
    FontScript: Optional[FontScript]
    FontSize: Optional[_integerMin0Max96]
    Height: Optional[_integerMin1Max2147483647]
    HexFontColor: Optional[_stringMin6Max8Pattern09aFAF609aFAF2]
    OutlineColor: Optional[DvbSubtitleOutlineColor]
    OutlineSize: Optional[_integerMin0Max10]
    ShadowColor: Optional[DvbSubtitleShadowColor]
    ShadowOpacity: Optional[_integerMin0Max255]
    ShadowXOffset: Optional[_integerMinNegative2147483648Max2147483647]
    ShadowYOffset: Optional[_integerMinNegative2147483648Max2147483647]
    StylePassthrough: Optional[DvbSubtitleStylePassthrough]
    SubtitlingType: Optional[DvbSubtitlingType]
    TeletextSpacing: Optional[DvbSubtitleTeletextSpacing]
    Width: Optional[_integerMin1Max2147483647]
    XPosition: Optional[_integerMin0Max2147483647]
    YPosition: Optional[_integerMin0Max2147483647]


class CaptionDestinationSettings(TypedDict, total=False):
    BurninDestinationSettings: Optional[BurninDestinationSettings]
    DestinationType: Optional[CaptionDestinationType]
    DvbSubDestinationSettings: Optional[DvbSubDestinationSettings]
    EmbeddedDestinationSettings: Optional[EmbeddedDestinationSettings]
    ImscDestinationSettings: Optional[ImscDestinationSettings]
    SccDestinationSettings: Optional[SccDestinationSettings]
    SrtDestinationSettings: Optional[SrtDestinationSettings]
    TeletextDestinationSettings: Optional[TeletextDestinationSettings]
    TtmlDestinationSettings: Optional[TtmlDestinationSettings]
    WebvttDestinationSettings: Optional[WebvttDestinationSettings]


class CaptionDescription(TypedDict, total=False):
    CaptionSelectorName: Optional[_stringMin1]
    CustomLanguageCode: Optional[_stringPatternAZaZ23AZaZ]
    DestinationSettings: Optional[CaptionDestinationSettings]
    LanguageCode: Optional[LanguageCode]
    LanguageDescription: Optional[_string]


class CaptionDescriptionPreset(TypedDict, total=False):
    CustomLanguageCode: Optional[_stringPatternAZaZ23AZaZ]
    DestinationSettings: Optional[CaptionDestinationSettings]
    LanguageCode: Optional[LanguageCode]
    LanguageDescription: Optional[_string]


class WebvttHlsSourceSettings(TypedDict, total=False):
    RenditionGroupId: Optional[_string]
    RenditionLanguageCode: Optional[LanguageCode]
    RenditionName: Optional[_string]


class TrackSourceSettings(TypedDict, total=False):
    TrackNumber: Optional[_integerMin1Max2147483647]


class TeletextSourceSettings(TypedDict, total=False):
    PageNumber: Optional[_stringMin3Max3Pattern1809aFAF09aEAE]


class CaptionSourceFramerate(TypedDict, total=False):
    FramerateDenominator: Optional[_integerMin1Max1001]
    FramerateNumerator: Optional[_integerMin1Max60000]


class FileSourceSettings(TypedDict, total=False):
    Convert608To708: Optional[FileSourceConvert608To708]
    Framerate: Optional[CaptionSourceFramerate]
    SourceFile: Optional[
        _stringMin14PatternS3SccSCCTtmlTTMLDfxpDFXPStlSTLSrtSRTXmlXMLSmiSMIVttVTTWebvttWEBVTTHttpsSccSCCTtmlTTMLDfxpDFXPStlSTLSrtSRTXmlXMLSmiSMIVttVTTWebvttWEBVTT
    ]
    TimeDelta: Optional[_integerMinNegative2147483648Max2147483647]
    TimeDeltaUnits: Optional[FileSourceTimeDeltaUnits]


class EmbeddedSourceSettings(TypedDict, total=False):
    Convert608To708: Optional[EmbeddedConvert608To708]
    Source608ChannelNumber: Optional[_integerMin1Max4]
    Source608TrackNumber: Optional[_integerMin1Max1]
    TerminateCaptions: Optional[EmbeddedTerminateCaptions]


class DvbSubSourceSettings(TypedDict, total=False):
    Pid: Optional[_integerMin1Max2147483647]


class CaptionSourceSettings(TypedDict, total=False):
    AncillarySourceSettings: Optional[AncillarySourceSettings]
    DvbSubSourceSettings: Optional[DvbSubSourceSettings]
    EmbeddedSourceSettings: Optional[EmbeddedSourceSettings]
    FileSourceSettings: Optional[FileSourceSettings]
    SourceType: Optional[CaptionSourceType]
    TeletextSourceSettings: Optional[TeletextSourceSettings]
    TrackSourceSettings: Optional[TrackSourceSettings]
    WebvttHlsSourceSettings: Optional[WebvttHlsSourceSettings]


class CaptionSelector(TypedDict, total=False):
    CustomLanguageCode: Optional[_stringMin3Max3PatternAZaZ3]
    LanguageCode: Optional[LanguageCode]
    SourceSettings: Optional[CaptionSourceSettings]


class CmafAdditionalManifest(TypedDict, total=False):
    ManifestNameModifier: Optional[_stringMin1]
    SelectedOutputs: Optional[_listOf__stringMin1]


class StaticKeyProvider(TypedDict, total=False):
    KeyFormat: Optional[_stringPatternIdentityAZaZ26AZaZ09163]
    KeyFormatVersions: Optional[_stringPatternDD]
    StaticKeyValue: Optional[_stringPatternAZaZ0932]
    Url: Optional[_string]


_listOf__stringMin36Max36Pattern09aFAF809aFAF409aFAF409aFAF409aFAF12 = List[
    _stringMin36Max36Pattern09aFAF809aFAF409aFAF409aFAF409aFAF12
]


class SpekeKeyProviderCmaf(TypedDict, total=False):
    CertificateArn: Optional[_stringPatternArnAwsUsGovAcm]
    DashSignaledSystemIds: Optional[
        _listOf__stringMin36Max36Pattern09aFAF809aFAF409aFAF409aFAF409aFAF12
    ]
    HlsSignaledSystemIds: Optional[
        _listOf__stringMin36Max36Pattern09aFAF809aFAF409aFAF409aFAF409aFAF12
    ]
    ResourceId: Optional[_stringPatternW]
    Url: Optional[_stringPatternHttps]


class CmafEncryptionSettings(TypedDict, total=False):
    ConstantInitializationVector: Optional[_stringMin32Max32Pattern09aFAF32]
    EncryptionMethod: Optional[CmafEncryptionType]
    InitializationVectorInManifest: Optional[CmafInitializationVectorInManifest]
    SpekeKeyProvider: Optional[SpekeKeyProviderCmaf]
    StaticKeyProvider: Optional[StaticKeyProvider]
    Type: Optional[CmafKeyProviderType]


class CmafImageBasedTrickPlaySettings(TypedDict, total=False):
    IntervalCadence: Optional[CmafIntervalCadence]
    ThumbnailHeight: Optional[_integerMin2Max4096]
    ThumbnailInterval: Optional[_doubleMin0Max2147483647]
    ThumbnailWidth: Optional[_integerMin8Max4096]
    TileHeight: Optional[_integerMin1Max2048]
    TileWidth: Optional[_integerMin1Max512]


class S3EncryptionSettings(TypedDict, total=False):
    EncryptionType: Optional[S3ServerSideEncryptionType]
    KmsEncryptionContext: Optional[_stringPatternAZaZ0902]
    KmsKeyArn: Optional[
        _stringPatternArnAwsUsGovCnKmsAZ26EastWestCentralNorthSouthEastWest1912D12KeyAFAF098AFAF094AFAF094AFAF094AFAF0912MrkAFAF0932
    ]


class S3DestinationAccessControl(TypedDict, total=False):
    CannedAcl: Optional[S3ObjectCannedAcl]


class S3DestinationSettings(TypedDict, total=False):
    AccessControl: Optional[S3DestinationAccessControl]
    Encryption: Optional[S3EncryptionSettings]


class DestinationSettings(TypedDict, total=False):
    S3Settings: Optional[S3DestinationSettings]


_listOfCmafAdditionalManifest = List[CmafAdditionalManifest]


class CmafGroupSettings(TypedDict, total=False):
    AdditionalManifests: Optional[_listOfCmafAdditionalManifest]
    BaseUrl: Optional[_string]
    ClientCache: Optional[CmafClientCache]
    CodecSpecification: Optional[CmafCodecSpecification]
    Destination: Optional[_stringPatternS3]
    DestinationSettings: Optional[DestinationSettings]
    Encryption: Optional[CmafEncryptionSettings]
    FragmentLength: Optional[_integerMin1Max2147483647]
    ImageBasedTrickPlay: Optional[CmafImageBasedTrickPlay]
    ImageBasedTrickPlaySettings: Optional[CmafImageBasedTrickPlaySettings]
    ManifestCompression: Optional[CmafManifestCompression]
    ManifestDurationFormat: Optional[CmafManifestDurationFormat]
    MinBufferTime: Optional[_integerMin0Max2147483647]
    MinFinalSegmentLength: Optional[_doubleMin0Max2147483647]
    MpdProfile: Optional[CmafMpdProfile]
    PtsOffsetHandlingForBFrames: Optional[CmafPtsOffsetHandlingForBFrames]
    SegmentControl: Optional[CmafSegmentControl]
    SegmentLength: Optional[_integerMin1Max2147483647]
    SegmentLengthControl: Optional[CmafSegmentLengthControl]
    StreamInfResolution: Optional[CmafStreamInfResolution]
    TargetDurationCompatibilityMode: Optional[CmafTargetDurationCompatibilityMode]
    WriteDashManifest: Optional[CmafWriteDASHManifest]
    WriteHlsManifest: Optional[CmafWriteHLSManifest]
    WriteSegmentTimelineInRepresentation: Optional[CmafWriteSegmentTimelineInRepresentation]


class CmfcSettings(TypedDict, total=False):
    AudioDuration: Optional[CmfcAudioDuration]
    AudioGroupId: Optional[_string]
    AudioRenditionSets: Optional[_string]
    AudioTrackType: Optional[CmfcAudioTrackType]
    DescriptiveVideoServiceFlag: Optional[CmfcDescriptiveVideoServiceFlag]
    IFrameOnlyManifest: Optional[CmfcIFrameOnlyManifest]
    Scte35Esam: Optional[CmfcScte35Esam]
    Scte35Source: Optional[CmfcScte35Source]
    TimedMetadata: Optional[CmfcTimedMetadata]


class Hdr10Metadata(TypedDict, total=False):
    BluePrimaryX: Optional[_integerMin0Max50000]
    BluePrimaryY: Optional[_integerMin0Max50000]
    GreenPrimaryX: Optional[_integerMin0Max50000]
    GreenPrimaryY: Optional[_integerMin0Max50000]
    MaxContentLightLevel: Optional[_integerMin0Max65535]
    MaxFrameAverageLightLevel: Optional[_integerMin0Max65535]
    MaxLuminance: Optional[_integerMin0Max2147483647]
    MinLuminance: Optional[_integerMin0Max2147483647]
    RedPrimaryX: Optional[_integerMin0Max50000]
    RedPrimaryY: Optional[_integerMin0Max50000]
    WhitePointX: Optional[_integerMin0Max50000]
    WhitePointY: Optional[_integerMin0Max50000]


class ColorCorrector(TypedDict, total=False):
    Brightness: Optional[_integerMin1Max100]
    ColorSpaceConversion: Optional[ColorSpaceConversion]
    Contrast: Optional[_integerMin1Max100]
    Hdr10Metadata: Optional[Hdr10Metadata]
    Hue: Optional[_integerMinNegative180Max180]
    SampleRangeConversion: Optional[SampleRangeConversion]
    Saturation: Optional[_integerMin1Max100]


class MxfXavcProfileSettings(TypedDict, total=False):
    DurationMode: Optional[MxfXavcDurationMode]
    MaxAncDataSize: Optional[_integerMin0Max2147483647]


class MxfSettings(TypedDict, total=False):
    AfdSignaling: Optional[MxfAfdSignaling]
    Profile: Optional[MxfProfile]
    XavcProfileSettings: Optional[MxfXavcProfileSettings]


class MpdSettings(TypedDict, total=False):
    AccessibilityCaptionHints: Optional[MpdAccessibilityCaptionHints]
    AudioDuration: Optional[MpdAudioDuration]
    CaptionContainerType: Optional[MpdCaptionContainerType]
    Scte35Esam: Optional[MpdScte35Esam]
    Scte35Source: Optional[MpdScte35Source]
    TimedMetadata: Optional[MpdTimedMetadata]


class Mp4Settings(TypedDict, total=False):
    AudioDuration: Optional[CmfcAudioDuration]
    CslgAtom: Optional[Mp4CslgAtom]
    CttsVersion: Optional[_integerMin0Max1]
    FreeSpaceBox: Optional[Mp4FreeSpaceBox]
    MoovPlacement: Optional[Mp4MoovPlacement]
    Mp4MajorBrand: Optional[_string]


class MovSettings(TypedDict, total=False):
    ClapAtom: Optional[MovClapAtom]
    CslgAtom: Optional[MovCslgAtom]
    Mpeg2FourCCControl: Optional[MovMpeg2FourCCControl]
    PaddingControl: Optional[MovPaddingControl]
    Reference: Optional[MovReference]


_listOf__integerMin32Max8182 = List[_integerMin32Max8182]


class M3u8Settings(TypedDict, total=False):
    AudioDuration: Optional[M3u8AudioDuration]
    AudioFramesPerPes: Optional[_integerMin0Max2147483647]
    AudioPids: Optional[_listOf__integerMin32Max8182]
    DataPTSControl: Optional[M3u8DataPtsControl]
    MaxPcrInterval: Optional[_integerMin0Max500]
    NielsenId3: Optional[M3u8NielsenId3]
    PatInterval: Optional[_integerMin0Max1000]
    PcrControl: Optional[M3u8PcrControl]
    PcrPid: Optional[_integerMin32Max8182]
    PmtInterval: Optional[_integerMin0Max1000]
    PmtPid: Optional[_integerMin32Max8182]
    PrivateMetadataPid: Optional[_integerMin32Max8182]
    ProgramNumber: Optional[_integerMin0Max65535]
    Scte35Pid: Optional[_integerMin32Max8182]
    Scte35Source: Optional[M3u8Scte35Source]
    TimedMetadata: Optional[TimedMetadata]
    TimedMetadataPid: Optional[_integerMin32Max8182]
    TransportStreamId: Optional[_integerMin0Max65535]
    VideoPid: Optional[_integerMin32Max8182]


class M2tsScte35Esam(TypedDict, total=False):
    Scte35EsamPid: Optional[_integerMin32Max8182]


class DvbTdtSettings(TypedDict, total=False):
    TdtInterval: Optional[_integerMin1000Max30000]


class DvbSdtSettings(TypedDict, total=False):
    OutputSdt: Optional[OutputSdt]
    SdtInterval: Optional[_integerMin25Max2000]
    ServiceName: Optional[_stringMin1Max256]
    ServiceProviderName: Optional[_stringMin1Max256]


class DvbNitSettings(TypedDict, total=False):
    NetworkId: Optional[_integerMin0Max65535]
    NetworkName: Optional[_stringMin1Max256]
    NitInterval: Optional[_integerMin25Max10000]


class M2tsSettings(TypedDict, total=False):
    AudioBufferModel: Optional[M2tsAudioBufferModel]
    AudioDuration: Optional[M2tsAudioDuration]
    AudioFramesPerPes: Optional[_integerMin0Max2147483647]
    AudioPids: Optional[_listOf__integerMin32Max8182]
    Bitrate: Optional[_integerMin0Max2147483647]
    BufferModel: Optional[M2tsBufferModel]
    DataPTSControl: Optional[M2tsDataPtsControl]
    DvbNitSettings: Optional[DvbNitSettings]
    DvbSdtSettings: Optional[DvbSdtSettings]
    DvbSubPids: Optional[_listOf__integerMin32Max8182]
    DvbTdtSettings: Optional[DvbTdtSettings]
    DvbTeletextPid: Optional[_integerMin32Max8182]
    EbpAudioInterval: Optional[M2tsEbpAudioInterval]
    EbpPlacement: Optional[M2tsEbpPlacement]
    EsRateInPes: Optional[M2tsEsRateInPes]
    ForceTsVideoEbpOrder: Optional[M2tsForceTsVideoEbpOrder]
    FragmentTime: Optional[_doubleMin0]
    MaxPcrInterval: Optional[_integerMin0Max500]
    MinEbpInterval: Optional[_integerMin0Max10000]
    NielsenId3: Optional[M2tsNielsenId3]
    NullPacketBitrate: Optional[_doubleMin0]
    PatInterval: Optional[_integerMin0Max1000]
    PcrControl: Optional[M2tsPcrControl]
    PcrPid: Optional[_integerMin32Max8182]
    PmtInterval: Optional[_integerMin0Max1000]
    PmtPid: Optional[_integerMin32Max8182]
    PrivateMetadataPid: Optional[_integerMin32Max8182]
    ProgramNumber: Optional[_integerMin0Max65535]
    RateMode: Optional[M2tsRateMode]
    Scte35Esam: Optional[M2tsScte35Esam]
    Scte35Pid: Optional[_integerMin32Max8182]
    Scte35Source: Optional[M2tsScte35Source]
    SegmentationMarkers: Optional[M2tsSegmentationMarkers]
    SegmentationStyle: Optional[M2tsSegmentationStyle]
    SegmentationTime: Optional[_doubleMin0]
    TimedMetadataPid: Optional[_integerMin32Max8182]
    TransportStreamId: Optional[_integerMin0Max65535]
    VideoPid: Optional[_integerMin32Max8182]


class F4vSettings(TypedDict, total=False):
    MoovPlacement: Optional[F4vMoovPlacement]


class ContainerSettings(TypedDict, total=False):
    CmfcSettings: Optional[CmfcSettings]
    Container: Optional[ContainerType]
    F4vSettings: Optional[F4vSettings]
    M2tsSettings: Optional[M2tsSettings]
    M3u8Settings: Optional[M3u8Settings]
    MovSettings: Optional[MovSettings]
    Mp4Settings: Optional[Mp4Settings]
    MpdSettings: Optional[MpdSettings]
    MxfSettings: Optional[MxfSettings]


_mapOf__string = Dict[_string, _string]


class Id3Insertion(TypedDict, total=False):
    Id3: Optional[_stringPatternAZaZ0902]
    Timecode: Optional[_stringPattern010920405090509092]


_listOfId3Insertion = List[Id3Insertion]


class TimedMetadataInsertion(TypedDict, total=False):
    Id3Insertions: Optional[_listOfId3Insertion]


class TimecodeConfig(TypedDict, total=False):
    Anchor: Optional[_stringPattern010920405090509092]
    Source: Optional[TimecodeSource]
    Start: Optional[_stringPattern010920405090509092]
    TimestampOffset: Optional[_stringPattern0940191020191209301]


class TimecodeBurnin(TypedDict, total=False):
    FontSize: Optional[_integerMin10Max48]
    Position: Optional[TimecodeBurninPosition]
    Prefix: Optional[_stringPattern]


class NexGuardFileMarkerSettings(TypedDict, total=False):
    License: Optional[_stringMin1Max100000]
    Payload: Optional[_integerMin0Max4194303]
    Preset: Optional[_stringMin1Max256]
    Strength: Optional[WatermarkingStrength]


class PartnerWatermarking(TypedDict, total=False):
    NexguardFileMarkerSettings: Optional[NexGuardFileMarkerSettings]


class NoiseReducerTemporalFilterSettings(TypedDict, total=False):
    AggressiveMode: Optional[_integerMin0Max4]
    PostTemporalSharpening: Optional[NoiseFilterPostTemporalSharpening]
    PostTemporalSharpeningStrength: Optional[NoiseFilterPostTemporalSharpeningStrength]
    Speed: Optional[_integerMinNegative1Max3]
    Strength: Optional[_integerMin0Max16]


class NoiseReducerSpatialFilterSettings(TypedDict, total=False):
    PostFilterSharpenStrength: Optional[_integerMin0Max3]
    Speed: Optional[_integerMinNegative2Max3]
    Strength: Optional[_integerMin0Max16]


class NoiseReducerFilterSettings(TypedDict, total=False):
    Strength: Optional[_integerMin0Max3]


class NoiseReducer(TypedDict, total=False):
    Filter: Optional[NoiseReducerFilter]
    FilterSettings: Optional[NoiseReducerFilterSettings]
    SpatialFilterSettings: Optional[NoiseReducerSpatialFilterSettings]
    TemporalFilterSettings: Optional[NoiseReducerTemporalFilterSettings]


class InsertableImage(TypedDict, total=False):
    Duration: Optional[_integerMin0Max2147483647]
    FadeIn: Optional[_integerMin0Max2147483647]
    FadeOut: Optional[_integerMin0Max2147483647]
    Height: Optional[_integerMin0Max2147483647]
    ImageInserterInput: Optional[_stringMin14PatternS3BmpBMPPngPNGTgaTGAHttpsBmpBMPPngPNGTgaTGA]
    ImageX: Optional[_integerMin0Max2147483647]
    ImageY: Optional[_integerMin0Max2147483647]
    Layer: Optional[_integerMin0Max99]
    Opacity: Optional[_integerMin0Max100]
    StartTime: Optional[_stringPattern01D20305D205D]
    Width: Optional[_integerMin0Max2147483647]


_listOfInsertableImage = List[InsertableImage]


class ImageInserter(TypedDict, total=False):
    InsertableImages: Optional[_listOfInsertableImage]


class Hdr10Plus(TypedDict, total=False):
    MasteringMonitorNits: Optional[_integerMin0Max4000]
    TargetMonitorNits: Optional[_integerMin0Max4000]


class DolbyVisionLevel6Metadata(TypedDict, total=False):
    MaxCll: Optional[_integerMin0Max65535]
    MaxFall: Optional[_integerMin0Max65535]


class DolbyVision(TypedDict, total=False):
    L6Metadata: Optional[DolbyVisionLevel6Metadata]
    L6Mode: Optional[DolbyVisionLevel6Mode]
    Profile: Optional[DolbyVisionProfile]


class Deinterlacer(TypedDict, total=False):
    Algorithm: Optional[DeinterlaceAlgorithm]
    Control: Optional[DeinterlacerControl]
    Mode: Optional[DeinterlacerMode]


class VideoPreprocessor(TypedDict, total=False):
    ColorCorrector: Optional[ColorCorrector]
    Deinterlacer: Optional[Deinterlacer]
    DolbyVision: Optional[DolbyVision]
    Hdr10Plus: Optional[Hdr10Plus]
    ImageInserter: Optional[ImageInserter]
    NoiseReducer: Optional[NoiseReducer]
    PartnerWatermarking: Optional[PartnerWatermarking]
    TimecodeBurnin: Optional[TimecodeBurnin]


class Rectangle(TypedDict, total=False):
    Height: Optional[_integerMin2Max2147483647]
    Width: Optional[_integerMin2Max2147483647]
    X: Optional[_integerMin0Max2147483647]
    Y: Optional[_integerMin0Max2147483647]


class XavcHdProfileSettings(TypedDict, total=False):
    BitrateClass: Optional[XavcHdProfileBitrateClass]
    FlickerAdaptiveQuantization: Optional[XavcFlickerAdaptiveQuantization]
    GopBReference: Optional[XavcGopBReference]
    GopClosedCadence: Optional[_integerMin0Max2147483647]
    HrdBufferSize: Optional[_integerMin0Max1152000000]
    InterlaceMode: Optional[XavcInterlaceMode]
    QualityTuningLevel: Optional[XavcHdProfileQualityTuningLevel]
    Slices: Optional[_integerMin4Max12]
    Telecine: Optional[XavcHdProfileTelecine]


class XavcHdIntraCbgProfileSettings(TypedDict, total=False):
    XavcClass: Optional[XavcHdIntraCbgProfileClass]


class Xavc4kProfileSettings(TypedDict, total=False):
    BitrateClass: Optional[Xavc4kProfileBitrateClass]
    CodecProfile: Optional[Xavc4kProfileCodecProfile]
    FlickerAdaptiveQuantization: Optional[XavcFlickerAdaptiveQuantization]
    GopBReference: Optional[XavcGopBReference]
    GopClosedCadence: Optional[_integerMin0Max2147483647]
    HrdBufferSize: Optional[_integerMin0Max1152000000]
    QualityTuningLevel: Optional[Xavc4kProfileQualityTuningLevel]
    Slices: Optional[_integerMin8Max12]


class Xavc4kIntraVbrProfileSettings(TypedDict, total=False):
    XavcClass: Optional[Xavc4kIntraVbrProfileClass]


class Xavc4kIntraCbgProfileSettings(TypedDict, total=False):
    XavcClass: Optional[Xavc4kIntraCbgProfileClass]


class XavcSettings(TypedDict, total=False):
    AdaptiveQuantization: Optional[XavcAdaptiveQuantization]
    EntropyEncoding: Optional[XavcEntropyEncoding]
    FramerateControl: Optional[XavcFramerateControl]
    FramerateConversionAlgorithm: Optional[XavcFramerateConversionAlgorithm]
    FramerateDenominator: Optional[_integerMin1Max1001]
    FramerateNumerator: Optional[_integerMin24Max60000]
    Profile: Optional[XavcProfile]
    SlowPal: Optional[XavcSlowPal]
    Softness: Optional[_integerMin0Max128]
    SpatialAdaptiveQuantization: Optional[XavcSpatialAdaptiveQuantization]
    TemporalAdaptiveQuantization: Optional[XavcTemporalAdaptiveQuantization]
    Xavc4kIntraCbgProfileSettings: Optional[Xavc4kIntraCbgProfileSettings]
    Xavc4kIntraVbrProfileSettings: Optional[Xavc4kIntraVbrProfileSettings]
    Xavc4kProfileSettings: Optional[Xavc4kProfileSettings]
    XavcHdIntraCbgProfileSettings: Optional[XavcHdIntraCbgProfileSettings]
    XavcHdProfileSettings: Optional[XavcHdProfileSettings]


class Vp9Settings(TypedDict, total=False):
    Bitrate: Optional[_integerMin1000Max480000000]
    FramerateControl: Optional[Vp9FramerateControl]
    FramerateConversionAlgorithm: Optional[Vp9FramerateConversionAlgorithm]
    FramerateDenominator: Optional[_integerMin1Max2147483647]
    FramerateNumerator: Optional[_integerMin1Max2147483647]
    GopSize: Optional[_doubleMin0]
    HrdBufferSize: Optional[_integerMin0Max47185920]
    MaxBitrate: Optional[_integerMin1000Max480000000]
    ParControl: Optional[Vp9ParControl]
    ParDenominator: Optional[_integerMin1Max2147483647]
    ParNumerator: Optional[_integerMin1Max2147483647]
    QualityTuningLevel: Optional[Vp9QualityTuningLevel]
    RateControlMode: Optional[Vp9RateControlMode]


class Vp8Settings(TypedDict, total=False):
    Bitrate: Optional[_integerMin1000Max1152000000]
    FramerateControl: Optional[Vp8FramerateControl]
    FramerateConversionAlgorithm: Optional[Vp8FramerateConversionAlgorithm]
    FramerateDenominator: Optional[_integerMin1Max2147483647]
    FramerateNumerator: Optional[_integerMin1Max2147483647]
    GopSize: Optional[_doubleMin0]
    HrdBufferSize: Optional[_integerMin0Max47185920]
    MaxBitrate: Optional[_integerMin1000Max1152000000]
    ParControl: Optional[Vp8ParControl]
    ParDenominator: Optional[_integerMin1Max2147483647]
    ParNumerator: Optional[_integerMin1Max2147483647]
    QualityTuningLevel: Optional[Vp8QualityTuningLevel]
    RateControlMode: Optional[Vp8RateControlMode]


class Vc3Settings(TypedDict, total=False):
    FramerateControl: Optional[Vc3FramerateControl]
    FramerateConversionAlgorithm: Optional[Vc3FramerateConversionAlgorithm]
    FramerateDenominator: Optional[_integerMin1Max1001]
    FramerateNumerator: Optional[_integerMin24Max60000]
    InterlaceMode: Optional[Vc3InterlaceMode]
    ScanTypeConversionMode: Optional[Vc3ScanTypeConversionMode]
    SlowPal: Optional[Vc3SlowPal]
    Telecine: Optional[Vc3Telecine]
    Vc3Class: Optional[Vc3Class]


class ProresSettings(TypedDict, total=False):
    ChromaSampling: Optional[ProresChromaSampling]
    CodecProfile: Optional[ProresCodecProfile]
    FramerateControl: Optional[ProresFramerateControl]
    FramerateConversionAlgorithm: Optional[ProresFramerateConversionAlgorithm]
    FramerateDenominator: Optional[_integerMin1Max2147483647]
    FramerateNumerator: Optional[_integerMin1Max2147483647]
    InterlaceMode: Optional[ProresInterlaceMode]
    ParControl: Optional[ProresParControl]
    ParDenominator: Optional[_integerMin1Max2147483647]
    ParNumerator: Optional[_integerMin1Max2147483647]
    ScanTypeConversionMode: Optional[ProresScanTypeConversionMode]
    SlowPal: Optional[ProresSlowPal]
    Telecine: Optional[ProresTelecine]


class Mpeg2Settings(TypedDict, total=False):
    AdaptiveQuantization: Optional[Mpeg2AdaptiveQuantization]
    Bitrate: Optional[_integerMin1000Max288000000]
    CodecLevel: Optional[Mpeg2CodecLevel]
    CodecProfile: Optional[Mpeg2CodecProfile]
    DynamicSubGop: Optional[Mpeg2DynamicSubGop]
    FramerateControl: Optional[Mpeg2FramerateControl]
    FramerateConversionAlgorithm: Optional[Mpeg2FramerateConversionAlgorithm]
    FramerateDenominator: Optional[_integerMin1Max1001]
    FramerateNumerator: Optional[_integerMin24Max60000]
    GopClosedCadence: Optional[_integerMin0Max2147483647]
    GopSize: Optional[_doubleMin0]
    GopSizeUnits: Optional[Mpeg2GopSizeUnits]
    HrdBufferInitialFillPercentage: Optional[_integerMin0Max100]
    HrdBufferSize: Optional[_integerMin0Max47185920]
    InterlaceMode: Optional[Mpeg2InterlaceMode]
    IntraDcPrecision: Optional[Mpeg2IntraDcPrecision]
    MaxBitrate: Optional[_integerMin1000Max300000000]
    MinIInterval: Optional[_integerMin0Max30]
    NumberBFramesBetweenReferenceFrames: Optional[_integerMin0Max7]
    ParControl: Optional[Mpeg2ParControl]
    ParDenominator: Optional[_integerMin1Max2147483647]
    ParNumerator: Optional[_integerMin1Max2147483647]
    QualityTuningLevel: Optional[Mpeg2QualityTuningLevel]
    RateControlMode: Optional[Mpeg2RateControlMode]
    ScanTypeConversionMode: Optional[Mpeg2ScanTypeConversionMode]
    SceneChangeDetect: Optional[Mpeg2SceneChangeDetect]
    SlowPal: Optional[Mpeg2SlowPal]
    Softness: Optional[_integerMin0Max128]
    SpatialAdaptiveQuantization: Optional[Mpeg2SpatialAdaptiveQuantization]
    Syntax: Optional[Mpeg2Syntax]
    Telecine: Optional[Mpeg2Telecine]
    TemporalAdaptiveQuantization: Optional[Mpeg2TemporalAdaptiveQuantization]


class H265QvbrSettings(TypedDict, total=False):
    MaxAverageBitrate: Optional[_integerMin1000Max1466400000]
    QvbrQualityLevel: Optional[_integerMin1Max10]
    QvbrQualityLevelFineTune: Optional[_doubleMin0Max1]


class H265Settings(TypedDict, total=False):
    AdaptiveQuantization: Optional[H265AdaptiveQuantization]
    AlternateTransferFunctionSei: Optional[H265AlternateTransferFunctionSei]
    Bitrate: Optional[_integerMin1000Max1466400000]
    CodecLevel: Optional[H265CodecLevel]
    CodecProfile: Optional[H265CodecProfile]
    DynamicSubGop: Optional[H265DynamicSubGop]
    FlickerAdaptiveQuantization: Optional[H265FlickerAdaptiveQuantization]
    FramerateControl: Optional[H265FramerateControl]
    FramerateConversionAlgorithm: Optional[H265FramerateConversionAlgorithm]
    FramerateDenominator: Optional[_integerMin1Max2147483647]
    FramerateNumerator: Optional[_integerMin1Max2147483647]
    GopBReference: Optional[H265GopBReference]
    GopClosedCadence: Optional[_integerMin0Max2147483647]
    GopSize: Optional[_doubleMin0]
    GopSizeUnits: Optional[H265GopSizeUnits]
    HrdBufferInitialFillPercentage: Optional[_integerMin0Max100]
    HrdBufferSize: Optional[_integerMin0Max1466400000]
    InterlaceMode: Optional[H265InterlaceMode]
    MaxBitrate: Optional[_integerMin1000Max1466400000]
    MinIInterval: Optional[_integerMin0Max30]
    NumberBFramesBetweenReferenceFrames: Optional[_integerMin0Max7]
    NumberReferenceFrames: Optional[_integerMin1Max6]
    ParControl: Optional[H265ParControl]
    ParDenominator: Optional[_integerMin1Max2147483647]
    ParNumerator: Optional[_integerMin1Max2147483647]
    QualityTuningLevel: Optional[H265QualityTuningLevel]
    QvbrSettings: Optional[H265QvbrSettings]
    RateControlMode: Optional[H265RateControlMode]
    SampleAdaptiveOffsetFilterMode: Optional[H265SampleAdaptiveOffsetFilterMode]
    ScanTypeConversionMode: Optional[H265ScanTypeConversionMode]
    SceneChangeDetect: Optional[H265SceneChangeDetect]
    Slices: Optional[_integerMin1Max32]
    SlowPal: Optional[H265SlowPal]
    SpatialAdaptiveQuantization: Optional[H265SpatialAdaptiveQuantization]
    Telecine: Optional[H265Telecine]
    TemporalAdaptiveQuantization: Optional[H265TemporalAdaptiveQuantization]
    TemporalIds: Optional[H265TemporalIds]
    Tiles: Optional[H265Tiles]
    UnregisteredSeiTimecode: Optional[H265UnregisteredSeiTimecode]
    WriteMp4PackagingType: Optional[H265WriteMp4PackagingType]


class H264QvbrSettings(TypedDict, total=False):
    MaxAverageBitrate: Optional[_integerMin1000Max1152000000]
    QvbrQualityLevel: Optional[_integerMin1Max10]
    QvbrQualityLevelFineTune: Optional[_doubleMin0Max1]


class H264Settings(TypedDict, total=False):
    AdaptiveQuantization: Optional[H264AdaptiveQuantization]
    Bitrate: Optional[_integerMin1000Max1152000000]
    CodecLevel: Optional[H264CodecLevel]
    CodecProfile: Optional[H264CodecProfile]
    DynamicSubGop: Optional[H264DynamicSubGop]
    EntropyEncoding: Optional[H264EntropyEncoding]
    FieldEncoding: Optional[H264FieldEncoding]
    FlickerAdaptiveQuantization: Optional[H264FlickerAdaptiveQuantization]
    FramerateControl: Optional[H264FramerateControl]
    FramerateConversionAlgorithm: Optional[H264FramerateConversionAlgorithm]
    FramerateDenominator: Optional[_integerMin1Max2147483647]
    FramerateNumerator: Optional[_integerMin1Max2147483647]
    GopBReference: Optional[H264GopBReference]
    GopClosedCadence: Optional[_integerMin0Max2147483647]
    GopSize: Optional[_doubleMin0]
    GopSizeUnits: Optional[H264GopSizeUnits]
    HrdBufferInitialFillPercentage: Optional[_integerMin0Max100]
    HrdBufferSize: Optional[_integerMin0Max1152000000]
    InterlaceMode: Optional[H264InterlaceMode]
    MaxBitrate: Optional[_integerMin1000Max1152000000]
    MinIInterval: Optional[_integerMin0Max30]
    NumberBFramesBetweenReferenceFrames: Optional[_integerMin0Max7]
    NumberReferenceFrames: Optional[_integerMin1Max6]
    ParControl: Optional[H264ParControl]
    ParDenominator: Optional[_integerMin1Max2147483647]
    ParNumerator: Optional[_integerMin1Max2147483647]
    QualityTuningLevel: Optional[H264QualityTuningLevel]
    QvbrSettings: Optional[H264QvbrSettings]
    RateControlMode: Optional[H264RateControlMode]
    RepeatPps: Optional[H264RepeatPps]
    ScanTypeConversionMode: Optional[H264ScanTypeConversionMode]
    SceneChangeDetect: Optional[H264SceneChangeDetect]
    Slices: Optional[_integerMin1Max32]
    SlowPal: Optional[H264SlowPal]
    Softness: Optional[_integerMin0Max128]
    SpatialAdaptiveQuantization: Optional[H264SpatialAdaptiveQuantization]
    Syntax: Optional[H264Syntax]
    Telecine: Optional[H264Telecine]
    TemporalAdaptiveQuantization: Optional[H264TemporalAdaptiveQuantization]
    UnregisteredSeiTimecode: Optional[H264UnregisteredSeiTimecode]


class FrameCaptureSettings(TypedDict, total=False):
    FramerateDenominator: Optional[_integerMin1Max2147483647]
    FramerateNumerator: Optional[_integerMin1Max2147483647]
    MaxCaptures: Optional[_integerMin1Max10000000]
    Quality: Optional[_integerMin1Max100]


class VideoCodecSettings(TypedDict, total=False):
    Av1Settings: Optional[Av1Settings]
    AvcIntraSettings: Optional[AvcIntraSettings]
    Codec: Optional[VideoCodec]
    FrameCaptureSettings: Optional[FrameCaptureSettings]
    H264Settings: Optional[H264Settings]
    H265Settings: Optional[H265Settings]
    Mpeg2Settings: Optional[Mpeg2Settings]
    ProresSettings: Optional[ProresSettings]
    Vc3Settings: Optional[Vc3Settings]
    Vp8Settings: Optional[Vp8Settings]
    Vp9Settings: Optional[Vp9Settings]
    XavcSettings: Optional[XavcSettings]


class VideoDescription(TypedDict, total=False):
    AfdSignaling: Optional[AfdSignaling]
    AntiAlias: Optional[AntiAlias]
    CodecSettings: Optional[VideoCodecSettings]
    ColorMetadata: Optional[ColorMetadata]
    Crop: Optional[Rectangle]
    DropFrameTimecode: Optional[DropFrameTimecode]
    FixedAfd: Optional[_integerMin0Max15]
    Height: Optional[_integerMin32Max8192]
    Position: Optional[Rectangle]
    RespondToAfd: Optional[RespondToAfd]
    ScalingBehavior: Optional[ScalingBehavior]
    Sharpness: Optional[_integerMin0Max100]
    TimecodeInsertion: Optional[VideoTimecodeInsertion]
    VideoPreprocessors: Optional[VideoPreprocessor]
    Width: Optional[_integerMin32Max8192]


class HlsSettings(TypedDict, total=False):
    AudioGroupId: Optional[_string]
    AudioOnlyContainer: Optional[HlsAudioOnlyContainer]
    AudioRenditionSets: Optional[_string]
    AudioTrackType: Optional[HlsAudioTrackType]
    DescriptiveVideoServiceFlag: Optional[HlsDescriptiveVideoServiceFlag]
    IFrameOnlyManifest: Optional[HlsIFrameOnlyManifest]
    SegmentModifier: Optional[_string]


class OutputSettings(TypedDict, total=False):
    HlsSettings: Optional[HlsSettings]


_listOfCaptionDescription = List[CaptionDescription]
_listOfAudioDescription = List[AudioDescription]


class Output(TypedDict, total=False):
    AudioDescriptions: Optional[_listOfAudioDescription]
    CaptionDescriptions: Optional[_listOfCaptionDescription]
    ContainerSettings: Optional[ContainerSettings]
    Extension: Optional[_string]
    NameModifier: Optional[_stringMin1]
    OutputSettings: Optional[OutputSettings]
    Preset: Optional[_stringMin0]
    VideoDescription: Optional[VideoDescription]


_listOfOutput = List[Output]
_listOf__stringPattern09aFAF809aFAF409aFAF409aFAF409aFAF12 = List[
    _stringPattern09aFAF809aFAF409aFAF409aFAF409aFAF12
]


class SpekeKeyProvider(TypedDict, total=False):
    CertificateArn: Optional[_stringPatternArnAwsUsGovAcm]
    ResourceId: Optional[_string]
    SystemIds: Optional[_listOf__stringPattern09aFAF809aFAF409aFAF409aFAF409aFAF12]
    Url: Optional[_stringPatternHttps]


class MsSmoothEncryptionSettings(TypedDict, total=False):
    SpekeKeyProvider: Optional[SpekeKeyProvider]


class MsSmoothAdditionalManifest(TypedDict, total=False):
    ManifestNameModifier: Optional[_stringMin1]
    SelectedOutputs: Optional[_listOf__stringMin1]


_listOfMsSmoothAdditionalManifest = List[MsSmoothAdditionalManifest]


class MsSmoothGroupSettings(TypedDict, total=False):
    AdditionalManifests: Optional[_listOfMsSmoothAdditionalManifest]
    AudioDeduplication: Optional[MsSmoothAudioDeduplication]
    Destination: Optional[_stringPatternS3]
    DestinationSettings: Optional[DestinationSettings]
    Encryption: Optional[MsSmoothEncryptionSettings]
    FragmentLength: Optional[_integerMin1Max2147483647]
    FragmentLengthControl: Optional[MsSmoothFragmentLengthControl]
    ManifestEncoding: Optional[MsSmoothManifestEncoding]


class HlsImageBasedTrickPlaySettings(TypedDict, total=False):
    IntervalCadence: Optional[HlsIntervalCadence]
    ThumbnailHeight: Optional[_integerMin2Max4096]
    ThumbnailInterval: Optional[_doubleMin0Max2147483647]
    ThumbnailWidth: Optional[_integerMin8Max4096]
    TileHeight: Optional[_integerMin1Max2048]
    TileWidth: Optional[_integerMin1Max512]


class HlsEncryptionSettings(TypedDict, total=False):
    ConstantInitializationVector: Optional[_stringMin32Max32Pattern09aFAF32]
    EncryptionMethod: Optional[HlsEncryptionType]
    InitializationVectorInManifest: Optional[HlsInitializationVectorInManifest]
    OfflineEncrypted: Optional[HlsOfflineEncrypted]
    SpekeKeyProvider: Optional[SpekeKeyProvider]
    StaticKeyProvider: Optional[StaticKeyProvider]
    Type: Optional[HlsKeyProviderType]


class HlsCaptionLanguageMapping(TypedDict, total=False):
    CaptionChannel: Optional[_integerMinNegative2147483648Max2147483647]
    CustomLanguageCode: Optional[_stringMin3Max3PatternAZaZ3]
    LanguageCode: Optional[LanguageCode]
    LanguageDescription: Optional[_string]


_listOfHlsCaptionLanguageMapping = List[HlsCaptionLanguageMapping]


class HlsAdditionalManifest(TypedDict, total=False):
    ManifestNameModifier: Optional[_stringMin1]
    SelectedOutputs: Optional[_listOf__stringMin1]


_listOfHlsAdditionalManifest = List[HlsAdditionalManifest]
_listOfHlsAdMarkers = List[HlsAdMarkers]


class HlsGroupSettings(TypedDict, total=False):
    AdMarkers: Optional[_listOfHlsAdMarkers]
    AdditionalManifests: Optional[_listOfHlsAdditionalManifest]
    AudioOnlyHeader: Optional[HlsAudioOnlyHeader]
    BaseUrl: Optional[_string]
    CaptionLanguageMappings: Optional[_listOfHlsCaptionLanguageMapping]
    CaptionLanguageSetting: Optional[HlsCaptionLanguageSetting]
    ClientCache: Optional[HlsClientCache]
    CodecSpecification: Optional[HlsCodecSpecification]
    Destination: Optional[_stringPatternS3]
    DestinationSettings: Optional[DestinationSettings]
    DirectoryStructure: Optional[HlsDirectoryStructure]
    Encryption: Optional[HlsEncryptionSettings]
    ImageBasedTrickPlay: Optional[HlsImageBasedTrickPlay]
    ImageBasedTrickPlaySettings: Optional[HlsImageBasedTrickPlaySettings]
    ManifestCompression: Optional[HlsManifestCompression]
    ManifestDurationFormat: Optional[HlsManifestDurationFormat]
    MinFinalSegmentLength: Optional[_doubleMin0Max2147483647]
    MinSegmentLength: Optional[_integerMin0Max2147483647]
    OutputSelection: Optional[HlsOutputSelection]
    ProgramDateTime: Optional[HlsProgramDateTime]
    ProgramDateTimePeriod: Optional[_integerMin0Max3600]
    SegmentControl: Optional[HlsSegmentControl]
    SegmentLength: Optional[_integerMin1Max2147483647]
    SegmentLengthControl: Optional[HlsSegmentLengthControl]
    SegmentsPerSubdirectory: Optional[_integerMin1Max2147483647]
    StreamInfResolution: Optional[HlsStreamInfResolution]
    TargetDurationCompatibilityMode: Optional[HlsTargetDurationCompatibilityMode]
    TimedMetadataId3Frame: Optional[HlsTimedMetadataId3Frame]
    TimedMetadataId3Period: Optional[_integerMinNegative2147483648Max2147483647]
    TimestampDeltaMilliseconds: Optional[_integerMinNegative2147483648Max2147483647]


class FileGroupSettings(TypedDict, total=False):
    Destination: Optional[_stringPatternS3]
    DestinationSettings: Optional[DestinationSettings]


class DashIsoImageBasedTrickPlaySettings(TypedDict, total=False):
    IntervalCadence: Optional[DashIsoIntervalCadence]
    ThumbnailHeight: Optional[_integerMin1Max4096]
    ThumbnailInterval: Optional[_doubleMin0Max2147483647]
    ThumbnailWidth: Optional[_integerMin8Max4096]
    TileHeight: Optional[_integerMin1Max2048]
    TileWidth: Optional[_integerMin1Max512]


class DashIsoEncryptionSettings(TypedDict, total=False):
    PlaybackDeviceCompatibility: Optional[DashIsoPlaybackDeviceCompatibility]
    SpekeKeyProvider: Optional[SpekeKeyProvider]


class DashAdditionalManifest(TypedDict, total=False):
    ManifestNameModifier: Optional[_stringMin1]
    SelectedOutputs: Optional[_listOf__stringMin1]


_listOfDashAdditionalManifest = List[DashAdditionalManifest]


class DashIsoGroupSettings(TypedDict, total=False):
    AdditionalManifests: Optional[_listOfDashAdditionalManifest]
    AudioChannelConfigSchemeIdUri: Optional[DashIsoGroupAudioChannelConfigSchemeIdUri]
    BaseUrl: Optional[_string]
    Destination: Optional[_stringPatternS3]
    DestinationSettings: Optional[DestinationSettings]
    Encryption: Optional[DashIsoEncryptionSettings]
    FragmentLength: Optional[_integerMin1Max2147483647]
    HbbtvCompliance: Optional[DashIsoHbbtvCompliance]
    ImageBasedTrickPlay: Optional[DashIsoImageBasedTrickPlay]
    ImageBasedTrickPlaySettings: Optional[DashIsoImageBasedTrickPlaySettings]
    MinBufferTime: Optional[_integerMin0Max2147483647]
    MinFinalSegmentLength: Optional[_doubleMin0Max2147483647]
    MpdProfile: Optional[DashIsoMpdProfile]
    PtsOffsetHandlingForBFrames: Optional[DashIsoPtsOffsetHandlingForBFrames]
    SegmentControl: Optional[DashIsoSegmentControl]
    SegmentLength: Optional[_integerMin1Max2147483647]
    SegmentLengthControl: Optional[DashIsoSegmentLengthControl]
    WriteSegmentTimelineInRepresentation: Optional[DashIsoWriteSegmentTimelineInRepresentation]


class OutputGroupSettings(TypedDict, total=False):
    CmafGroupSettings: Optional[CmafGroupSettings]
    DashIsoGroupSettings: Optional[DashIsoGroupSettings]
    FileGroupSettings: Optional[FileGroupSettings]
    HlsGroupSettings: Optional[HlsGroupSettings]
    MsSmoothGroupSettings: Optional[MsSmoothGroupSettings]
    Type: Optional[OutputGroupType]


class OutputGroup(TypedDict, total=False):
    AutomatedEncodingSettings: Optional[AutomatedEncodingSettings]
    CustomName: Optional[_string]
    Name: Optional[_string]
    OutputGroupSettings: Optional[OutputGroupSettings]
    Outputs: Optional[_listOfOutput]


_listOfOutputGroup = List[OutputGroup]


class NielsenNonLinearWatermarkSettings(TypedDict, total=False):
    ActiveWatermarkProcess: Optional[NielsenActiveWatermarkProcessType]
    AdiFilename: Optional[_stringPatternS3]
    AssetId: Optional[_stringMin1Max20]
    AssetName: Optional[_stringMin1Max50]
    CbetSourceId: Optional[_stringPattern0xAFaF0908190908]
    EpisodeId: Optional[_stringMin1Max20]
    MetadataDestination: Optional[_stringPatternS3]
    SourceId: Optional[_integerMin0Max65534]
    SourceWatermarkStatus: Optional[NielsenSourceWatermarkStatusType]
    TicServerUrl: Optional[_stringPatternHttps]
    UniqueTicPerAudioTrack: Optional[NielsenUniqueTicPerAudioTrackType]


class NielsenConfiguration(TypedDict, total=False):
    BreakoutCode: Optional[_integerMin0Max0]
    DistributorId: Optional[_string]


class MotionImageInsertionOffset(TypedDict, total=False):
    ImageX: Optional[_integerMin0Max2147483647]
    ImageY: Optional[_integerMin0Max2147483647]


class MotionImageInsertionFramerate(TypedDict, total=False):
    FramerateDenominator: Optional[_integerMin1Max17895697]
    FramerateNumerator: Optional[_integerMin1Max2147483640]


class MotionImageInserter(TypedDict, total=False):
    Framerate: Optional[MotionImageInsertionFramerate]
    Input: Optional[_stringMin14PatternS3Mov09PngHttpsMov09Png]
    InsertionMode: Optional[MotionImageInsertionMode]
    Offset: Optional[MotionImageInsertionOffset]
    Playback: Optional[MotionImagePlayback]
    StartTime: Optional[_stringMin11Max11Pattern01D20305D205D]


class KantarWatermarkSettings(TypedDict, total=False):
    ChannelName: Optional[_stringMin1Max20]
    ContentReference: Optional[_stringMin1Max50PatternAZAZ09]
    CredentialsSecretName: Optional[_stringMin1Max512PatternAZAZ09]
    FileOffset: Optional[_doubleMin0]
    KantarLicenseId: Optional[_integerMin0Max2147483647]
    KantarServerUrl: Optional[_stringPatternHttpsKantarmediaCom]
    LogDestination: Optional[_stringPatternS3]
    Metadata3: Optional[_stringMin1Max50]
    Metadata4: Optional[_stringMin1Max50]
    Metadata5: Optional[_stringMin1Max50]
    Metadata6: Optional[_stringMin1Max50]
    Metadata7: Optional[_stringMin1Max50]
    Metadata8: Optional[_stringMin1Max50]


class VideoSelector(TypedDict, total=False):
    AlphaBehavior: Optional[AlphaBehavior]
    ColorSpace: Optional[ColorSpace]
    ColorSpaceUsage: Optional[ColorSpaceUsage]
    Hdr10Metadata: Optional[Hdr10Metadata]
    Pid: Optional[_integerMin1Max2147483647]
    ProgramNumber: Optional[_integerMinNegative2147483648Max2147483647]
    Rotate: Optional[InputRotate]
    SampleRange: Optional[InputSampleRange]


_listOf__stringPatternS3ASSETMAPXml = List[_stringPatternS3ASSETMAPXml]


class InputClipping(TypedDict, total=False):
    EndTimecode: Optional[_stringPattern010920405090509092]
    StartTimecode: Optional[_stringPattern010920405090509092]


_listOfInputClipping = List[InputClipping]


class InputDecryptionSettings(TypedDict, total=False):
    DecryptionMode: Optional[DecryptionMode]
    EncryptedDecryptionKey: Optional[_stringMin24Max512PatternAZaZ0902]
    InitializationVector: Optional[_stringMin16Max24PatternAZaZ0922AZaZ0916]
    KmsKeyRegion: Optional[_stringMin9Max19PatternAZ26EastWestCentralNorthSouthEastWest1912]


_mapOfCaptionSelector = Dict[_string, CaptionSelector]
_mapOfAudioSelector = Dict[_string, AudioSelector]
_mapOfAudioSelectorGroup = Dict[_string, AudioSelectorGroup]


class Input(TypedDict, total=False):
    AudioSelectorGroups: Optional[_mapOfAudioSelectorGroup]
    AudioSelectors: Optional[_mapOfAudioSelector]
    CaptionSelectors: Optional[_mapOfCaptionSelector]
    Crop: Optional[Rectangle]
    DeblockFilter: Optional[InputDeblockFilter]
    DecryptionSettings: Optional[InputDecryptionSettings]
    DenoiseFilter: Optional[InputDenoiseFilter]
    DolbyVisionMetadataXml: Optional[_stringMin14PatternS3XmlXMLHttpsXmlXML]
    FileInput: Optional[
        _stringPatternS3MM2PPMM2VVMMPPEEGGMMPP3AAVVIIMMPP4FFLLVVMMPPTTMMPPGGMM4VVTTRRPPFF4VVMM2TTSSTTSS264HH264MMKKVVMMKKAAMMOOVVMMTTSSMM2TTWWMMVVaAAASSFFVVOOBB3GGPP3GGPPPPMMXXFFDDIIVVXXXXVVIIDDRRAAWWDDVVGGXXFFMM1VV3GG2VVMMFFMM3UU8WWEEBBMMLLCCHHGGXXFFMMPPEEGG2MMXXFFMMPPEEGG2MMXXFFHHDDWWAAVVYY4MMXXMMLLOOGGGGaAAATTMMOOSSHttpsMM2VVMMPPEEGGMMPP3AAVVIIMMPP4FFLLVVMMPPTTMMPPGGMM4VVTTRRPPFF4VVMM2TTSSTTSS264HH264MMKKVVMMKKAAMMOOVVMMTTSSMM2TTWWMMVVaAAASSFFVVOOBB3GGPP3GGPPPPMMXXFFDDIIVVXXXXVVIIDDRRAAWWDDVVGGXXFFMM1VV3GG2VVMMFFMM3UU8WWEEBBMMLLCCHHGGXXFFMMPPEEGG2MMXXFFMMPPEEGG2MMXXFFHHDDWWAAVVYY4MMXXMMLLOOGGGGaAAATTMMOOSS
    ]
    FilterEnable: Optional[InputFilterEnable]
    FilterStrength: Optional[_integerMinNegative5Max5]
    ImageInserter: Optional[ImageInserter]
    InputClippings: Optional[_listOfInputClipping]
    InputScanType: Optional[InputScanType]
    Position: Optional[Rectangle]
    ProgramNumber: Optional[_integerMin1Max2147483647]
    PsiControl: Optional[InputPsiControl]
    SupplementalImps: Optional[_listOf__stringPatternS3ASSETMAPXml]
    TimecodeSource: Optional[InputTimecodeSource]
    TimecodeStart: Optional[_stringMin11Max11Pattern01D20305D205D]
    VideoSelector: Optional[VideoSelector]


_listOfInput = List[Input]


class ExtendedDataServices(TypedDict, total=False):
    CopyProtectionAction: Optional[CopyProtectionAction]
    VchipAction: Optional[VchipAction]


class EsamSignalProcessingNotification(TypedDict, total=False):
    SccXml: Optional[_stringPatternSNSignalProcessingNotificationNS]


class EsamManifestConfirmConditionNotification(TypedDict, total=False):
    MccXml: Optional[_stringPatternSNManifestConfirmConditionNotificationNS]


class EsamSettings(TypedDict, total=False):
    ManifestConfirmConditionNotification: Optional[EsamManifestConfirmConditionNotification]
    ResponseSignalPreroll: Optional[_integerMin0Max30000]
    SignalProcessingNotification: Optional[EsamSignalProcessingNotification]


class JobSettings(TypedDict, total=False):
    AdAvailOffset: Optional[_integerMinNegative1000Max1000]
    AvailBlanking: Optional[AvailBlanking]
    Esam: Optional[EsamSettings]
    ExtendedDataServices: Optional[ExtendedDataServices]
    Inputs: Optional[_listOfInput]
    KantarWatermark: Optional[KantarWatermarkSettings]
    MotionImageInserter: Optional[MotionImageInserter]
    NielsenConfiguration: Optional[NielsenConfiguration]
    NielsenNonLinearWatermark: Optional[NielsenNonLinearWatermarkSettings]
    OutputGroups: Optional[_listOfOutputGroup]
    TimecodeConfig: Optional[TimecodeConfig]
    TimedMetadataInsertion: Optional[TimedMetadataInsertion]


class HopDestination(TypedDict, total=False):
    Priority: Optional[_integerMinNegative50Max50]
    Queue: Optional[_string]
    WaitMinutes: Optional[_integer]


_listOfHopDestination = List[HopDestination]


class CreateJobRequest(ServiceRequest):
    AccelerationSettings: Optional[AccelerationSettings]
    BillingTagsSource: Optional[BillingTagsSource]
    ClientRequestToken: Optional[_string]
    HopDestinations: Optional[_listOfHopDestination]
    JobTemplate: Optional[_string]
    Priority: Optional[_integerMinNegative50Max50]
    Queue: Optional[_string]
    Role: _string
    Settings: JobSettings
    SimulateReservedQueue: Optional[SimulateReservedQueue]
    StatusUpdateInterval: Optional[StatusUpdateInterval]
    Tags: Optional[_mapOf__string]
    UserMetadata: Optional[_mapOf__string]


_timestampUnix = datetime


class Timing(TypedDict, total=False):
    FinishTime: Optional[_timestampUnix]
    StartTime: Optional[_timestampUnix]
    SubmitTime: Optional[_timestampUnix]


class QueueTransition(TypedDict, total=False):
    DestinationQueue: Optional[_string]
    SourceQueue: Optional[_string]
    Timestamp: Optional[_timestampUnix]


_listOfQueueTransition = List[QueueTransition]


class VideoDetail(TypedDict, total=False):
    HeightInPx: Optional[_integer]
    WidthInPx: Optional[_integer]


class OutputDetail(TypedDict, total=False):
    DurationInMs: Optional[_integer]
    VideoDetails: Optional[VideoDetail]


_listOfOutputDetail = List[OutputDetail]


class OutputGroupDetail(TypedDict, total=False):
    OutputDetails: Optional[_listOfOutputDetail]


_listOfOutputGroupDetail = List[OutputGroupDetail]
_listOf__string = List[_string]


class JobMessages(TypedDict, total=False):
    Info: Optional[_listOf__string]
    Warning: Optional[_listOf__string]


class Job(TypedDict, total=False):
    AccelerationSettings: Optional[AccelerationSettings]
    AccelerationStatus: Optional[AccelerationStatus]
    Arn: Optional[_string]
    BillingTagsSource: Optional[BillingTagsSource]
    CreatedAt: Optional[_timestampUnix]
    CurrentPhase: Optional[JobPhase]
    ErrorCode: Optional[_integer]
    ErrorMessage: Optional[_string]
    HopDestinations: Optional[_listOfHopDestination]
    Id: Optional[_string]
    JobPercentComplete: Optional[_integer]
    JobTemplate: Optional[_string]
    Messages: Optional[JobMessages]
    OutputGroupDetails: Optional[_listOfOutputGroupDetail]
    Priority: Optional[_integerMinNegative50Max50]
    Queue: Optional[_string]
    QueueTransitions: Optional[_listOfQueueTransition]
    RetryCount: Optional[_integer]
    Role: _string
    Settings: JobSettings
    SimulateReservedQueue: Optional[SimulateReservedQueue]
    Status: Optional[JobStatus]
    StatusUpdateInterval: Optional[StatusUpdateInterval]
    Timing: Optional[Timing]
    UserMetadata: Optional[_mapOf__string]


class CreateJobResponse(TypedDict, total=False):
    Job: Optional[Job]


class InputTemplate(TypedDict, total=False):
    AudioSelectorGroups: Optional[_mapOfAudioSelectorGroup]
    AudioSelectors: Optional[_mapOfAudioSelector]
    CaptionSelectors: Optional[_mapOfCaptionSelector]
    Crop: Optional[Rectangle]
    DeblockFilter: Optional[InputDeblockFilter]
    DenoiseFilter: Optional[InputDenoiseFilter]
    DolbyVisionMetadataXml: Optional[_stringMin14PatternS3XmlXMLHttpsXmlXML]
    FilterEnable: Optional[InputFilterEnable]
    FilterStrength: Optional[_integerMinNegative5Max5]
    ImageInserter: Optional[ImageInserter]
    InputClippings: Optional[_listOfInputClipping]
    InputScanType: Optional[InputScanType]
    Position: Optional[Rectangle]
    ProgramNumber: Optional[_integerMin1Max2147483647]
    PsiControl: Optional[InputPsiControl]
    TimecodeSource: Optional[InputTimecodeSource]
    TimecodeStart: Optional[_stringMin11Max11Pattern01D20305D205D]
    VideoSelector: Optional[VideoSelector]


_listOfInputTemplate = List[InputTemplate]


class JobTemplateSettings(TypedDict, total=False):
    AdAvailOffset: Optional[_integerMinNegative1000Max1000]
    AvailBlanking: Optional[AvailBlanking]
    Esam: Optional[EsamSettings]
    ExtendedDataServices: Optional[ExtendedDataServices]
    Inputs: Optional[_listOfInputTemplate]
    KantarWatermark: Optional[KantarWatermarkSettings]
    MotionImageInserter: Optional[MotionImageInserter]
    NielsenConfiguration: Optional[NielsenConfiguration]
    NielsenNonLinearWatermark: Optional[NielsenNonLinearWatermarkSettings]
    OutputGroups: Optional[_listOfOutputGroup]
    TimecodeConfig: Optional[TimecodeConfig]
    TimedMetadataInsertion: Optional[TimedMetadataInsertion]


class CreateJobTemplateRequest(ServiceRequest):
    AccelerationSettings: Optional[AccelerationSettings]
    Category: Optional[_string]
    Description: Optional[_string]
    HopDestinations: Optional[_listOfHopDestination]
    Name: _string
    Priority: Optional[_integerMinNegative50Max50]
    Queue: Optional[_string]
    Settings: JobTemplateSettings
    StatusUpdateInterval: Optional[StatusUpdateInterval]
    Tags: Optional[_mapOf__string]


class JobTemplate(TypedDict, total=False):
    AccelerationSettings: Optional[AccelerationSettings]
    Arn: Optional[_string]
    Category: Optional[_string]
    CreatedAt: Optional[_timestampUnix]
    Description: Optional[_string]
    HopDestinations: Optional[_listOfHopDestination]
    LastUpdated: Optional[_timestampUnix]
    Name: _string
    Priority: Optional[_integerMinNegative50Max50]
    Queue: Optional[_string]
    Settings: JobTemplateSettings
    StatusUpdateInterval: Optional[StatusUpdateInterval]
    Type: Optional[Type]


class CreateJobTemplateResponse(TypedDict, total=False):
    JobTemplate: Optional[JobTemplate]


_listOfCaptionDescriptionPreset = List[CaptionDescriptionPreset]


class PresetSettings(TypedDict, total=False):
    AudioDescriptions: Optional[_listOfAudioDescription]
    CaptionDescriptions: Optional[_listOfCaptionDescriptionPreset]
    ContainerSettings: Optional[ContainerSettings]
    VideoDescription: Optional[VideoDescription]


class CreatePresetRequest(ServiceRequest):
    Category: Optional[_string]
    Description: Optional[_string]
    Name: _string
    Settings: PresetSettings
    Tags: Optional[_mapOf__string]


class Preset(TypedDict, total=False):
    Arn: Optional[_string]
    Category: Optional[_string]
    CreatedAt: Optional[_timestampUnix]
    Description: Optional[_string]
    LastUpdated: Optional[_timestampUnix]
    Name: _string
    Settings: PresetSettings
    Type: Optional[Type]


class CreatePresetResponse(TypedDict, total=False):
    Preset: Optional[Preset]


class ReservationPlanSettings(TypedDict, total=False):
    Commitment: Commitment
    RenewalType: RenewalType
    ReservedSlots: _integer


class CreateQueueRequest(ServiceRequest):
    Description: Optional[_string]
    Name: _string
    PricingPlan: Optional[PricingPlan]
    ReservationPlanSettings: Optional[ReservationPlanSettings]
    Status: Optional[QueueStatus]
    Tags: Optional[_mapOf__string]


class ReservationPlan(TypedDict, total=False):
    Commitment: Optional[Commitment]
    ExpiresAt: Optional[_timestampUnix]
    PurchasedAt: Optional[_timestampUnix]
    RenewalType: Optional[RenewalType]
    ReservedSlots: Optional[_integer]
    Status: Optional[ReservationPlanStatus]


class Queue(TypedDict, total=False):
    Arn: Optional[_string]
    CreatedAt: Optional[_timestampUnix]
    Description: Optional[_string]
    LastUpdated: Optional[_timestampUnix]
    Name: _string
    PricingPlan: Optional[PricingPlan]
    ProgressingJobsCount: Optional[_integer]
    ReservationPlan: Optional[ReservationPlan]
    Status: Optional[QueueStatus]
    SubmittedJobsCount: Optional[_integer]
    Type: Optional[Type]


class CreateQueueResponse(TypedDict, total=False):
    Queue: Optional[Queue]


class DeleteJobTemplateRequest(ServiceRequest):
    Name: _string


class DeleteJobTemplateResponse(TypedDict, total=False):
    pass


class DeletePolicyRequest(ServiceRequest):
    pass


class DeletePolicyResponse(TypedDict, total=False):
    pass


class DeletePresetRequest(ServiceRequest):
    Name: _string


class DeletePresetResponse(TypedDict, total=False):
    pass


class DeleteQueueRequest(ServiceRequest):
    Name: _string


class DeleteQueueResponse(TypedDict, total=False):
    pass


class DescribeEndpointsRequest(ServiceRequest):
    MaxResults: Optional[_integer]
    Mode: Optional[DescribeEndpointsMode]
    NextToken: Optional[_string]


class Endpoint(TypedDict, total=False):
    Url: Optional[_string]


_listOfEndpoint = List[Endpoint]


class DescribeEndpointsResponse(TypedDict, total=False):
    Endpoints: Optional[_listOfEndpoint]
    NextToken: Optional[_string]


class DisassociateCertificateRequest(ServiceRequest):
    Arn: _string


class DisassociateCertificateResponse(TypedDict, total=False):
    pass


class ExceptionBody(TypedDict, total=False):
    Message: Optional[_string]


class GetJobRequest(ServiceRequest):
    Id: _string


class GetJobResponse(TypedDict, total=False):
    Job: Optional[Job]


class GetJobTemplateRequest(ServiceRequest):
    Name: _string


class GetJobTemplateResponse(TypedDict, total=False):
    JobTemplate: Optional[JobTemplate]


class GetPolicyRequest(ServiceRequest):
    pass


class Policy(TypedDict, total=False):
    HttpInputs: Optional[InputPolicy]
    HttpsInputs: Optional[InputPolicy]
    S3Inputs: Optional[InputPolicy]


class GetPolicyResponse(TypedDict, total=False):
    Policy: Optional[Policy]


class GetPresetRequest(ServiceRequest):
    Name: _string


class GetPresetResponse(TypedDict, total=False):
    Preset: Optional[Preset]


class GetQueueRequest(ServiceRequest):
    Name: _string


class GetQueueResponse(TypedDict, total=False):
    Queue: Optional[Queue]


class ListJobTemplatesRequest(ServiceRequest):
    Category: Optional[_string]
    ListBy: Optional[JobTemplateListBy]
    MaxResults: Optional[_integerMin1Max20]
    NextToken: Optional[_string]
    Order: Optional[Order]


_listOfJobTemplate = List[JobTemplate]


class ListJobTemplatesResponse(TypedDict, total=False):
    JobTemplates: Optional[_listOfJobTemplate]
    NextToken: Optional[_string]


class ListJobsRequest(ServiceRequest):
    MaxResults: Optional[_integerMin1Max20]
    NextToken: Optional[_string]
    Order: Optional[Order]
    Queue: Optional[_string]
    Status: Optional[JobStatus]


_listOfJob = List[Job]


class ListJobsResponse(TypedDict, total=False):
    Jobs: Optional[_listOfJob]
    NextToken: Optional[_string]


class ListPresetsRequest(ServiceRequest):
    Category: Optional[_string]
    ListBy: Optional[PresetListBy]
    MaxResults: Optional[_integerMin1Max20]
    NextToken: Optional[_string]
    Order: Optional[Order]


_listOfPreset = List[Preset]


class ListPresetsResponse(TypedDict, total=False):
    NextToken: Optional[_string]
    Presets: Optional[_listOfPreset]


class ListQueuesRequest(ServiceRequest):
    ListBy: Optional[QueueListBy]
    MaxResults: Optional[_integerMin1Max20]
    NextToken: Optional[_string]
    Order: Optional[Order]


_listOfQueue = List[Queue]


class ListQueuesResponse(TypedDict, total=False):
    NextToken: Optional[_string]
    Queues: Optional[_listOfQueue]


class ListTagsForResourceRequest(ServiceRequest):
    Arn: _string


class ResourceTags(TypedDict, total=False):
    Arn: Optional[_string]
    Tags: Optional[_mapOf__string]


class ListTagsForResourceResponse(TypedDict, total=False):
    ResourceTags: Optional[ResourceTags]


class PutPolicyRequest(ServiceRequest):
    Policy: Policy


class PutPolicyResponse(TypedDict, total=False):
    Policy: Optional[Policy]


class TagResourceRequest(ServiceRequest):
    Arn: _string
    Tags: _mapOf__string


class TagResourceResponse(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    Arn: _string
    TagKeys: Optional[_listOf__string]


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateJobTemplateRequest(ServiceRequest):
    AccelerationSettings: Optional[AccelerationSettings]
    Category: Optional[_string]
    Description: Optional[_string]
    HopDestinations: Optional[_listOfHopDestination]
    Name: _string
    Priority: Optional[_integerMinNegative50Max50]
    Queue: Optional[_string]
    Settings: Optional[JobTemplateSettings]
    StatusUpdateInterval: Optional[StatusUpdateInterval]


class UpdateJobTemplateResponse(TypedDict, total=False):
    JobTemplate: Optional[JobTemplate]


class UpdatePresetRequest(ServiceRequest):
    Category: Optional[_string]
    Description: Optional[_string]
    Name: _string
    Settings: Optional[PresetSettings]


class UpdatePresetResponse(TypedDict, total=False):
    Preset: Optional[Preset]


class UpdateQueueRequest(ServiceRequest):
    Description: Optional[_string]
    Name: _string
    ReservationPlanSettings: Optional[ReservationPlanSettings]
    Status: Optional[QueueStatus]


class UpdateQueueResponse(TypedDict, total=False):
    Queue: Optional[Queue]


_timestampIso8601 = datetime


class MediaconvertApi:

    service = "mediaconvert"
    version = "2017-08-29"

    @handler("AssociateCertificate")
    def associate_certificate(
        self, context: RequestContext, arn: _string
    ) -> AssociateCertificateResponse:
        raise NotImplementedError

    @handler("CancelJob")
    def cancel_job(self, context: RequestContext, id: _string) -> CancelJobResponse:
        raise NotImplementedError

    @handler("CreateJob")
    def create_job(
        self,
        context: RequestContext,
        role: _string,
        settings: JobSettings,
        acceleration_settings: AccelerationSettings = None,
        billing_tags_source: BillingTagsSource = None,
        client_request_token: _string = None,
        hop_destinations: _listOfHopDestination = None,
        job_template: _string = None,
        priority: _integerMinNegative50Max50 = None,
        queue: _string = None,
        simulate_reserved_queue: SimulateReservedQueue = None,
        status_update_interval: StatusUpdateInterval = None,
        tags: _mapOf__string = None,
        user_metadata: _mapOf__string = None,
    ) -> CreateJobResponse:
        raise NotImplementedError

    @handler("CreateJobTemplate")
    def create_job_template(
        self,
        context: RequestContext,
        settings: JobTemplateSettings,
        name: _string,
        acceleration_settings: AccelerationSettings = None,
        category: _string = None,
        description: _string = None,
        hop_destinations: _listOfHopDestination = None,
        priority: _integerMinNegative50Max50 = None,
        queue: _string = None,
        status_update_interval: StatusUpdateInterval = None,
        tags: _mapOf__string = None,
    ) -> CreateJobTemplateResponse:
        raise NotImplementedError

    @handler("CreatePreset")
    def create_preset(
        self,
        context: RequestContext,
        settings: PresetSettings,
        name: _string,
        category: _string = None,
        description: _string = None,
        tags: _mapOf__string = None,
    ) -> CreatePresetResponse:
        raise NotImplementedError

    @handler("CreateQueue")
    def create_queue(
        self,
        context: RequestContext,
        name: _string,
        description: _string = None,
        pricing_plan: PricingPlan = None,
        reservation_plan_settings: ReservationPlanSettings = None,
        status: QueueStatus = None,
        tags: _mapOf__string = None,
    ) -> CreateQueueResponse:
        raise NotImplementedError

    @handler("DeleteJobTemplate")
    def delete_job_template(
        self, context: RequestContext, name: _string
    ) -> DeleteJobTemplateResponse:
        raise NotImplementedError

    @handler("DeletePolicy")
    def delete_policy(
        self,
        context: RequestContext,
    ) -> DeletePolicyResponse:
        raise NotImplementedError

    @handler("DeletePreset")
    def delete_preset(self, context: RequestContext, name: _string) -> DeletePresetResponse:
        raise NotImplementedError

    @handler("DeleteQueue")
    def delete_queue(self, context: RequestContext, name: _string) -> DeleteQueueResponse:
        raise NotImplementedError

    @handler("DescribeEndpoints")
    def describe_endpoints(
        self,
        context: RequestContext,
        max_results: _integer = None,
        mode: DescribeEndpointsMode = None,
        next_token: _string = None,
    ) -> DescribeEndpointsResponse:
        raise NotImplementedError

    @handler("DisassociateCertificate")
    def disassociate_certificate(
        self, context: RequestContext, arn: _string
    ) -> DisassociateCertificateResponse:
        raise NotImplementedError

    @handler("GetJob")
    def get_job(self, context: RequestContext, id: _string) -> GetJobResponse:
        raise NotImplementedError

    @handler("GetJobTemplate")
    def get_job_template(self, context: RequestContext, name: _string) -> GetJobTemplateResponse:
        raise NotImplementedError

    @handler("GetPolicy")
    def get_policy(
        self,
        context: RequestContext,
    ) -> GetPolicyResponse:
        raise NotImplementedError

    @handler("GetPreset")
    def get_preset(self, context: RequestContext, name: _string) -> GetPresetResponse:
        raise NotImplementedError

    @handler("GetQueue")
    def get_queue(self, context: RequestContext, name: _string) -> GetQueueResponse:
        raise NotImplementedError

    @handler("ListJobTemplates")
    def list_job_templates(
        self,
        context: RequestContext,
        category: _string = None,
        list_by: JobTemplateListBy = None,
        max_results: _integerMin1Max20 = None,
        next_token: _string = None,
        order: Order = None,
    ) -> ListJobTemplatesResponse:
        raise NotImplementedError

    @handler("ListJobs")
    def list_jobs(
        self,
        context: RequestContext,
        max_results: _integerMin1Max20 = None,
        next_token: _string = None,
        order: Order = None,
        queue: _string = None,
        status: JobStatus = None,
    ) -> ListJobsResponse:
        raise NotImplementedError

    @handler("ListPresets")
    def list_presets(
        self,
        context: RequestContext,
        category: _string = None,
        list_by: PresetListBy = None,
        max_results: _integerMin1Max20 = None,
        next_token: _string = None,
        order: Order = None,
    ) -> ListPresetsResponse:
        raise NotImplementedError

    @handler("ListQueues")
    def list_queues(
        self,
        context: RequestContext,
        list_by: QueueListBy = None,
        max_results: _integerMin1Max20 = None,
        next_token: _string = None,
        order: Order = None,
    ) -> ListQueuesResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, arn: _string
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("PutPolicy")
    def put_policy(self, context: RequestContext, policy: Policy) -> PutPolicyResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, arn: _string, tags: _mapOf__string
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, arn: _string, tag_keys: _listOf__string = None
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateJobTemplate")
    def update_job_template(
        self,
        context: RequestContext,
        name: _string,
        acceleration_settings: AccelerationSettings = None,
        category: _string = None,
        description: _string = None,
        hop_destinations: _listOfHopDestination = None,
        priority: _integerMinNegative50Max50 = None,
        queue: _string = None,
        settings: JobTemplateSettings = None,
        status_update_interval: StatusUpdateInterval = None,
    ) -> UpdateJobTemplateResponse:
        raise NotImplementedError

    @handler("UpdatePreset")
    def update_preset(
        self,
        context: RequestContext,
        name: _string,
        category: _string = None,
        description: _string = None,
        settings: PresetSettings = None,
    ) -> UpdatePresetResponse:
        raise NotImplementedError

    @handler("UpdateQueue")
    def update_queue(
        self,
        context: RequestContext,
        name: _string,
        description: _string = None,
        reservation_plan_settings: ReservationPlanSettings = None,
        status: QueueStatus = None,
    ) -> UpdateQueueResponse:
        raise NotImplementedError
