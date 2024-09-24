from datetime import datetime
from typing import cast

from localstack.aws.api.firehose import (
    AmazonopensearchserviceDestinationConfiguration,
    AmazonopensearchserviceDestinationDescription,
    AmazonopensearchserviceDestinationUpdate,
    ElasticsearchDestinationConfiguration,
    ElasticsearchDestinationDescription,
    ElasticsearchDestinationUpdate,
    ExtendedS3DestinationConfiguration,
    ExtendedS3DestinationDescription,
    ExtendedS3DestinationUpdate,
    HttpEndpointDestinationConfiguration,
    HttpEndpointDestinationDescription,
    HttpEndpointDestinationUpdate,
    KinesisStreamSourceConfiguration,
    KinesisStreamSourceDescription,
    RedshiftDestinationConfiguration,
    RedshiftDestinationDescription,
    S3DestinationConfiguration,
    S3DestinationDescription,
    S3DestinationUpdate,
    SourceDescription,
    VpcConfigurationDescription,
)


def convert_es_config_to_desc(
    configuration: ElasticsearchDestinationConfiguration,
) -> ElasticsearchDestinationDescription:
    if configuration is not None:
        # Just take the whole typed dict and typecast it to our target type
        result = cast(ElasticsearchDestinationDescription, configuration)
        # Only specifically handle keys which are named differently or their values differ (version and clusterconfig)
        result["S3DestinationDescription"] = convert_s3_config_to_desc(
            configuration["S3Configuration"]
        )
        if "VpcConfiguration" in configuration:
            result["VpcConfigurationDescription"] = cast(
                VpcConfigurationDescription, configuration["VpcConfiguration"]
            )
        result.pop("S3Configuration", None)
        result.pop("VpcConfiguration", None)
        return result


def convert_es_update_to_desc(
    update: ElasticsearchDestinationUpdate,
) -> ElasticsearchDestinationDescription:
    if update is not None:
        # Just take the whole typed dict and typecast it to our target type
        result = cast(ElasticsearchDestinationDescription, update)
        # Only specifically handle keys which are named differently or their values differ (version and clusterconfig)
        if "S3Update" in update:
            result["S3DestinationDescription"] = cast(S3DestinationDescription, update["S3Update"])
        result.pop("S3Update", None)
        return result


def convert_opensearch_config_to_desc(
    configuration: AmazonopensearchserviceDestinationConfiguration,
) -> AmazonopensearchserviceDestinationDescription:
    if configuration is not None:
        # Just take the whole typed dict and typecast it to our target type
        result = cast(AmazonopensearchserviceDestinationDescription, configuration)
        # Only specifically handle keys which are named differently or their values differ (version and clusterconfig)
        if "S3Configuration" in configuration:
            result["S3DestinationDescription"] = convert_s3_config_to_desc(
                configuration["S3Configuration"]
            )
        if "VpcConfiguration" in configuration:
            result["VpcConfigurationDescription"] = cast(
                VpcConfigurationDescription, configuration["VpcConfiguration"]
            )
        result.pop("S3Configuration", None)
        result.pop("VpcConfiguration", None)
        return result


def convert_opensearch_update_to_desc(
    update: AmazonopensearchserviceDestinationUpdate,
) -> AmazonopensearchserviceDestinationDescription:
    if update is not None:
        # Just take the whole typed dict and typecast it to our target type
        result = cast(AmazonopensearchserviceDestinationDescription, update)
        # Only specifically handle keys which are named differently or their values differ (version and clusterconfig)
        if "S3Update" in update:
            result["S3DestinationDescription"] = cast(S3DestinationDescription, update["S3Update"])
        result.pop("S3Update", None)
        return result


def convert_s3_config_to_desc(
    configuration: S3DestinationConfiguration,
) -> S3DestinationDescription:
    if configuration:
        return cast(S3DestinationDescription, configuration)


def convert_s3_update_to_desc(update: S3DestinationUpdate) -> S3DestinationDescription:
    if update:
        return cast(S3DestinationDescription, update)


def convert_extended_s3_config_to_desc(
    configuration: ExtendedS3DestinationConfiguration,
) -> ExtendedS3DestinationDescription:
    if configuration:
        result = cast(ExtendedS3DestinationDescription, configuration)
        if "S3BackupConfiguration" in configuration:
            result["S3BackupDescription"] = convert_s3_config_to_desc(
                configuration["S3BackupConfiguration"]
            )
        result.pop("S3BackupConfiguration", None)
        return result


def convert_extended_s3_update_to_desc(
    update: ExtendedS3DestinationUpdate,
) -> ExtendedS3DestinationDescription:
    if update:
        result = cast(ExtendedS3DestinationDescription, update)
        if "S3BackupUpdate" in update:
            result["S3BackupDescription"] = convert_s3_update_to_desc(update["S3BackupUpdate"])
        result.pop("S3BackupUpdate", None)
        return result


def convert_http_config_to_desc(
    configuration: HttpEndpointDestinationConfiguration,
) -> HttpEndpointDestinationDescription:
    if configuration:
        result = cast(HttpEndpointDestinationDescription, configuration)
        if "S3Configuration" in configuration:
            result["S3DestinationDescription"] = convert_s3_config_to_desc(
                configuration["S3Configuration"]
            )
        result.pop("S3Configuration", None)
        return result


def convert_http_update_to_desc(
    update: HttpEndpointDestinationUpdate,
) -> HttpEndpointDestinationDescription:
    if update:
        result = cast(HttpEndpointDestinationDescription, update)
        if "S3Update" in update:
            result["S3DestinationDescription"] = convert_s3_update_to_desc(update["S3Update"])
        result.pop("S3Update", None)
        return result


def convert_source_config_to_desc(
    configuration: KinesisStreamSourceConfiguration,
) -> SourceDescription:
    if configuration:
        result = cast(KinesisStreamSourceDescription, configuration)
        result["DeliveryStartTimestamp"] = datetime.now()
        return SourceDescription(KinesisStreamSourceDescription=result)


def convert_redshift_config_to_desc(
    configuration: RedshiftDestinationConfiguration,
) -> RedshiftDestinationDescription:
    if configuration is not None:
        result = cast(RedshiftDestinationDescription, configuration)
        result["S3DestinationDescription"] = convert_s3_config_to_desc(
            configuration["S3Configuration"]
        )
        result.pop("S3Configuration", None)
        return result
