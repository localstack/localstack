import base64
import json
import logging
import threading
import time
import uuid
from datetime import datetime
from typing import Dict, List

import requests

from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api import RequestContext
from localstack.aws.api.firehose import (
    AmazonopensearchserviceDestinationConfiguration,
    AmazonopensearchserviceDestinationUpdate,
    BooleanObject,
    CreateDeliveryStreamOutput,
    DeleteDeliveryStreamOutput,
    DeliveryStreamDescription,
    DeliveryStreamEncryptionConfigurationInput,
    DeliveryStreamName,
    DeliveryStreamStatus,
    DeliveryStreamType,
    DeliveryStreamVersionId,
    DescribeDeliveryStreamInputLimit,
    DescribeDeliveryStreamOutput,
    DestinationDescription,
    DestinationDescriptionList,
    DestinationId,
    ElasticsearchDestinationConfiguration,
    ElasticsearchDestinationUpdate,
    ElasticsearchS3BackupMode,
    ExtendedS3DestinationConfiguration,
    ExtendedS3DestinationUpdate,
    FirehoseApi,
    HttpEndpointDestinationConfiguration,
    HttpEndpointDestinationUpdate,
    InvalidArgumentException,
    KinesisStreamSourceConfiguration,
    ListDeliveryStreamsInputLimit,
    ListDeliveryStreamsOutput,
    ListTagsForDeliveryStreamInputLimit,
    ListTagsForDeliveryStreamOutput,
    ListTagsForDeliveryStreamOutputTagList,
    PutRecordBatchOutput,
    PutRecordBatchRequestEntryList,
    PutRecordBatchResponseEntry,
    PutRecordOutput,
    Record,
    RedshiftDestinationConfiguration,
    RedshiftDestinationUpdate,
    ResourceNotFoundException,
    S3DestinationConfiguration,
    S3DestinationDescription,
    S3DestinationUpdate,
    SplunkDestinationConfiguration,
    SplunkDestinationUpdate,
    TagDeliveryStreamInputTagList,
    TagDeliveryStreamOutput,
    TagKey,
    TagKeyList,
    UntagDeliveryStreamOutput,
    UpdateDestinationOutput,
)
from localstack.services.firehose.mappers import (
    convert_es_config_to_desc,
    convert_es_update_to_desc,
    convert_extended_s3_config_to_desc,
    convert_extended_s3_update_to_desc,
    convert_http_config_to_desc,
    convert_http_update_to_desc,
    convert_opensearch_config_to_desc,
    convert_opensearch_update_to_desc,
    convert_s3_config_to_desc,
    convert_s3_update_to_desc,
    convert_source_config_to_desc,
)
from localstack.services.firehose.models import FirehoseStore, firehose_stores
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_stack import (
    connect_to_resource,
    extract_region_from_arn,
    firehose_stream_arn,
    get_search_db_connection,
    s3_bucket_name,
)
from localstack.utils.common import (
    TIMESTAMP_FORMAT_MICROS,
    first_char_to_lower,
    keys_to_lower,
    now_utc,
    short_uid,
    timestamp,
    to_bytes,
    to_str,
    truncate,
)
from localstack.utils.kinesis import kinesis_connector
from localstack.utils.run import run_for_max_seconds

LOG = logging.getLogger(__name__)

# global sequence number counter for Firehose records (these are very large long values in AWS)
SEQUENCE_NUMBER = 49546986683135544286507457936321625675700192471156785154
SEQUENCE_NUMBER_MUTEX = threading.RLock()


def next_sequence_number() -> int:
    """Increase and return the next global sequence number."""
    global SEQUENCE_NUMBER
    with SEQUENCE_NUMBER_MUTEX:
        SEQUENCE_NUMBER += 1
        return SEQUENCE_NUMBER


def _get_description_or_raise_not_found(
    context, delivery_stream_name: str
) -> DeliveryStreamDescription:
    store = FirehoseProvider.get_store()
    delivery_stream_description = store.delivery_streams.get(delivery_stream_name)
    if not delivery_stream_description:
        raise ResourceNotFoundException(
            f"Firehose {delivery_stream_name} under account {context.account_id} " f"not found."
        )
    return delivery_stream_description


class FirehoseProvider(FirehoseApi):
    @staticmethod
    def get_store() -> FirehoseStore:
        return firehose_stores[get_aws_account_id()][aws_stack.get_region()]

    def create_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        delivery_stream_type: DeliveryStreamType = DeliveryStreamType.DirectPut,
        kinesis_stream_source_configuration: KinesisStreamSourceConfiguration = None,
        delivery_stream_encryption_configuration_input: DeliveryStreamEncryptionConfigurationInput = None,
        s3_destination_configuration: S3DestinationConfiguration = None,
        extended_s3_destination_configuration: ExtendedS3DestinationConfiguration = None,
        redshift_destination_configuration: RedshiftDestinationConfiguration = None,
        elasticsearch_destination_configuration: ElasticsearchDestinationConfiguration = None,
        amazonopensearchservice_destination_configuration: AmazonopensearchserviceDestinationConfiguration = None,
        splunk_destination_configuration: SplunkDestinationConfiguration = None,
        http_endpoint_destination_configuration: HttpEndpointDestinationConfiguration = None,
        tags: TagDeliveryStreamInputTagList = None,
    ) -> CreateDeliveryStreamOutput:
        store = self.get_store()

        destinations: DestinationDescriptionList = []
        if elasticsearch_destination_configuration:
            destinations.append(
                DestinationDescription(
                    DestinationId=short_uid(),
                    ElasticsearchDestinationDescription=convert_es_config_to_desc(
                        elasticsearch_destination_configuration
                    ),
                )
            )
        if amazonopensearchservice_destination_configuration:
            destinations.append(
                DestinationDescription(
                    DestinationId=short_uid(),
                    AmazonopensearchserviceDestinationDescription=convert_opensearch_config_to_desc(
                        amazonopensearchservice_destination_configuration
                    ),
                )
            )
        if s3_destination_configuration or extended_s3_destination_configuration:
            destinations.append(
                DestinationDescription(
                    DestinationId=short_uid(),
                    S3DestinationDescription=convert_s3_config_to_desc(
                        s3_destination_configuration
                    ),
                    ExtendedS3DestinationDescription=convert_extended_s3_config_to_desc(
                        extended_s3_destination_configuration
                    ),
                )
            )
        if http_endpoint_destination_configuration:
            destinations.append(
                DestinationDescription(
                    DestinationId=short_uid(),
                    HttpEndpointDestinationDescription=convert_http_config_to_desc(
                        http_endpoint_destination_configuration
                    ),
                )
            )
        if splunk_destination_configuration:
            LOG.warning(
                "Delivery stream contains a splunk destination (which is currently not supported)."
            )
        if redshift_destination_configuration:
            LOG.warning(
                "Delivery stream contains a redshift destination (which is currently not supported)."
            )

        stream = DeliveryStreamDescription(
            DeliveryStreamName=delivery_stream_name,
            DeliveryStreamARN=firehose_stream_arn(
                stream_name=delivery_stream_name,
                account_id=context.account_id,
                region_name=context.region,
            ),
            DeliveryStreamStatus=DeliveryStreamStatus.ACTIVE,
            DeliveryStreamType=delivery_stream_type,
            HasMoreDestinations=False,
            VersionId="1",
            CreateTimestamp=datetime.now(),
            Destinations=destinations,
            Source=convert_source_config_to_desc(kinesis_stream_source_configuration),
        )
        store.TAGS.tag_resource(stream["DeliveryStreamARN"], tags)
        store.delivery_streams[delivery_stream_name] = stream

        if delivery_stream_type == DeliveryStreamType.KinesisStreamAsSource:
            if not kinesis_stream_source_configuration:
                raise InvalidArgumentException("Missing delivery stream configuration")
            kinesis_stream_arn = kinesis_stream_source_configuration["KinesisStreamARN"]
            kinesis_stream_name = kinesis_stream_arn.split(":stream/")[1]

            def _startup():
                stream["DeliveryStreamStatus"] = DeliveryStreamStatus.CREATING
                try:
                    process = kinesis_connector.listen_to_kinesis(
                        stream_name=kinesis_stream_name,
                        fh_d_stream=delivery_stream_name,
                        listener_func=self._process_records,
                        wait_until_started=True,
                        ddb_lease_table_suffix="-firehose",
                    )
                    store.kinesis_listeners[delivery_stream_name] = process
                    stream["DeliveryStreamStatus"] = DeliveryStreamStatus.ACTIVE
                except Exception as e:
                    LOG.warning(
                        "Unable to create Firehose delivery stream %s: %s", delivery_stream_name, e
                    )
                    stream["DeliveryStreamStatus"] = DeliveryStreamStatus.CREATING_FAILED

            run_for_max_seconds(25, _startup)
        return CreateDeliveryStreamOutput(DeliveryStreamARN=stream["DeliveryStreamARN"])

    def delete_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        allow_force_delete: BooleanObject = None,
    ) -> DeleteDeliveryStreamOutput:
        store = self.get_store()
        delivery_stream_description = store.delivery_streams.pop(delivery_stream_name, {})
        if not delivery_stream_description:
            raise ResourceNotFoundException(
                f"Firehose {delivery_stream_name} under account {context.account_id} " f"not found."
            )
        kinesis_process = store.kinesis_listeners.pop(delivery_stream_name, None)
        if kinesis_process:
            LOG.debug("Stopping kinesis listener for %s", delivery_stream_name)
            kinesis_process.stop()

        return DeleteDeliveryStreamOutput()

    def describe_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        limit: DescribeDeliveryStreamInputLimit = None,
        exclusive_start_destination_id: DestinationId = None,
    ) -> DescribeDeliveryStreamOutput:
        delivery_stream_description = _get_description_or_raise_not_found(
            context, delivery_stream_name
        )
        return DescribeDeliveryStreamOutput(DeliveryStreamDescription=delivery_stream_description)

    def list_delivery_streams(
        self,
        context: RequestContext,
        limit: ListDeliveryStreamsInputLimit = None,
        delivery_stream_type: DeliveryStreamType = None,
        exclusive_start_delivery_stream_name: DeliveryStreamName = None,
    ) -> ListDeliveryStreamsOutput:
        store = self.get_store()
        delivery_stream_names = []
        for name, stream in store.delivery_streams.items():
            delivery_stream_names.append(stream["DeliveryStreamName"])
        return ListDeliveryStreamsOutput(
            DeliveryStreamNames=delivery_stream_names, HasMoreDeliveryStreams=False
        )

    def put_record(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        record: Record,
    ) -> PutRecordOutput:
        record = self._reencode_record(record)
        return self._put_record(delivery_stream_name, record)

    def put_record_batch(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        records: PutRecordBatchRequestEntryList,
    ) -> PutRecordBatchOutput:
        records = self._reencode_records(records)
        return PutRecordBatchOutput(
            FailedPutCount=0, RequestResponses=self._put_records(delivery_stream_name, records)
        )

    def tag_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        tags: TagDeliveryStreamInputTagList,
    ) -> TagDeliveryStreamOutput:
        store = self.get_store()
        delivery_stream_description = _get_description_or_raise_not_found(
            context, delivery_stream_name
        )
        store.TAGS.tag_resource(delivery_stream_description["DeliveryStreamARN"], tags)
        return ListTagsForDeliveryStreamOutput()

    def list_tags_for_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        exclusive_start_tag_key: TagKey = None,
        limit: ListTagsForDeliveryStreamInputLimit = None,
    ) -> ListTagsForDeliveryStreamOutput:
        store = self.get_store()
        delivery_stream_description = _get_description_or_raise_not_found(
            context, delivery_stream_name
        )
        # The tagging service returns a dictionary with the given root name
        tags = store.TAGS.list_tags_for_resource(
            arn=delivery_stream_description["DeliveryStreamARN"], root_name="root"
        )
        # Extract the actual list of tags for the typed response
        tag_list: ListTagsForDeliveryStreamOutputTagList = tags["root"]
        return ListTagsForDeliveryStreamOutput(Tags=tag_list, HasMoreTags=False)

    def untag_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        tag_keys: TagKeyList,
    ) -> UntagDeliveryStreamOutput:
        store = self.get_store()
        delivery_stream_description = _get_description_or_raise_not_found(
            context, delivery_stream_name
        )
        # The tagging service returns a dictionary with the given root name
        store.TAGS.untag_resource(
            arn=delivery_stream_description["DeliveryStreamARN"], tag_names=tag_keys
        )
        return UntagDeliveryStreamOutput()

    def update_destination(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        current_delivery_stream_version_id: DeliveryStreamVersionId,
        destination_id: DestinationId,
        s3_destination_update: S3DestinationUpdate = None,
        extended_s3_destination_update: ExtendedS3DestinationUpdate = None,
        redshift_destination_update: RedshiftDestinationUpdate = None,
        elasticsearch_destination_update: ElasticsearchDestinationUpdate = None,
        amazonopensearchservice_destination_update: AmazonopensearchserviceDestinationUpdate = None,
        splunk_destination_update: SplunkDestinationUpdate = None,
        http_endpoint_destination_update: HttpEndpointDestinationUpdate = None,
    ) -> UpdateDestinationOutput:
        delivery_stream_description = _get_description_or_raise_not_found(
            context, delivery_stream_name
        )
        destinations = delivery_stream_description["Destinations"]
        try:
            destination = next(filter(lambda d: d["DestinationId"] == destination_id, destinations))
        except StopIteration:
            destination = DestinationDescription(DestinationId=destination_id)
            delivery_stream_description["Destinations"].append(destination)

        if elasticsearch_destination_update:
            destination["ElasticsearchDestinationDescription"] = convert_es_update_to_desc(
                elasticsearch_destination_update
            )

        if amazonopensearchservice_destination_update:
            destination[
                "AmazonopensearchserviceDestinationDescription"
            ] = convert_opensearch_update_to_desc(amazonopensearchservice_destination_update)

        if s3_destination_update:
            destination["S3DestinationDescription"] = convert_s3_update_to_desc(
                s3_destination_update
            )

        if extended_s3_destination_update:
            destination["ExtendedS3DestinationDescription"] = convert_extended_s3_update_to_desc(
                extended_s3_destination_update
            )

        if http_endpoint_destination_update:
            destination["HttpEndpointDestinationDescription"] = convert_http_update_to_desc(
                http_endpoint_destination_update
            )

        return UpdateDestinationOutput()

    def _reencode_record(self, record: Record) -> Record:
        """
        The ASF decodes the record's data automatically. But most of the service integrations (kinesis, lambda, http)
        are working with the base64 encoded data.
        """
        if "Data" in record:
            record["Data"] = base64.b64encode(record["Data"])
        return record

    def _reencode_records(self, records: List[Record]) -> List[Record]:
        return [self._reencode_record(r) for r in records]

    def _process_records(self, records: List[Record], shard_id: str, fh_d_stream: str):
        """Process the given records from the underlying Kinesis stream"""
        return self._put_records(fh_d_stream, records)

    def _put_record(self, delivery_stream_name: str, record: Record) -> PutRecordOutput:
        """Put a record to the firehose stream from a PutRecord API call"""
        result = self._put_records(delivery_stream_name, [record])
        return PutRecordOutput(RecordId=result[0]["RecordId"])

    def _put_records(
        self, delivery_stream_name: str, unprocessed_records: List[Record]
    ) -> List[PutRecordBatchResponseEntry]:
        """Put a list of records to the firehose stream - either directly from a PutRecord API call, or
        received from an underlying Kinesis stream (if 'KinesisStreamAsSource' is configured)"""
        store = self.get_store()
        delivery_stream_description = store.delivery_streams.get(delivery_stream_name)
        if not delivery_stream_description:
            raise ResourceNotFoundException(
                f"Firehose {delivery_stream_name} under account {get_aws_account_id()} not found."
            )

        # preprocess records, add any missing attributes
        self._add_missing_record_attributes(unprocessed_records)

        for destination in delivery_stream_description.get("Destinations", []):

            # apply processing steps to incoming items
            proc_config = {}
            for child in destination.values():
                proc_config = (
                    isinstance(child, dict) and child.get("ProcessingConfiguration") or proc_config
                )
            records = list(unprocessed_records)
            if proc_config.get("Enabled") is not False:
                for processor in proc_config.get("Processors", []):
                    # TODO: run processors asynchronously, to avoid request timeouts on PutRecord API calls
                    records = self._preprocess_records(processor, records)

            if "ElasticsearchDestinationDescription" in destination:
                self._put_to_search_db(
                    "ElasticSearch",
                    destination["ElasticsearchDestinationDescription"],
                    delivery_stream_name,
                    records,
                    unprocessed_records,
                )
            if "AmazonopensearchserviceDestinationDescription" in destination:
                self._put_to_search_db(
                    "OpenSearch",
                    destination["AmazonopensearchserviceDestinationDescription"],
                    delivery_stream_name,
                    records,
                    unprocessed_records,
                )
            if "S3DestinationDescription" in destination:
                s3_dest_desc = (
                    destination["S3DestinationDescription"]
                    or destination["ExtendedS3DestinationDescription"]
                )
                self._put_records_to_s3_bucket(delivery_stream_name, records, s3_dest_desc)
            if "HttpEndpointDestinationDescription" in destination:
                http_dest = destination["HttpEndpointDestinationDescription"]
                end_point = http_dest["EndpointConfiguration"]
                url = end_point["Url"]
                record_to_send = {
                    "requestId": str(uuid.uuid4()),
                    "timestamp": (int(time.time())),
                    "records": [],
                }
                for record in records:
                    data = record.get("Data") or record.get("data")
                    record_to_send["records"].append({"data": to_str(data)})
                headers = {
                    "Content-Type": "application/json",
                }
                try:
                    requests.post(url, json=record_to_send, headers=headers)
                except Exception as e:
                    LOG.exception(f"Unable to put Firehose records to HTTP endpoint {url}.")
                    raise e
        return [
            PutRecordBatchResponseEntry(RecordId=str(uuid.uuid4())) for _ in unprocessed_records
        ]

    def _put_to_search_db(
        self, db_flavor, db_description, delivery_stream_name, records, unprocessed_records
    ):
        """
        sends Firehose records to an ElasticSearch or Opensearch database
        """
        search_db_index = db_description["IndexName"]
        search_db_type = db_description.get("TypeName")
        region = aws_stack.get_region()
        domain_arn = db_description.get("DomainARN")
        cluster_endpoint = db_description.get("ClusterEndpoint")
        if cluster_endpoint is None:
            cluster_endpoint = aws_stack.get_opensearch_endpoint(domain_arn)

        db_connection = get_search_db_connection(cluster_endpoint, region)
        if db_description.get("S3BackupMode") == ElasticsearchS3BackupMode.AllDocuments:
            s3_dest_desc = db_description.get("S3DestinationDescription")
            if s3_dest_desc:
                try:
                    self._put_records_to_s3_bucket(
                        stream_name=delivery_stream_name,
                        records=unprocessed_records,
                        s3_destination_description=s3_dest_desc,
                    )
                except Exception as e:
                    LOG.warning("Unable to backup unprocessed records to S3. Error: %s", e)
            else:
                LOG.warning("Passed S3BackupMode without S3Configuration. Cannot backup...")
        elif db_description.get("S3BackupMode") == ElasticsearchS3BackupMode.FailedDocumentsOnly:
            # TODO support FailedDocumentsOnly as well
            LOG.warning("S3BackupMode FailedDocumentsOnly is set but currently not supported.")
        for record in records:
            obj_id = uuid.uuid4()

            data = "{}"
            # DirectPut
            if "Data" in record:
                data = base64.b64decode(record["Data"])
            # KinesisAsSource
            elif "data" in record:
                data = base64.b64decode(record["data"])

            try:
                body = json.loads(data)
            except Exception as e:
                LOG.warning(f"{db_flavor} only allows json input data!")
                raise e

            LOG.debug(
                "Publishing to {} destination. Data: {}".format(
                    db_flavor, truncate(data, max_length=300)
                )
            )
            try:
                db_connection.create(
                    index=search_db_index, doc_type=search_db_type, id=obj_id, body=body
                )
            except Exception as e:
                LOG.exception(f"Unable to put record to stream {delivery_stream_name}.")
                raise e

    def _add_missing_record_attributes(self, records: List[Dict]) -> None:
        def _get_entry(obj, key):
            return obj.get(key) or obj.get(first_char_to_lower(key))

        for record in records:
            if not _get_entry(record, "ApproximateArrivalTimestamp"):
                record["ApproximateArrivalTimestamp"] = int(now_utc(millis=True))
            if not _get_entry(record, "KinesisRecordMetadata"):
                record["kinesisRecordMetadata"] = {
                    "shardId": "shardId-000000000000",
                    # not really documented what AWS is using internally - simply using a random UUID here
                    "partitionKey": str(uuid.uuid4()),
                    "approximateArrivalTimestamp": timestamp(
                        float(_get_entry(record, "ApproximateArrivalTimestamp")) / 1000,
                        format=TIMESTAMP_FORMAT_MICROS,
                    ),
                    "sequenceNumber": next_sequence_number(),
                    "subsequenceNumber": "",
                }

    def _preprocess_records(self, processor: Dict, records: List[Record]) -> List[Dict]:
        """Preprocess the list of records by calling the given processor (e.g., Lamnda function)."""
        proc_type = processor.get("Type")
        parameters = processor.get("Parameters", [])
        parameters = {p["ParameterName"]: p["ParameterValue"] for p in parameters}
        if proc_type == "Lambda":
            lambda_arn = parameters.get("LambdaArn")
            # TODO: add support for other parameters, e.g., NumberOfRetries, BufferSizeInMBs, BufferIntervalInSeconds, ...
            records = keys_to_lower(records)
            # Convert the record data to string (for json serialization)
            for record in records:
                if "data" in record:
                    record["data"] = to_str(record["data"])
                if "Data" in record:
                    record["Data"] = to_str(record["Data"])
            event = {"records": records}
            event = to_bytes(json.dumps(event))
            client = aws_stack.connect_to_service(
                "lambda", region_name=extract_region_from_arn(lambda_arn)
            )
            response = client.invoke(FunctionName=lambda_arn, Payload=event)
            result = response.get("Payload").read()
            result = json.loads(to_str(result))
            records = result.get("records", []) if result else []
        else:
            LOG.warning("Unsupported Firehose processor type '%s'", proc_type)
        return records

    def _put_records_to_s3_bucket(
        self,
        stream_name: str,
        records: List[Dict],
        s3_destination_description: S3DestinationDescription,
    ):
        bucket = s3_bucket_name(s3_destination_description["BucketARN"])
        prefix = s3_destination_description.get("Prefix", "")

        s3 = connect_to_resource("s3")
        batched_data = b"".join([base64.b64decode(r.get("Data") or r.get("data")) for r in records])

        obj_path = self._get_s3_object_path(stream_name, prefix)
        try:
            LOG.debug("Publishing to S3 destination: %s. Data: %s", bucket, batched_data)
            s3.Object(bucket, obj_path).put(Body=batched_data)
        except Exception as e:
            LOG.exception(f"Unable to put records {records} to s3 bucket.")
            raise e

    def _get_s3_object_path(self, stream_name, prefix):
        # See https://aws.amazon.com/kinesis/data-firehose/faqs/#Data_delivery
        # Path prefix pattern: myApp/YYYY/MM/DD/HH/
        # Object name pattern: DeliveryStreamName-DeliveryStreamVersion-YYYY-MM-DD-HH-MM-SS-RandomString
        if not prefix.endswith("/") and prefix != "":
            prefix = prefix + "/"
        pattern = "{pre}%Y/%m/%d/%H/{name}-%Y-%m-%d-%H-%M-%S-{rand}"
        path = pattern.format(pre=prefix, name=stream_name, rand=str(uuid.uuid4()))
        path = timestamp(format=path)
        return path
