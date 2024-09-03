package kinesis;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kinesis.KinesisClient;
import software.amazon.awssdk.services.kinesis.model.*;

import java.net.URI;
import java.nio.charset.Charset;
import java.time.Instant;
import java.util.*;


public class Handler implements RequestHandler<Map<String, String>, String> {

    public String handleRequest(Map<String, String> event, Context context) {
        // extract the StreamARN from the event
        String streamArn = event.get("StreamARN");
        System.out.print("Stream ARN = " + streamArn);

        // get the first shard
        DescribeStreamResponse streamDescription = this.getKinesisClient().describeStream(DescribeStreamRequest.builder().streamARN(streamArn).build());
        Instant streamCreationTimestamp = streamDescription.streamDescription().streamCreationTimestamp();
        Shard shard = streamDescription.streamDescription().shards().get(0);;
        System.out.println("Shard ID = " + shard.shardId());

        // create the shardIterator starting now
        GetShardIteratorResponse shardIterator = this.getKinesisClient().getShardIterator(GetShardIteratorRequest.builder().streamARN(streamArn).shardId(shard.shardId()).shardIteratorType(ShardIteratorType.AT_TIMESTAMP).timestamp(Instant.now()).build());
        System.out.println("Stream Creation Timestamp = " + streamCreationTimestamp);

        // put a record
        SdkBytes testData = SdkBytes.fromString("test-string", Charset.defaultCharset());
        this.getKinesisClient().putRecord(PutRecordRequest.builder().streamARN(streamArn).partitionKey("test-partition-key").data(testData).build());

        // get the record again
        GetRecordsResponse records = this.getKinesisClient().getRecords(GetRecordsRequest.builder().streamARN(streamArn).shardIterator(shardIterator.shardIterator()).build());

        // expect the record has been returned
        assert records.hasRecords();
        assert records.records().get(0).data() == testData;

        return "ok";
    }

    private KinesisClient getKinesisClient() {
        String endpointUrl = System.getenv("AWS_ENDPOINT_URL");
        if (endpointUrl != null) {
            // Choosing a specific endpoint
            // https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/region-selection.html
            return KinesisClient.builder()
                    .endpointOverride(URI.create(endpointUrl)).build();
        }
        return KinesisClient.builder().build();
    }
}
