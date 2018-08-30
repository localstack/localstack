package cloud.localstack.lambda;
import static cloud.localstack.LambdaExecutor.get;
import com.amazonaws.services.lambda.runtime.events.S3Event;
import com.amazonaws.services.s3.event.S3EventNotification;
import org.joda.time.DateTime;

import java.util.*;


public class S3EventParser {

    public static S3Event parse(List<Map<String, Object>> records) {

        // parse out items to construct the S3EventNotification
        Map<String, Object> record = records.get(0);
        Map<String, Object> rp = (Map<String, Object>) get(record, "requestParameters");
        String sip = (String) get(rp,"sourceIPAddress");

        Map<String, Object> re = (Map<String, Object>) get(record, "responseElements");
        String xAmzld2 = (String) get(re,"x-amz-id-2");
        String xAmzRequestId = (String) get(re,"x-amz-request-id");

        Map<String, Object> s3 = (Map<String, Object>) get(record, "s3");
        Map<String, Object> bk = (Map<String, Object>) get(s3, "bucket");
        Map<String, Object> oi = (Map<String, Object>) get(bk,  "ownerIdentity");
        String bucketPrincipalId = (String) get(oi, "principalId");
        String bucketName = (String) get(bk,"name");
        String arn = (String) get(bk,"arn");
        String s3SchemaVersion = (String) get(s3, "s3SchemaVersion");

        Map<String, Object> obj = (Map<String, Object>) get(s3, "object");
        String key = (String) get(obj,"key");
        Long size = ((Number) get(obj,"size")).longValue();
        String eTag = (String) get(obj,"eTag");
        String versionId = (String) get(obj,"versionId");
        String sequencer = (String) get(obj,"sequencer");
        String configurationId = (String) get(s3,"configurationId");

        String awsRegion = (String) get(record, "awsRegion");
        String eventName = (String) get(record, "eventName");
        String eventSource = (String) get(record, "eventSource");
        String eventTime = (String) get(record, "eventTime");
        String eventVersion = (String) get(record, "eventVersion");

        Map<String, Object> ui = (Map<String, Object>) get(record, "userIdentity");
        String principalId = (String) get(ui,"principalId");

        // build up a S3Event to be passed to the Lambda
        List s3Records = new LinkedList<>();

        // bucket and S3ObjectEntity needed for S3Entity constructor
        S3EventNotification.UserIdentityEntity bucketUserIdentityEntity = new S3EventNotification.UserIdentityEntity(bucketPrincipalId);
        S3EventNotification.S3BucketEntity bucket = new S3EventNotification.S3BucketEntity(
                bucketName,
                bucketUserIdentityEntity,
                arn);

        S3EventNotification.S3ObjectEntity s3ObjectEntity = new S3EventNotification.S3ObjectEntity(
                key,
                size,
                eTag,
                versionId,
                sequencer);

        // S3Entity
        S3EventNotification.S3Entity s3Entity = new S3EventNotification.S3Entity(
                configurationId,
                bucket,
                s3ObjectEntity,
                s3SchemaVersion);

        // build S3EventNotificationRecord
        S3EventNotification.RequestParametersEntity requestParameters = new S3EventNotification.RequestParametersEntity(sip);
        S3EventNotification.ResponseElementsEntity responseEntity = new S3EventNotification.ResponseElementsEntity(xAmzld2, xAmzRequestId);
        S3EventNotification.UserIdentityEntity eventNotifyUserIdentityEntity = new S3EventNotification.UserIdentityEntity(principalId);
        S3EventNotification.S3EventNotificationRecord s3record = new S3EventNotification.S3EventNotificationRecord(
                awsRegion,
                eventName,
                eventSource,
                eventTime,
                eventVersion,
                requestParameters,
                responseEntity,
                s3Entity,
                eventNotifyUserIdentityEntity);

        // add the record to records list
        s3Records.add(0, s3record);

        // finally hydrate S3Event
        return new S3Event(s3Records);

    }

}
