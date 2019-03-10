package cloud.localstack;

import cloud.localstack.lambda.S3EventParser;
import com.amazonaws.services.lambda.runtime.events.S3Event;
import com.amazonaws.services.s3.event.S3EventNotification;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static cloud.localstack.LambdaExecutor.get;
import static cloud.localstack.LambdaExecutor.readFile;

public class S3EventMappingTest {

    static String fileName = "src/test/resources/S3EventLambda.json";

    @Test
    public void testParseS3Event() throws Exception {
        String fileContent = readFile(fileName);

        ObjectMapper reader = new ObjectMapper();
        @SuppressWarnings("deprecation")
        Map<String,Object> map = reader.reader(Map.class).readValue(fileContent);
        List<Map<String,Object>> records = (List<Map<String, Object>>) get(map, "Records");

        S3Event s3Event = S3EventParser.parse(records);
        S3EventNotification.S3EventNotificationRecord record = s3Event.getRecords().get(0);

        // grab expected results
        Map<String, Object> expectedResultRecord = records.get(0);
        Map<String, Object> expS3 = (Map<String, Object>) expectedResultRecord.get("s3");
        Map<String, Object> expBk = ((Map<String, Object>) get(expS3, "bucket"));
        Map<String, Object> expOi = (Map<String, Object>) get(expBk,  "ownerIdentity");

        // verify parsed event info
        Assert.assertEquals("eventVersion match", expectedResultRecord.get("eventVersion"), record.getEventVersion());
        Assert.assertEquals("eventTime match", expectedResultRecord.get("eventTime"), record.getEventTime().toString());
        Assert.assertEquals("sourceIPAddress match", get((Map<String, Object>)expectedResultRecord.get("requestParameters"), "sourceIPAddress"), record.getRequestParameters().getSourceIPAddress());

        Assert.assertEquals("s3 configurationId match", expS3.get("configurationId"), record.getS3().getConfigurationId());
        Assert.assertEquals("s3 object versionId match", get((Map<String, Object>) expS3.get("object"),"versionId"), record.getS3().getObject().getVersionId());
        Assert.assertEquals("s3 object eTag match", get((Map<String, Object>) expS3.get("object"),"eTag"), record.getS3().getObject().geteTag());
        Assert.assertEquals("s3 object key match", get((Map<String, Object>) expS3.get("object"),"key"), record.getS3().getObject().getKey());
        Assert.assertEquals("s3 object sequencer match", get((Map<String, Object>) expS3.get("object"),"sequencer"), record.getS3().getObject().getSequencer());
        Assert.assertEquals("s3 object size match", new Long(get((Map<String, Object>) expS3.get("object"),"size").toString()), record.getS3().getObject().getSizeAsLong());
        Assert.assertEquals("s3 ownerEntity principalId match", expOi.get("principalId"), record.getS3().getBucket().getOwnerIdentity().getPrincipalId());
        Assert.assertEquals("s3 bucket name match", expBk.get("name"), record.getS3().getBucket().getName() );
        Assert.assertEquals("s3 schemaVersion match", expS3.get("s3SchemaVersion"), record.getS3().getS3SchemaVersion() );

        Assert.assertEquals("responseElements x-amz-id-2 match", get((Map<String, Object>) expectedResultRecord.get("responseElements"),"x-amz-id-2"), record.getResponseElements().getxAmzId2());
        Assert.assertEquals("responseElements x-amz-request-id match", get((Map<String, Object>) expectedResultRecord.get("responseElements"),"x-amz-request-id"), record.getResponseElements().getxAmzRequestId());
        Assert.assertEquals("awsRegion match", expectedResultRecord.get("awsRegion"), record.getAwsRegion());
        Assert.assertEquals("eventName match", expectedResultRecord.get("eventName"), record.getEventName());
        Assert.assertEquals("userIdentity principalId", get((Map<String, Object>) expectedResultRecord.get("userIdentity"),"principalId"), record.getUserIdentity().getPrincipalId());
        Assert.assertEquals("eventSource match", expectedResultRecord.get("eventSource"), record.getEventSource());

    }

}

