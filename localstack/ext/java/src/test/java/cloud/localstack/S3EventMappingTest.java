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
        S3EventNotification.S3EventNotificationRecord record = s3Event.getRecords().iterator().next();

        Assert.assertTrue("eventVersion match", record.getEventVersion().contains("2.0"));
        Assert.assertTrue("eventTime match", record.getEventTime().toString().equals("2018-08-23T21:41:36.511Z"));
        Assert.assertTrue("sourceIPAddress match", record.getRequestParameters().getSourceIPAddress().equals("127.0.0.1"));

        Assert.assertTrue("s3 configurationId match", record.getS3().getConfigurationId().equals("testConfigRule"));
        Assert.assertTrue("s3 object versionId match", record.getS3().getObject().getVersionId().equals("096fKKXTRTtl3on89fVO.nfljtsv6qko"));
        Assert.assertTrue("s3 object eTag match", record.getS3().getObject().geteTag().equals("d41d8cd98f00b204e9800998ecf8427e"));
        Assert.assertTrue("s3 object key match", record.getS3().getObject().getKey().equals("key/file.txt"));
        Assert.assertTrue("s3 object sequencer match", record.getS3().getObject().getSequencer().equals("0055AED6DCD90281E5"));
        Assert.assertTrue("s3 object size match", record.getS3().getObject().getSizeAsLong().equals(1024L));
        Assert.assertTrue("s3 ownerEntity principalId match", record.getS3().getBucket().getOwnerIdentity().getPrincipalId().equals("A3NL1KOZZKExample"));
        Assert.assertTrue("s3 bucket name match", record.getS3().getBucket().getName().equals("bucket-name"));
        Assert.assertTrue("s3 bucket arn match", record.getS3().getBucket().getArn().equals("arn:aws:s3:::bucket-name"));
        Assert.assertTrue("s3 schemaVersion match", record.getS3().getS3SchemaVersion().equals("1.0"));

        Assert.assertTrue("responseElements x-amz-id-2 match", record.getResponseElements().getxAmzId2().equals("eftixk72aD6Ap51TnqcoF8eFidJG9Z/2"));
        Assert.assertTrue("responseElements x-amz-request-id match", record.getResponseElements().getxAmzRequestId().equals("8a0c0d15"));
        Assert.assertTrue("awsRegion", record.getAwsRegion().equals("us-east-1"));
        Assert.assertTrue("eventName", record.getEventName().equals("ObjectCreated:Put"));
        Assert.assertTrue("userIdentity principalId", record.getUserIdentity().getPrincipalId().equals("AIDAJDPLRKLG7UEXAMPLE"));
        Assert.assertTrue("eventSource match", record.getEventSource().equals("aws:s3"));

    }

}

