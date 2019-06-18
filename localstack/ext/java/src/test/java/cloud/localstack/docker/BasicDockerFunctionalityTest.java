package cloud.localstack.docker;

import cloud.localstack.DockerTestUtils;
import cloud.localstack.TestUtils;
import cloud.localstack.docker.annotation.LocalstackDockerProperties;
import com.amazon.sqs.javamessaging.SQSConnection;
import com.amazon.sqs.javamessaging.SQSConnectionFactory;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.model.AttributeDefinition;
import com.amazonaws.services.dynamodbv2.model.CreateTableRequest;
import com.amazonaws.services.dynamodbv2.model.KeySchemaElement;
import com.amazonaws.services.dynamodbv2.model.KeyType;
import com.amazonaws.services.dynamodbv2.model.ListTablesResult;
import com.amazonaws.services.dynamodbv2.model.ProvisionedThroughput;
import com.amazonaws.services.dynamodbv2.model.ScalarAttributeType;
import com.amazonaws.services.kinesis.AmazonKinesis;
import com.amazonaws.services.kinesis.model.CreateStreamRequest;
import com.amazonaws.services.kinesis.model.ListStreamsResult;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.services.s3.model.ObjectListing;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.model.CreateSecretRequest;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.model.CreateQueueRequest;
import com.amazonaws.services.sqs.model.ListQueuesResult;
import com.amazonaws.util.IOUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.runner.RunWith;

import javax.jms.MessageConsumer;
import javax.jms.MessageProducer;
import javax.jms.Queue;
import javax.jms.Session;
import javax.jms.TextMessage;
import java.io.File;
import java.io.FileOutputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RunWith(LocalstackDockerTestRunner.class)
@ExtendWith(LocalstackDockerExtension.class)
@LocalstackDockerProperties(randomizePorts = true)
public class BasicDockerFunctionalityTest {

    static {
        TestUtils.setEnv("AWS_CBOR_DISABLE", "1");
    }

    @org.junit.Test
    @org.junit.jupiter.api.Test
    public void testSecretsManager() throws Exception {
        AWSSecretsManager secretsManager = DockerTestUtils.getClientSecretsManager();

        CreateSecretRequest createSecretRequest = new CreateSecretRequest();
        createSecretRequest.setName("my-secret-name");
        createSecretRequest.setSecretString("this is a secret thing");
        secretsManager.createSecret(createSecretRequest);

        GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest().withSecretId("my-secret-name");
        String result = secretsManager.getSecretValue(getSecretValueRequest).getSecretString();
        Assertions.assertThat(result).isEqualTo("this is a secret thing");

    }

    @org.junit.Test
    @org.junit.jupiter.api.Test
    public void testKinesis() throws Exception {
        AmazonKinesis kinesis = DockerTestUtils.getClientKinesis();

        ListStreamsResult streamsResult = kinesis.listStreams();

        Assertions.assertThat(streamsResult.getStreamNames()).isEmpty();

        CreateStreamRequest createStreamRequest = new CreateStreamRequest()
                .withStreamName("test-stream")
                .withShardCount(2);

        kinesis.createStream(createStreamRequest);

        streamsResult = kinesis.listStreams();
        Assertions.assertThat(streamsResult.getStreamNames()).contains("test-stream");
    }

    @org.junit.Test
    @org.junit.jupiter.api.Test
    public void testDynamo() throws Exception {
        AmazonDynamoDB dynamoDB = DockerTestUtils.getClientDynamoDb();

        ListTablesResult tablesResult = dynamoDB.listTables();
        Assertions.assertThat(tablesResult.getTableNames()).hasSize(0);

        CreateTableRequest createTableRequest = new CreateTableRequest()
                .withTableName("test.table")
                .withKeySchema(new KeySchemaElement("identifier", KeyType.HASH))
                .withAttributeDefinitions(new AttributeDefinition("identifier", ScalarAttributeType.S))
                .withProvisionedThroughput(new ProvisionedThroughput(10L, 10L));
        dynamoDB.createTable(createTableRequest);

        tablesResult = dynamoDB.listTables();
        Assertions.assertThat(tablesResult.getTableNames()).contains("test.table");
    }

    @org.junit.Test
    @org.junit.jupiter.api.Test
    public void testS3() throws Exception {
        AmazonS3 client = DockerTestUtils.getClientS3();

        client.createBucket("test-bucket");
        List<Bucket> bucketList = client.listBuckets();

        Assertions.assertThat(bucketList).hasSize(1);

        File file = File.createTempFile("localstack", "s3");
        file.deleteOnExit();

        try (FileOutputStream stream = new FileOutputStream(file)) {
            String content = "HELLO WORLD!";
            stream.write(content.getBytes());
        }

        PutObjectRequest request = new PutObjectRequest("test-bucket", "testData", file);
        client.putObject(request);

        ObjectListing listing = client.listObjects("test-bucket");
        Assertions.assertThat(listing.getObjectSummaries()).hasSize(1);

        S3Object s3Object = client.getObject("test-bucket", "testData");
        String resultContent = IOUtils.toString(s3Object.getObjectContent());

        Assertions.assertThat(resultContent).isEqualTo("HELLO WORLD!");
    }

    @org.junit.Test
    @org.junit.jupiter.api.Test
    public void testSQS() throws Exception {
        AmazonSQS client = DockerTestUtils.getClientSQS();

        Map<String, String> attributeMap = new HashMap<>();
        attributeMap.put("DelaySeconds", "0");
        attributeMap.put("MaximumMessageSize", "262144");
        attributeMap.put("MessageRetentionPeriod", "1209600");
        attributeMap.put("ReceiveMessageWaitTimeSeconds", "20");
        attributeMap.put("VisibilityTimeout", "30");

        CreateQueueRequest createQueueRequest = new CreateQueueRequest("test-queue").withAttributes(attributeMap);
        client.createQueue(createQueueRequest);

        ListQueuesResult listQueuesResult = client.listQueues();
        Assertions.assertThat(listQueuesResult.getQueueUrls()).hasSize(1);

        SQSConnection connection = createSQSConnection();
        connection.start();
        Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);

        Queue queue = session.createQueue("test-queue");

        MessageProducer producer = session.createProducer(queue);
        TextMessage message = session.createTextMessage("Hello World!");
        producer.send(message);

        MessageConsumer consumer = session.createConsumer(queue);
        TextMessage received = (TextMessage) consumer.receive();
        Assertions.assertThat(received.getText()).isEqualTo("Hello World!");
    }

    private SQSConnection createSQSConnection() throws Exception {
        SQSConnectionFactory connectionFactory = SQSConnectionFactory.builder().withEndpoint(
                LocalstackDocker.INSTANCE.getEndpointSQS()).withAWSCredentialsProvider(
                new AWSStaticCredentialsProvider(TestUtils.TEST_CREDENTIALS)).build();
        return connectionFactory.createConnection();
    }
}
