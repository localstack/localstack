package cloud.localstack.docker;

import cloud.localstack.DockerTestUtils;
import cloud.localstack.TestUtils;
import cloud.localstack.docker.annotation.LocalstackDockerProperties;
import com.amazon.sqs.javamessaging.SQSConnection;
import com.amazon.sqs.javamessaging.SQSConnectionFactory;
import com.amazonaws.SdkClientException;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.model.*;
import com.amazonaws.services.kinesis.AmazonKinesis;
import com.amazonaws.services.kinesis.model.CreateStreamRequest;
import com.amazonaws.services.kinesis.model.ListStreamsResult;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.services.s3.model.ObjectListing;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.model.CreateQueueRequest;
import com.amazonaws.services.sqs.model.ListQueuesResult;
import com.amazonaws.util.IOUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;

import javax.jms.*;
import java.io.File;
import java.io.FileOutputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

@RunWith(LocalstackDockerTestRunner.class)
@LocalstackDockerProperties(randomizePorts = true, services = "sqs")
public class DockerOnlySQSFunctionalityTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    static {
        TestUtils.setEnv("AWS_CBOR_DISABLE", "1");
    }

    @Test
    public void testKinesisNotRunning() {
        thrown.expect(SdkClientException.class);
        AmazonKinesis kinesis = DockerTestUtils.getClientKinesis();
        kinesis.listStreams();
    }


    @Test
    public void testDynamoNotRunning() {
        thrown.expect(SdkClientException.class);

        AmazonDynamoDB dynamoDB = DockerTestUtils.getClientDynamoDb();
        ListTablesResult tablesResult = dynamoDB.listTables();
    }

    @Test
    public void testS3NotRunning() {
        thrown.expect(SdkClientException.class);
        AmazonS3 client = DockerTestUtils.getClientS3();
        client.createBucket("test-bucket");
    }

    @Test
    public void testSQSRunning() throws Exception {
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
        assertThat(listQueuesResult.getQueueUrls().size(), is(1));

        SQSConnection connection = createSQSConnection();
        connection.start();
        Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);

        Queue queue = session.createQueue("test-queue");

        MessageProducer producer = session.createProducer(queue);
        TextMessage message = session.createTextMessage("Hello World!");
        producer.send(message);

        MessageConsumer consumer = session.createConsumer(queue);
        TextMessage received = (TextMessage) consumer.receive();
        assertThat(received.getText(), is ("Hello World!"));
    }


    private SQSConnection createSQSConnection() throws Exception {
        SQSConnectionFactory connectionFactory = SQSConnectionFactory.builder().withEndpoint(
            LocalstackDockerTestRunner.getLocalstackDocker().getEndpointSQS()).withAWSCredentialsProvider(
                new AWSStaticCredentialsProvider(TestUtils.TEST_CREDENTIALS)).build();
        return  connectionFactory.createConnection();
    }
}
