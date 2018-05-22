package cloud.localstack.docker;

import cloud.localstack.DockerTestUtils;
import cloud.localstack.TestUtils;
import cloud.localstack.docker.LocalstackDocker;
import cloud.localstack.docker.LocalstackDockerExtension;
import cloud.localstack.docker.LocalstackDockerTestRunner;
import cloud.localstack.docker.annotation.LocalstackDockerProperties;
import com.amazon.sqs.javamessaging.SQSConnection;
import com.amazon.sqs.javamessaging.SQSConnectionFactory;
import com.amazonaws.SdkClientException;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.model.CreateQueueRequest;
import com.amazonaws.services.sqs.model.ListQueuesResult;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.runner.RunWith;

import javax.jms.MessageConsumer;
import javax.jms.MessageProducer;
import javax.jms.Queue;
import javax.jms.Session;
import javax.jms.TextMessage;
import java.util.HashMap;
import java.util.Map;

@RunWith(LocalstackDockerTestRunner.class)
@ExtendWith(LocalstackDockerExtension.class)
@LocalstackDockerProperties(randomizePorts = true, services = "sqs")
public class DockerOnlySQSFunctionalityTest {

    static {
        TestUtils.setEnv("AWS_CBOR_DISABLE", "1");
    }

    @org.junit.Test
    @org.junit.jupiter.api.Test
    public void testKinesisNotRunning() {
        final Throwable throwable = Assertions.catchThrowable(() -> DockerTestUtils.getClientKinesis().listStreams());

        Assertions.assertThat(throwable).isInstanceOf(SdkClientException.class);
    }

    // Should throw SdkClientException
    @org.junit.Test
    @org.junit.jupiter.api.Test
    public void testDynamoNotRunning() {

        final Throwable throwable = Assertions.catchThrowable(() -> DockerTestUtils.getClientDynamoDb().listTables());

        Assertions.assertThat(throwable).isInstanceOf(SdkClientException.class);
    }

    @org.junit.Test
    @org.junit.jupiter.api.Test
    public void testS3NotRunning() {
        final Throwable throwable = Assertions.catchThrowable(() -> DockerTestUtils.getClientS3().createBucket
                ("test-bucket"));

        Assertions.assertThat(throwable).isInstanceOf(SdkClientException.class);
    }

    @org.junit.Test
    @org.junit.jupiter.api.Test
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
