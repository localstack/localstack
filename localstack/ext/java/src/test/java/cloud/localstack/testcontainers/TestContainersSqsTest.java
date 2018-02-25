package cloud.localstack.testcontainers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.LogMessageWaitStrategy;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sqs.model.CreateQueueResult;
import com.amazonaws.services.sqs.model.Message;
import com.amazonaws.services.sqs.model.ReceiveMessageResult;
import com.amazonaws.services.sqs.model.SendMessageResult;

/**
 * <p>
 * This test is used to ensure that the bug of <a href="https://github.com/localstack/localstack/issues/308">#308</a> is fixed.
 * </p>
 * <p>
 * In this test the localstack docker images will be started by the <a href="https://www.testcontainers.org">testcontainers</a> framework.
 * SQS will then be used to send some messages.
 * </p>
 * <p>
 * The goal of this test is to check that the random port mapping of testcontainers is working with localstack.
 * </p>
 */
public class TestContainersSqsTest {

    private static final String DOCKER_IMAGE_NAME = "localstack/localstack:latest";

    private static final int SQS_PORT = 4576;

    private AmazonSQS amazonSQS;

    private GenericContainer<?> genericContainer;

    @Before
    public void before() {
        startDockerImage();
        createSqsClient();
    }

    @After
    public void after() {
        genericContainer.stop();
    }

    private void createSqsClient() {

        /*
         * get the randomly generated SQS port
         */
        final Integer mappedPort = genericContainer.getMappedPort(SQS_PORT);

        /*
         * create the SQS client
         */
        final AwsClientBuilder.EndpointConfiguration endpointConfiguration = new AwsClientBuilder.EndpointConfiguration(
                "http://localhost:" + mappedPort,
                "us-east-1");

        final AWSStaticCredentialsProvider awsStaticCredentialsProvider = new AWSStaticCredentialsProvider(
                new BasicAWSCredentials("accesskey", "secretkey"));

        amazonSQS = AmazonSQSClientBuilder
                .standard()
                .withEndpointConfiguration(endpointConfiguration)
                .withCredentials(awsStaticCredentialsProvider)
                .build();
    }

    @Test
    public void sendAndReceiveMessageTest() {

        /*
         * create the queue
         */
        final CreateQueueResult queue = amazonSQS.createQueue("test-queue");
        final String queueUrl = queue.getQueueUrl();

        /*
         * send a message to the queue
         */
        final String messageBody = "test-message";
        final SendMessageResult sendMessageResult = amazonSQS.sendMessage(queueUrl, messageBody);
        assertNotNull(sendMessageResult);

        final String messageId = sendMessageResult.getMessageId();
        assertNotNull(messageId);

        /*
         * receive the message from the queue
         */
        final ReceiveMessageResult messageResult = amazonSQS.receiveMessage(queueUrl);
        assertNotNull(messageResult);

        /*
         * compare results
         */
        final List<Message> messages = messageResult.getMessages();
        assertNotNull(messages);
        assertEquals(1, messages.size());

        final Message message = messages.get(0);
        assertEquals(messageId, message.getMessageId());
        assertEquals(messageBody, message.getBody());

    }

	@SuppressWarnings("resource")
	private void startDockerImage() {

        genericContainer = new GenericContainer<>(DOCKER_IMAGE_NAME)
                .withExposedPorts(SQS_PORT)
                .waitingFor(new LogMessageWaitStrategy().withRegEx(".*Ready\\.\n"));

        genericContainer.start();
    }
}
