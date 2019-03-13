package cloud.localstack;

import cloud.localstack.utils.PromiseAsyncHandler;
import com.amazon.sqs.javamessaging.SQSConnection;
import com.amazon.sqs.javamessaging.SQSConnectionFactory;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSAsync;
import com.amazonaws.services.sqs.model.*;
import com.amazonaws.services.sqs.model.Message;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.jms.*;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Test integration of SQS/JMS messaging with LocalStack
 * Based on: https://bitbucket.org/atlassian/localstack/issues/24/not-support-sqs-in-jms
 */
@RunWith(LocalstackTestRunner.class)
public class SQSMessagingTest {

    private static final String JMS_QUEUE_NAME = "aws_develop_class_jms";
    private static final String SAMPLE_QUEUE_NAME = "aws_develop_class";

    @BeforeClass
    public static void setup() {
        Map<String, String> attributeMap = new HashMap<>();
        attributeMap.put("DelaySeconds", "0");
        attributeMap.put("MaximumMessageSize", "262144");
        attributeMap.put("MessageRetentionPeriod", "1209600");
        attributeMap.put("ReceiveMessageWaitTimeSeconds", "20");
        attributeMap.put("VisibilityTimeout", "30");

        AmazonSQS client = TestUtils.getClientSQS();
        CreateQueueRequest createQueueRequest = new CreateQueueRequest(JMS_QUEUE_NAME).withAttributes(attributeMap);
        CreateQueueResult result = client.createQueue(createQueueRequest);
        Assert.assertNotNull(result);

        /* Disable SSL certificate checks for local testing */
        if (Localstack.useSSL()) {
            TestUtils.disableSslCertChecking();
        }
    }

    @Test
    public void testSendMessage() throws JMSException {
        SQSConnectionFactory connectionFactory = SQSConnectionFactory.builder().withEndpoint(
                Localstack.getEndpointSQS()).withAWSCredentialsProvider(
                new AWSStaticCredentialsProvider(TestUtils.TEST_CREDENTIALS)).build();
        SQSConnection connection = connectionFactory.createConnection();
        connection.start();
        Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);

        Queue queue = session.createQueue(JMS_QUEUE_NAME);

        // send message
        MessageProducer producer = session.createProducer(queue);
        TextMessage message = session.createTextMessage("This is a message!");
        producer.send(message);
        Assert.assertNotNull(message.getJMSMessageID());

        // receive message
        MessageConsumer consumer = session.createConsumer(queue);
        TextMessage received = (TextMessage) consumer.receive();
        Assert.assertNotNull(received);
    }

    @Test
    public void testSendMessageAsync() throws Exception {
        final AmazonSQSAsync clientSQSAsync = TestUtils.getClientSQSAsync();

        final PromiseAsyncHandler<CreateQueueRequest, CreateQueueResult> createQueuePromise = new PromiseAsyncHandler<>();

        clientSQSAsync.createQueueAsync(SAMPLE_QUEUE_NAME, createQueuePromise);

        final CompletableFuture<String> queueUrl = createQueuePromise.thenCompose(createQueueResult -> {
            final PromiseAsyncHandler<SendMessageRequest, SendMessageResult> sendMessagePromise = new PromiseAsyncHandler<>();
            clientSQSAsync.sendMessageAsync(createQueueResult.getQueueUrl(), "message", sendMessagePromise);
            return sendMessagePromise.thenApply(e -> createQueueResult.getQueueUrl());
        });

        final String queue = queueUrl.get(3, TimeUnit.SECONDS);
        Assert.assertNotNull(queue);

        final PromiseAsyncHandler<ReceiveMessageRequest, ReceiveMessageResult> receiveMessagePromise = new PromiseAsyncHandler<>();
        clientSQSAsync.receiveMessageAsync(queue, receiveMessagePromise);

        final CompletableFuture<Message> receivedMessage = receiveMessagePromise.thenApply(e -> e.getMessages().get(0));

        Assert.assertEquals(receivedMessage.get(3, TimeUnit.SECONDS).getBody(), "message");
    }

}