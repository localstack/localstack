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
import java.util.List;
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
    private static final String SAMPLE_MULTI_BYTE_CHAR_QUEUE_NAME = "aws_develop_multi_byte";

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

    /**
     * Test calculate md5 correct
     * Based on: https://github.com/localstack/localstack/issues/1619
     */
    @Test
    public void testSendMultiByteCharactersMessage() throws JMSException {
        final AmazonSQS clientSQS = TestUtils.getClientSQS();
        final String queueUrl = clientSQS.createQueue(SAMPLE_MULTI_BYTE_CHAR_QUEUE_NAME).getQueueUrl();

        /*
         * send a message to the queue
         */
        final String messageBody = "foo";
        final Map<String, MessageAttributeValue> messageAttributes = new HashMap<>();
        messageAttributes.put("XXX", new MessageAttributeValue()
                .withDataType("String")
                .withStringValue("😇"));
        final SendMessageRequest sendMessageRequest = new SendMessageRequest();
        sendMessageRequest.withMessageBody(messageBody);
        sendMessageRequest.withQueueUrl(queueUrl);
        sendMessageRequest.withMessageAttributes(messageAttributes);
        final SendMessageResult sendMessageResult = clientSQS.sendMessage(sendMessageRequest);

        Assert.assertNotNull(sendMessageResult);
        Assert.assertEquals("acbd18db4cc2f85cedef654fccc4a4d8", sendMessageResult.getMD5OfMessageBody());
        Assert.assertEquals("23bf3e5b587065b0cfbe95761641595a", sendMessageResult.getMD5OfMessageAttributes());

        /*
         * receive the message from the queue
         */
        final ReceiveMessageResult messageResult = clientSQS.receiveMessage(queueUrl);
        Assert.assertNotNull(messageResult);
    }
}