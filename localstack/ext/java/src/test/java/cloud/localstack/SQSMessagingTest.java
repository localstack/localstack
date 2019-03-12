package cloud.localstack;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import javax.jms.JMSException;
import javax.jms.MessageConsumer;
import javax.jms.MessageProducer;
import javax.jms.Queue;
import javax.jms.Session;
import javax.jms.TextMessage;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.amazon.sqs.javamessaging.SQSConnection;
import com.amazon.sqs.javamessaging.SQSConnectionFactory;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSAsync;
import com.amazonaws.services.sqs.model.CreateQueueRequest;
import com.amazonaws.services.sqs.model.CreateQueueResult;
import com.amazonaws.services.sqs.model.Message;
import com.amazonaws.services.sqs.model.ReceiveMessageRequest;
import com.amazonaws.services.sqs.model.ReceiveMessageResult;
import com.amazonaws.services.sqs.model.SendMessageRequest;
import com.amazonaws.services.sqs.model.SendMessageResult;

import cloud.localstack.LocalstackTestRunner;
import cloud.localstack.TestUtils;
import cloud.localstack.util.PromiseAsyncHandler;

/**
 * Test integration of SQS/JMS messaging with LocalStack
 * Based on: https://bitbucket.org/atlassian/localstack/issues/24/not-support-sqs-in-jms
 */
@RunWith(LocalstackTestRunner.class)
public class SQSMessagingTest {

	private static final String QUEUE_NAME = "aws_develop_class_jms";

    @BeforeClass
    public static void setup() {
        Map<String, String> attributeMap = new HashMap<>();
        attributeMap.put("DelaySeconds", "0");
        attributeMap.put("MaximumMessageSize", "262144");
        attributeMap.put("MessageRetentionPeriod", "1209600");
        attributeMap.put("ReceiveMessageWaitTimeSeconds", "20");
        attributeMap.put("VisibilityTimeout", "30");

        AmazonSQS client = TestUtils.getClientSQS();
        CreateQueueRequest createQueueRequest = new CreateQueueRequest(QUEUE_NAME).withAttributes(attributeMap);
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

        Queue queue = session.createQueue(QUEUE_NAME);

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
        final String SAMPLE_QUEUE_NAME = "SAMPLE_QUEUE_NAME";

        final AmazonSQSAsync clientSQSAsync = TestUtils.getClientSQSAsync();

        final PromiseAsyncHandler<CreateQueueRequest, CreateQueueResult> createQueuePromise = new PromiseAsyncHandler<>();

        clientSQSAsync.createQueueAsync(SAMPLE_QUEUE_NAME, createQueuePromise);

        final CompletableFuture<String> queueUrl = createQueuePromise.thenCompose(createQueueResult -> {
            final PromiseAsyncHandler<SendMessageRequest, SendMessageResult> sendMessagePromise = new PromiseAsyncHandler<>();
            clientSQSAsync.sendMessageAsync(createQueueResult.getQueueUrl(), "message", sendMessagePromise);
            return sendMessagePromise.thenApply(e -> createQueueResult.getQueueUrl());
        });

        final String queue = queueUrl.get(5, TimeUnit.SECONDS);
        Assert.assertNotNull(queue);

        final PromiseAsyncHandler<ReceiveMessageRequest, ReceiveMessageResult> receiveMessagePromise = new PromiseAsyncHandler<>();
        clientSQSAsync.receiveMessageAsync(queue, receiveMessagePromise);

        final CompletableFuture<Message> receivedMessage = receiveMessagePromise.thenApply(e -> e.getMessages().get(0));

        Assert.assertEquals(receivedMessage.get(5, TimeUnit.SECONDS).getBody(), "message");
    }

}