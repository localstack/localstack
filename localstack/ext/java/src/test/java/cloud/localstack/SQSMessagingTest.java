package cloud.localstack;

import java.util.HashMap;
import java.util.Map;

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
import com.amazonaws.services.sqs.model.CreateQueueRequest;
import com.amazonaws.services.sqs.model.CreateQueueResult;

import cloud.localstack.LocalstackTestRunner;
import cloud.localstack.TestUtils;

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
		if (LocalstackTestRunner.useSSL()) {
			TestUtils.disableSslCertChecking();
		}
    }

    @Test
    public void testSendMessage() throws JMSException {
        SQSConnectionFactory connectionFactory = SQSConnectionFactory.builder().withEndpoint(
                LocalstackTestRunner.getEndpointSQS()).withAWSCredentialsProvider(
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

}