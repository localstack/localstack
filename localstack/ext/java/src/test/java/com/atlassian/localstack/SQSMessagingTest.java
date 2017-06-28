package com.atlassian.localstack;

import com.amazon.sqs.javamessaging.SQSConnection;
import com.amazon.sqs.javamessaging.SQSConnectionFactory;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.model.CreateQueueRequest;
import com.amazonaws.services.sqs.model.CreateQueueResult;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.jms.*;
import java.util.HashMap;
import java.util.Map;

/**
 * Test integration of SQS/JMS messaging with LocalStack
 * Based on: https://bitbucket.org/atlassian/localstack/issues/24/not-support-sqs-in-jms
 */
@RunWith(LocalstackTestRunner.class)
@Ignore
public class SQSMessagingTest {

    @BeforeClass
    public static void setup() {
        Map<String, String> attributeMap = new HashMap<>();
        attributeMap.put("DelaySeconds", "0");
        attributeMap.put("MaximumMessageSize", "262144");
        attributeMap.put("MessageRetentionPeriod", "1209600");
        attributeMap.put("ReceiveMessageWaitTimeSeconds", "20");
        attributeMap.put("VisibilityTimeout", "30");

        AmazonSQS client = TestUtils.getClientSQS();
        CreateQueueRequest createQueueRequest = new CreateQueueRequest("aws_develop_class_jms").withAttributes(attributeMap);
        CreateQueueResult result = client.createQueue(createQueueRequest);
        Assert.assertNotNull(result);
    }

    @Test
    public void testSendMessage() throws JMSException {
        SQSConnectionFactory connectionFactory = SQSConnectionFactory.builder().withEndpoint(
                LocalstackTestRunner.getEndpointSQS()).build();
        SQSConnection connection = connectionFactory.createConnection();
        Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);

        Queue queue = session.createQueue("aws_develop_class_jms");
        MessageProducer producer = session.createProducer(queue);
        TextMessage message = session.createTextMessage("This is a message!");
        producer.send(message);
        Assert.assertNotNull(message.getJMSMessageID());
    }

}
