package cloud.localstack;

import static cloud.localstack.TestUtils.TEST_CREDENTIALS;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.amazonaws.services.kinesis.AmazonKinesis;
import com.amazonaws.services.kinesis.model.ListStreamsResult;
import com.amazonaws.services.kinesis.model.PutRecordRequest;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.model.ListFunctionsResult;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.model.CreateQueueRequest;
import com.amazonaws.services.sqs.model.CreateQueueResult;
import com.amazonaws.services.sqs.model.DeleteQueueRequest;
import com.amazonaws.services.sqs.model.ListQueuesResult;
import com.amazonaws.services.sqs.model.ReceiveMessageRequest;
import com.amazonaws.services.sqs.model.ReceiveMessageResult;
import com.amazonaws.services.sqs.model.SendMessageRequest;
import com.amazonaws.services.sqs.model.SendMessageResult;

import cloud.localstack.sample.S3Sample;

/**
 * Simple class to test basic functionality and interaction with LocalStack.
 * @author Waldemar Hummer
 */
@RunWith(LocalstackTestRunner.class)
public class BasicFunctionalityTest {

	static {
		/*
		 * Need to disable CBOR protocol, see:
		 * https://github.com/mhart/kinesalite/blob/master/README.md#cbor-protocol-issues-with-the-java-sdk
		 */
		TestUtils.setEnv("AWS_CBOR_DISABLE", "1");
		/* Disable SSL certificate checks for local testing */
		if (LocalstackTestRunner.useSSL()) {
			TestUtils.disableSslCertChecking();
		}
	}

	@Test
	public void testLocalKinesisAPI() throws InterruptedException {
		AmazonKinesis kinesis = TestUtils.getClientKinesis();
		ListStreamsResult streams = kinesis.listStreams();
		Assert.assertNotNull(streams.getStreamNames());
		String streamName = "testStreamJUnit";
		kinesis.createStream(streamName, 1);
		// sleep required because of kinesalite
		Thread.sleep(500);
		PutRecordRequest req = new PutRecordRequest();
		req.setPartitionKey("foobar-key");
		req.setData(ByteBuffer.wrap("{}".getBytes()));
		req.setStreamName(streamName);
		kinesis.putRecord(req);
	}

	@Test
	public void testLocalS3API() throws Exception {
		AmazonS3 s3 = TestUtils.getClientS3();
		List<Bucket> buckets = s3.listBuckets();
		Assert.assertNotNull(buckets);
		S3Sample.runTest(TEST_CREDENTIALS);
	}

	@Test
	public void testLocalLambdaAPI() {
		AWSLambda lambda = TestUtils.getClientLambda();
		ListFunctionsResult functions = lambda.listFunctions();
		Assert.assertNotNull(functions.getFunctions());
	}

	@Test
	public void testLocalSQSAPI() {
		AmazonSQS sqs = TestUtils.getClientSQS();
		ListQueuesResult queues = sqs.listQueues();
		Assert.assertNotNull(queues.getQueueUrls());

		for (String queueName: Arrays.asList("java_test_queue", "java_test_queue.fifo")) {
			// create queue
			CreateQueueRequest createQueueRequest = new CreateQueueRequest();
			createQueueRequest.setQueueName(queueName);
			CreateQueueResult newQueue = sqs.createQueue(createQueueRequest);
			String queueUrl = newQueue.getQueueUrl();

			// send message
			SendMessageRequest send = new SendMessageRequest(queueUrl, "body");
			SendMessageResult sendResult = sqs.sendMessage(send);
			Assert.assertNotNull(sendResult.getMD5OfMessageBody());

			// receive message
			ReceiveMessageRequest request = new ReceiveMessageRequest(queueUrl);
			request.setWaitTimeSeconds(1);
			request.setMaxNumberOfMessages(1);
			request.setMessageAttributeNames(Arrays.asList("All"));
			request.setAttributeNames(Arrays.asList("All"));
			ReceiveMessageResult result = sqs.receiveMessage(request);
			Assert.assertNotNull(result.getMessages());
			Assert.assertEquals(result.getMessages().size(), 1);

			// delete queue
			DeleteQueueRequest deleteQueue = new DeleteQueueRequest();
			deleteQueue.setQueueUrl(queueUrl);
			sqs.deleteQueue(deleteQueue);
		}
	}

}
