package com.atlassian.localstack;

import static com.atlassian.localstack.TestUtils.TEST_CREDENTIALS;

import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.amazonaws.services.kinesis.AmazonKinesis;
import com.amazonaws.services.kinesis.model.ListStreamsResult;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.model.ListFunctionsResult;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.Bucket;
import com.atlassian.localstack.sample.S3Sample;

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
	}

	@Test
	public void testLocalKinesisAPI() {
		AmazonKinesis kinesis = TestUtils.getClientKinesis();
		ListStreamsResult streams = kinesis.listStreams();
		Assert.assertNotNull(streams.getStreamNames());
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

}
