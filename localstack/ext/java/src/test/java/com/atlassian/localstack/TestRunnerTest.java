package com.atlassian.localstack;

import java.util.List;

import com.atlassian.localstack.sample.S3Sample;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.kinesis.AmazonKinesis;
import com.amazonaws.services.kinesis.AmazonKinesisClient;
import com.amazonaws.services.kinesis.model.ListStreamsResult;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.ListFunctionsResult;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.Bucket;

import static com.atlassian.localstack.TestUtils.*;

@RunWith(LocalstackTestRunner.class)
public class TestRunnerTest {

	static {
		/*
		 * Need to disable CBOR protocol, see:
		 * https://github.com/mhart/kinesalite/blob/master/README.md#cbor-protocol-issues-with-the-java-sdk
		 */
		TestUtils.setEnv("AWS_CBOR_DISABLE", "1");
	}

	@Test
	public void testLocalKinesisAPI() {
		AmazonKinesis kinesis = new AmazonKinesisClient(TEST_CREDENTIALS);
		kinesis.setEndpoint(LocalstackTestRunner.getEndpointKinesis());
		ListStreamsResult streams = kinesis.listStreams();
		Assert.assertNotNull(streams.getStreamNames());
	}

	@Test
	public void testLocalS3API() throws Exception {
		AmazonS3 s3 = new AmazonS3Client(TEST_CREDENTIALS);
		s3.setEndpoint(LocalstackTestRunner.getEndpointS3());
		List<Bucket> buckets = s3.listBuckets();
		Assert.assertNotNull(buckets);
		S3Sample.runTest(TEST_CREDENTIALS);
	}

	@Test
	public void testLocalLambdaAPI() {
		AWSLambda lambda = AWSLambdaClientBuilder.standard().withEndpointConfiguration(
				new AwsClientBuilder.EndpointConfiguration(
						LocalstackTestRunner.getEndpointLambda(), DEFAULT_REGION)).withCredentials(
								new AWSStaticCredentialsProvider(TEST_CREDENTIALS)).build();
		ListFunctionsResult functions = lambda.listFunctions();
		Assert.assertNotNull(functions.getFunctions());
	}

}
