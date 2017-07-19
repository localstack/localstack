package com.atlassian.localstack;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.PutObjectResult;
import com.amazonaws.services.s3.model.SSEAwsKeyManagementParams;

/**
 * @author Waldemar Hummer
 */
@RunWith(LocalstackTestRunner.class)
public class S3HttpsConnectionTest {

	@Test
	public void testHttpsConnection() {
		if (!LocalstackTestRunner.useSSL()) {
			return;
		}

		TestUtils.disableSslCertChecking();

		String bucketName = "test-bucket-https";

		AmazonS3 amazonS3Client = AmazonS3ClientBuilder.standard()
                .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(
                        LocalstackTestRunner.getEndpointS3(), LocalstackTestRunner.getDefaultRegion()))
		        .withChunkedEncodingDisabled(true)
		        .withPathStyleAccessEnabled(true).build();
		InputStream is = new ByteArrayInputStream("test file content".getBytes());
		amazonS3Client.createBucket(bucketName);
		PutObjectRequest putObjectRequest = new PutObjectRequest(
				bucketName, "key1", is, new ObjectMetadata()).
				withSSEAwsKeyManagementParams(new SSEAwsKeyManagementParams("kmsKeyId"));
		PutObjectResult result = amazonS3Client.putObject(putObjectRequest);
		Assert.assertNotNull(result);
		Assert.assertNotNull(result.getMetadata().getContentType());
		Assert.assertNotNull(result.getMetadata().getETag());
	}

}
