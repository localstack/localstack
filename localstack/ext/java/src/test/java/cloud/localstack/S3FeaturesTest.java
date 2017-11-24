package cloud.localstack;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.BucketLifecycleConfiguration;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.PutObjectResult;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.SSEAwsKeyManagementParams;
import com.amazonaws.services.s3.model.Tag;
import com.amazonaws.services.s3.model.lifecycle.LifecycleFilter;
import com.amazonaws.services.s3.model.lifecycle.LifecycleTagPredicate;

@RunWith(LocalstackTestRunner.class)
public class S3FeaturesTest {

	/**
	 * Test that S3 bucket lifecycle settings can be set and read.
	 */
	@Test
	public void testSetBucketLifecycle() throws Exception {
		AmazonS3 client = TestUtils.getClientS3();

		String bucketName = UUID.randomUUID().toString();
		client.createBucket(bucketName);

		BucketLifecycleConfiguration.Rule rule = new BucketLifecycleConfiguration.Rule()
			.withId("expirationRule")
			.withFilter(new LifecycleFilter(new LifecycleTagPredicate(new Tag("deleted", "true"))))
			.withExpirationInDays(3)
			.withStatus(BucketLifecycleConfiguration.ENABLED);

		BucketLifecycleConfiguration bucketLifecycleConfiguration = new BucketLifecycleConfiguration()
			.withRules(rule);

		client.setBucketLifecycleConfiguration(bucketName, bucketLifecycleConfiguration);

		bucketLifecycleConfiguration = client.getBucketLifecycleConfiguration(bucketName);

		assertNotNull(bucketLifecycleConfiguration);
		assertEquals(bucketLifecycleConfiguration.getRules().get(0).getId(), "expirationRule");

		client.deleteBucket(bucketName);
	}

	/**
	 * Test HTTPS connections with local S3 service
	 */
	@Test
	public void testHttpsConnection() {
		if (!LocalstackTestRunner.useSSL()) {
			return;
		}

		TestUtils.disableSslCertChecking();

		String bucketName = "test-bucket-https";

		AmazonS3 amazonS3Client = AmazonS3ClientBuilder.standard()
				.withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(
						LocalstackTestRunner.getEndpointS3(),
						LocalstackTestRunner.getDefaultRegion()))
				.withCredentials(TestUtils.getCredentialsProvider())
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

	/**
	 * Test storing and retrieving of S3 object metadata
	 */
	@Test
	public void testMetadata() {
		AmazonS3 s3 = TestUtils.getClientS3();

		String bucketName = UUID.randomUUID().toString();
		s3.createBucket(bucketName);

		String keyWithUnderscores = "__key1";
		String keyWithDashes = keyWithUnderscores.replace("_", "-");

		Map<String, String> originalMetadata = new HashMap<String, String>();
		originalMetadata.put(keyWithUnderscores, "val1");

		ObjectMetadata objectMetadata = new ObjectMetadata();
		objectMetadata.setUserMetadata(originalMetadata);

		InputStream is = new ByteArrayInputStream("test-string".getBytes(StandardCharsets.UTF_8));
		s3.putObject(new PutObjectRequest(bucketName, "my-key1", is, objectMetadata));

		S3Object getObj = s3.getObject(new GetObjectRequest(bucketName, "my-key1"));
		ObjectMetadata objectMetadataResponse = getObj.getObjectMetadata();

		Map<String, String> receivedMetadata = objectMetadataResponse.getUserMetadata();

		Map<String, String> actualResult = new HashMap<String, String>();
		actualResult.put(keyWithDashes, "val1");

		// TODO: We currently have a bug that converts underscores in metadata keys to dashes.
		// See here for details: https://github.com/localstack/localstack/issues/459
		Assert.assertTrue(receivedMetadata.equals(originalMetadata) || receivedMetadata.equals(actualResult) );
	}

}
