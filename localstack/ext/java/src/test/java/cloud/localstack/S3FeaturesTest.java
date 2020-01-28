package cloud.localstack;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.*;
import java.net.*;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.apache.commons.io.IOUtils;
import org.apache.http.*;
import org.apache.http.conn.ssl.*;
import org.apache.http.client.*;
import org.apache.http.client.methods.*;
import org.apache.http.entity.*;
import org.apache.http.impl.client.*;

import com.amazonaws.HttpMethod;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import com.amazonaws.services.s3.model.lifecycle.*;

import cloud.localstack.docker.annotation.LocalstackDockerProperties;

@RunWith(LocalstackTestRunner.class)
@LocalstackDockerProperties(services = {"s3"}, ignoreDockerRunErrors=true)
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
		if (!Localstack.useSSL()) {
			return;
		}

		TestUtils.disableSslCertChecking();

		String bucketName = "test-bucket-https";

		AmazonS3 amazonS3Client = AmazonS3ClientBuilder.standard()
				.withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(
						Localstack.INSTANCE.getEndpointS3(),
						Localstack.getDefaultRegion()))
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

		Map<String, String> originalMetadata = new HashMap<String, String>();
		originalMetadata.put("key1", "val1");
		originalMetadata.put("key_2", "val2");
		originalMetadata.put("__key3", "val3");

		ObjectMetadata objectMetadata = new ObjectMetadata();
		objectMetadata.setUserMetadata(originalMetadata);

		InputStream is = new ByteArrayInputStream("test-string".getBytes(StandardCharsets.UTF_8));
		s3.putObject(new PutObjectRequest(bucketName, "my-key1", is, objectMetadata));

		S3Object getObj = s3.getObject(new GetObjectRequest(bucketName, "my-key1"));
		ObjectMetadata objectMetadataResponse = getObj.getObjectMetadata();

		Map<String, String> receivedMetadata = objectMetadataResponse.getUserMetadata();

		Assert.assertEquals(originalMetadata, receivedMetadata);
	}

	@Test
	public void testListNextBatchOfObjects() {
		AmazonS3 s3Client = TestUtils.getClientS3();
		String s3BucketName = UUID.randomUUID().toString();
		s3Client.createBucket(s3BucketName);
		s3Client.putObject(s3BucketName, "key1", "content");
		s3Client.putObject(s3BucketName, "key2", "content");
		s3Client.putObject(s3BucketName, "key3", "content");

		ListObjectsRequest listObjectsRequest = new ListObjectsRequest()
			.withBucketName(s3BucketName)
			.withPrefix("")
			.withDelimiter("/")
			.withMaxKeys(1); // 1 Key per request

		ObjectListing objectListing = s3Client.listObjects(listObjectsRequest);
		List<Object> someObjList = new LinkedList<>();
		someObjList.addAll(mapFilesToSomeObject(objectListing)); // puts at least 1 item into the list

		while (objectListing.isTruncated()) {
			objectListing = s3Client.listNextBatchOfObjects(objectListing);
			someObjList.addAll(mapFilesToSomeObject(objectListing));
		}
		assertEquals(3, someObjList.size());
	}

	@Test
	public void testUploadEmptyBody() {
		AmazonS3 s3client = TestUtils.getClientS3();
		String bucketName = UUID.randomUUID().toString();
		String keyName = "test-key-empty";
		s3client.createBucket(bucketName);
		InputStream stream = new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8));
		PutObjectRequest request = new PutObjectRequest(bucketName, keyName, stream, new ObjectMetadata());
		PutObjectResult result = s3client.putObject(request);
		Assert.assertEquals(result.getMetadata().getETag(), "d41d8cd98f00b204e9800998ecf8427e");
	}

	@Test
	public void testPresignedURLUpload() throws Exception {
		AmazonS3 s3client = TestUtils.getClientS3();
		Date expiration = new Date(System.currentTimeMillis() + 1000*60*5);
		String bucketName = UUID.randomUUID().toString();
		String keyName = "presign-test-key";
		s3client.createBucket(bucketName);

		GeneratePresignedUrlRequest generatePresignedUrlRequest =
			new GeneratePresignedUrlRequest(bucketName, keyName)
				.withMethod(HttpMethod.PUT)
				.withExpiration(expiration)
				.withKey(keyName);
		URL presignedUrl = s3client.generatePresignedUrl(generatePresignedUrlRequest);

		// upload content
		String content = "test content";
		HttpPut httpPut = new HttpPut(presignedUrl.toString());
    httpPut.setEntity(new StringEntity(content));
		SSLContextBuilder builder = new SSLContextBuilder();
		builder.loadTrustMaterial(null, new TrustSelfSignedStrategy());
		SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(builder.build());
		CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();

		httpclient.execute(httpPut);
		httpclient.close();

		// download content
		GetObjectRequest req = new GetObjectRequest(bucketName, keyName);
		S3Object stream = s3client.getObject(req);
		String result = IOUtils.toString(stream.getObjectContent());
		Assert.assertEquals(result, content);
	}

	// ----------------
	// UTILITY METHODS
	// ----------------

	private List<Object> mapFilesToSomeObject(ObjectListing objectListing) {
		return objectListing.getObjectSummaries()
			.stream()
			.map(S3ObjectSummary::getKey)
			.collect(Collectors.toList());
	}

}
