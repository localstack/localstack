package cloud.localstack;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.apache.http.entity.ContentType;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.BucketLifecycleConfiguration;
import com.amazonaws.services.s3.model.Tag;
import com.amazonaws.services.s3.model.lifecycle.LifecycleFilter;
import com.amazonaws.services.s3.model.lifecycle.LifecycleFilterPredicate;
import com.amazonaws.services.s3.model.lifecycle.LifecycleTagPredicate;

/**
 * Test that S3 bucket lifecycle settings can be set and read.
 */
@RunWith(LocalstackTestRunner.class)
public class S3LifecycleTest {

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
}
