package com.atlassian;

import java.net.URL;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.Protocol;
import com.amazonaws.services.kinesis.clientlibrary.lib.worker.KinesisClientLibConfiguration;
import com.amazonaws.services.kinesis.multilang.MultiLangDaemon;
import com.amazonaws.services.kinesis.multilang.MultiLangDaemonConfig;

/**
 * Custom extensions to <code>MultiLangDaemon</code> class from amazon-kinesis-client
 * project, introducing the following additional configuration properties:
 *
 * - dynamodbEndpoint: endpoint host (hostname:port) for DynamoDB API
 * - dynamodbProtocol: protocol for DynamoDB API (http or https)
 * - kinesisProtocol: protocol for Kinesis API (http or https)
 * - metricsLevel: level of CloudWatch metrics to report (e.g., SUMMARY or NONE)
 *
 * @author Waldemar Hummer
 */
public class KinesisStarter {

	private static final String PROP_DYNAMODB_ENDPOINT = "dynamodbEndpoint";
	private static final String PROP_DYNAMODB_PROTOCOL = "dynamodbProtocol";
	private static final String PROP_KINESIS_PROTOCOL = "kinesisProtocol";
	private static final String PROP_METRICS_LEVEL = "metricsLevel";

	public static void main(String[] args) throws Exception {

		Properties props = loadProps(args[0]);

		if(props.containsKey("disableCertChecking")) {
			System.setProperty("com.amazonaws.sdk.disableCertChecking", "true");
		}

		MultiLangDaemonConfig config = new MultiLangDaemonConfig(args[0]);

		ExecutorService executorService = config.getExecutorService();

		KinesisClientLibConfiguration kinesisConfig = config.getKinesisClientLibConfiguration();
		ClientConfiguration dynamodbClient = kinesisConfig.getDynamoDBClientConfiguration();
		ClientConfiguration kinesisClient = kinesisConfig.getKinesisClientConfiguration();

		if(props.containsKey(PROP_METRICS_LEVEL)) {
			String level = props.getProperty(PROP_METRICS_LEVEL);
			kinesisConfig = kinesisConfig.withMetricsLevel(level);
		}
		if(props.containsKey(PROP_DYNAMODB_ENDPOINT)) {
			String endpoint = props.getProperty(PROP_DYNAMODB_ENDPOINT);
			URL url = new URL("http://" + endpoint);
			dynamodbClient.setProxyPort(url.getPort());
			dynamodbClient.setProxyHost(url.getHost());
		}
		if(props.containsKey(PROP_DYNAMODB_PROTOCOL)) {
			String protocol = props.getProperty(PROP_DYNAMODB_PROTOCOL);
			if("http".equalsIgnoreCase(protocol)) {
				dynamodbClient.setProtocol(Protocol.HTTP);
			} else if("https".equalsIgnoreCase(protocol)) {
				dynamodbClient.setProtocol(Protocol.HTTPS);
			} else {
				throw new RuntimeException("Unexpected protocol: " + protocol);
			}
		}
		if(props.containsKey(PROP_KINESIS_PROTOCOL)) {
			String protocol = props.getProperty(PROP_KINESIS_PROTOCOL);
			if("http".equalsIgnoreCase(protocol)) {
				kinesisClient.setProtocol(Protocol.HTTP);
			} else if("https".equalsIgnoreCase(protocol)) {
				kinesisClient.setProtocol(Protocol.HTTPS);
			} else {
				throw new RuntimeException("Unexpected protocol: " + protocol);
			}
		}

		MultiLangDaemon daemon = new MultiLangDaemon(
			kinesisConfig,
			config.getRecordProcessorFactory(),
			executorService);

		Future<Integer> future = executorService.submit(daemon);
		System.exit(future.get());
	}
	
	private static Properties loadProps(String file) throws Exception {
		Properties props = new Properties();
		props.load(Thread.currentThread().getContextClassLoader().getResourceAsStream(file));
		return props;
	}
}