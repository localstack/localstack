package cloud.localstack;

import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.logging.Logger;
import java.util.logging.Level;

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
	private static final String PROP_KINESIS_ENDPOINT = "kinesisEndpoint";
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

		if(props.containsKey(PROP_METRICS_LEVEL)) {
			String level = props.getProperty(PROP_METRICS_LEVEL);
			kinesisConfig = kinesisConfig.withMetricsLevel(level);
		}
		if(props.containsKey(PROP_DYNAMODB_ENDPOINT)) {
			String protocol = "http";
			if(props.containsKey(PROP_DYNAMODB_PROTOCOL)) {
				protocol = props.getProperty(PROP_DYNAMODB_PROTOCOL);
			}
			String endpoint = protocol + "://" + props.getProperty(PROP_DYNAMODB_ENDPOINT);
			kinesisConfig.withDynamoDBEndpoint(endpoint);
		}
		if(props.containsKey(PROP_KINESIS_ENDPOINT)) {
			String protocol = "http";
			if(props.containsKey(PROP_KINESIS_PROTOCOL)) {
				protocol = props.getProperty(PROP_KINESIS_PROTOCOL);
			}
			String endpoint = protocol + "://" + props.getProperty(PROP_KINESIS_ENDPOINT);
			kinesisConfig.withKinesisEndpoint(endpoint);
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
