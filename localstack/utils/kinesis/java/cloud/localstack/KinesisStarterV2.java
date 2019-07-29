// package cloud.localstack;
//
// import java.util.Properties;
// import java.util.Map;
// import java.util.concurrent.ExecutorService;
// import java.util.concurrent.Future;
// import java.lang.reflect.Field;
// import java.lang.reflect.Method;
// import java.lang.reflect.Constructor;
//
// import org.apache.commons.beanutils.BeanUtilsBean;
//
// import software.amazon.awssdk.core.SdkSystemSetting;
// import software.amazon.awssdk.services.kinesis.KinesisAsyncClient;
// import software.amazon.awssdk.services.kinesis.KinesisAsyncClientBuilder;
// import software.amazon.awssdk.http.Protocol;
// import software.amazon.awssdk.http.nio.netty.NettyNioAsyncHttpClient;
// import software.amazon.awssdk.http.async.SdkAsyncHttpClient;
// import software.amazon.kinesis.coordinator.Scheduler;
// import software.amazon.kinesis.coordinator.KinesisClientLibConfiguration;
// import software.amazon.kinesis.multilang.MultiLangDaemon;
// import software.amazon.kinesis.multilang.MultiLangDaemonConfig;
// import software.amazon.kinesis.multilang.config.BuilderDynaBean;
// import software.amazon.kinesis.multilang.config.MultiLangDaemonConfiguration;
// import software.amazon.kinesis.multilang.config.KinesisClientLibConfigurator;
//
// /**
//  * Custom extensions to <code>MultiLangDaemon</code> class from amazon-kinesis-client
//  * project, introducing the following additional configuration properties:
//  *
//  * - dynamodbEndpoint: endpoint host (hostname:port) for DynamoDB API
//  * - dynamodbProtocol: protocol for DynamoDB API (http or https)
//  * - kinesisProtocol: protocol for Kinesis API (http or https)
//  * - metricsLevel: level of CloudWatch metrics to report (e.g., SUMMARY or NONE)
//  *
//  * NOTE: This is an unfinished draft implementation for the v2 of kinesis client
//  * 			 library with MultiLangDaemon. In order to get this fully working, we
//  *       need to provide support for the new HTTP/2 based Kinesis features.
//  *
//  * @author Waldemar Hummer
//  */
// public class KinesisStarter {
//
// 	private static final String PROP_DYNAMODB_ENDPOINT = "dynamodbEndpoint";
// 	private static final String PROP_DYNAMODB_PROTOCOL = "dynamodbProtocol";
// 	private static final String PROP_KINESIS_ENDPOINT = "kinesisEndpoint";
// 	private static final String PROP_KINESIS_PROTOCOL = "kinesisProtocol";
// 	private static final String PROP_METRICS_LEVEL = "metricsLevel";
//
// 	public static void main(String[] args) throws Exception {
// 		int exitCode = 1;
// 		MultiLangDaemon daemon = new MultiLangDaemon();
// 		try {
// 			Properties props = loadProps(args[0]);
//
// 			if(props.containsKey("disableCertChecking")) {
// 				System.setProperty("com.amazonaws.sdk.disableCertChecking", "true");
// 			}
// 			System.setProperty(SdkSystemSetting.CBOR_ENABLED.property(), "false");
//
// 			Method m0 = daemon.getClass().getDeclaredMethod("buildMultiLangDaemonConfig", String.class);
// 			m0.setAccessible(true);
// 			MultiLangDaemonConfig config = (MultiLangDaemonConfig)m0.invoke(daemon, args[0]);
//
// 			MultiLangDaemonConfiguration daemonConfig = config.getMultiLangDaemonConfiguration();
// 			if(props.containsKey(PROP_DYNAMODB_ENDPOINT)) {
// 				String protocol = "http";
// 				if(props.containsKey(PROP_DYNAMODB_PROTOCOL)) {
// 					protocol = props.getProperty(PROP_DYNAMODB_PROTOCOL);
// 				}
// 				String endpoint = protocol + "://" + props.getProperty(PROP_DYNAMODB_ENDPOINT);
// 				daemonConfig.setDynamoDBEndpoint(endpoint);
// 			}
// 			if(props.containsKey(PROP_KINESIS_ENDPOINT)) {
// 				String protocol = "http";
// 				if(props.containsKey(PROP_KINESIS_PROTOCOL)) {
// 					protocol = props.getProperty(PROP_KINESIS_PROTOCOL);
// 				}
// 				String endpoint = protocol + "://" + props.getProperty(PROP_KINESIS_ENDPOINT);
// 				daemonConfig.setKinesisEndpoint(endpoint);
// 			}
//
// 			Method m1 = daemon.getClass().getDeclaredMethod("buildScheduler", config.getClass());
// 			m1.setAccessible(true);
// 			Scheduler scheduler = (Scheduler)m1.invoke(daemon, config);
//
// 			Class<?> clazz = getMultiLangRunner(daemon);
// 			Constructor ctor = clazz.getDeclaredConstructors()[0];
// 			ctor.setAccessible(true);
// 			Object runner = ctor.newInstance(scheduler);
//
// 			Method m2 = daemon.getClass().getDeclaredMethod("submitRunnerAndWait", config.getClass(), runner.getClass());
// 			m2.setAccessible(true);
// 			exitCode = (Integer)m2.invoke(daemon, config, runner);
// 		} catch (Throwable t) {
// 			t.printStackTrace(System.err);
// 			System.err.println("For more information, visit: https://github.com/awslabs/amazon-kinesis-client");
// 		}
// 		System.exit(exitCode);
// //		daemon.exit(exitCode);
// 	}
//
// 	private static Class<?> getMultiLangRunner(MultiLangDaemon daemon) {
// 		Class<?> clazz = null;
// 		for (Class<?> c : daemon.getClass().getDeclaredClasses()) {
// 			if (c.getSimpleName().equals("MultiLangRunner")) {
// 				clazz = c;
// 				break;
// 			}
// 		}
// 		return clazz;
// 	}
//
// 	private static Properties loadProps(String file) throws Exception {
// 		Properties props = new Properties();
// 		props.load(Thread.currentThread().getContextClassLoader().getResourceAsStream(file));
// 		return props;
// 	}
// }
