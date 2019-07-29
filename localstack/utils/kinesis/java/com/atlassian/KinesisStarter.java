package com.atlassian;

import java.util.Properties;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Constructor;

import org.apache.commons.beanutils.BeanUtilsBean;

import software.amazon.awssdk.core.SdkSystemSetting;
import software.amazon.awssdk.services.kinesis.KinesisAsyncClient;
import software.amazon.awssdk.services.kinesis.KinesisAsyncClientBuilder;
import software.amazon.awssdk.http.Protocol;
import software.amazon.awssdk.http.nio.netty.NettyNioAsyncHttpClient;
import software.amazon.awssdk.http.async.SdkAsyncHttpClient;
import software.amazon.kinesis.coordinator.Scheduler;
import software.amazon.kinesis.coordinator.KinesisClientLibConfiguration;
import software.amazon.kinesis.multilang.MultiLangDaemon;
import software.amazon.kinesis.multilang.MultiLangDaemonConfig;
import software.amazon.kinesis.multilang.config.BuilderDynaBean;
import software.amazon.kinesis.multilang.config.MultiLangDaemonConfiguration;
import software.amazon.kinesis.multilang.config.KinesisClientLibConfigurator;

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
		int exitCode = 1;
		MultiLangDaemon daemon = new MultiLangDaemon();
		try {
			Properties props = loadProps(args[0]);

			if(props.containsKey("disableCertChecking")) {
				System.setProperty("com.amazonaws.sdk.disableCertChecking", "true");
			}
			System.setProperty(SdkSystemSetting.CBOR_ENABLED.property(), "false");

//			MultiLangDaemonConfig config = daemon.buildMultiLangDaemonConfig(propertiesFile);
			Method m0 = daemon.getClass().getDeclaredMethod("buildMultiLangDaemonConfig", String.class);
			m0.setAccessible(true);
			MultiLangDaemonConfig config = (MultiLangDaemonConfig)m0.invoke(daemon, args[0]);

			MultiLangDaemonConfiguration daemonConfig = config.getMultiLangDaemonConfiguration();
			if(props.containsKey(PROP_DYNAMODB_ENDPOINT)) {
				String protocol = "http";
				if(props.containsKey(PROP_DYNAMODB_PROTOCOL)) {
					protocol = props.getProperty(PROP_DYNAMODB_PROTOCOL);
				}
				String endpoint = protocol + "://" + props.getProperty(PROP_DYNAMODB_ENDPOINT);
				daemonConfig.setDynamoDBEndpoint(endpoint);
			}
			if(props.containsKey(PROP_KINESIS_ENDPOINT)) {
				String protocol = "http";
				if(props.containsKey(PROP_KINESIS_PROTOCOL)) {
					protocol = props.getProperty(PROP_KINESIS_PROTOCOL);
				}
				String endpoint = protocol + "://" + props.getProperty(PROP_KINESIS_ENDPOINT);
				daemonConfig.setKinesisEndpoint(endpoint);
			}

//			Scheduler scheduler = daemon.buildScheduler(config);
			Method m1 = daemon.getClass().getDeclaredMethod("buildScheduler", config.getClass());
			m1.setAccessible(true);
			Scheduler scheduler = (Scheduler)m1.invoke(daemon, config);

			Class<?> clazz = getMultiLangRunner(daemon);
			Constructor ctor = clazz.getDeclaredConstructors()[0];
			ctor.setAccessible(true);
			Object runner = ctor.newInstance(scheduler);
//			MultiLangRunner runner = new MultiLangRunner(scheduler);

//			daemon.setupShutdownHook(Runtime.getRuntime(), runner, config);
//			exitCode = daemon.submitRunnerAndWait(config, runner);

			Method m2 = daemon.getClass().getDeclaredMethod("submitRunnerAndWait", config.getClass(), runner.getClass());
			m2.setAccessible(true);
			exitCode = (Integer)m2.invoke(daemon, config, runner);
		} catch (Throwable t) {
			t.printStackTrace(System.err);
			System.err.println("For more information, visit: https://github.com/awslabs/amazon-kinesis-client");
		}
		System.exit(exitCode);
//		daemon.exit(exitCode);
	}

	public static void main1(String[] args) throws Exception {

		Properties props = loadProps(args[0]);

		if(props.containsKey("disableCertChecking")) {
			System.setProperty("com.amazonaws.sdk.disableCertChecking", "true");
		}

		KinesisClientLibConfigurator configurator = new KinesisClientLibConfigurator();
		// MultiLangDaemonConfiguration config = configurator.getConfiguration(props); // new MultiLangDaemonConfiguration(args[0]);
//		MultiLangDaemonConfig config = new MultiLangDaemonConfig(args[0]);

		MultiLangDaemon daemon = new MultiLangDaemon();
//		MultiLangDaemonConfig config = daemon.buildMultiLangDaemonConfig(props);
		MultiLangDaemonConfig config = (MultiLangDaemonConfig)daemon.getClass().getDeclaredMethod(
				"buildMultiLangDaemonConfig", props.getClass()).invoke(daemon, props);
		MultiLangDaemonConfiguration daemonConfig = config.getMultiLangDaemonConfiguration();

		ExecutorService executorService = config.getExecutorService();
//		KinesisClientLibConfiguration kinesisConfig = config.getKinesisClientLibConfiguration();

//		if(props.containsKey(PROP_METRICS_LEVEL)) {
//			String level = props.getProperty(PROP_METRICS_LEVEL);
//			kinesisConfig = kinesisConfig.withMetricsLevel(level);
//		}
		if(props.containsKey(PROP_DYNAMODB_ENDPOINT)) {
			String protocol = "http";
			if(props.containsKey(PROP_DYNAMODB_PROTOCOL)) {
				protocol = props.getProperty(PROP_DYNAMODB_PROTOCOL);
			}
			String endpoint = protocol + "://" + props.getProperty(PROP_DYNAMODB_ENDPOINT);
			daemonConfig.setDynamoDBEndpoint(endpoint);
//			kinesisConfig.withDynamoDBEndpoint(endpoint);
		}
		if(props.containsKey(PROP_KINESIS_ENDPOINT)) {
			String protocol = "http";
			if(props.containsKey(PROP_KINESIS_PROTOCOL)) {
				protocol = props.getProperty(PROP_KINESIS_PROTOCOL);
			}
			String endpoint = protocol + "://" + props.getProperty(PROP_KINESIS_ENDPOINT);
			daemonConfig.setKinesisEndpoint(endpoint);
//			kinesisConfig.withKinesisEndpoint(endpoint);
		}

//		MultiLangDaemon daemon = new MultiLangDaemon(
//			kinesisConfig,
//			config.getRecordProcessorFactory(),
//			executorService);
//
//		Future<Integer> future = executorService.submit(daemon);
//		System.exit(future.get());

		// We need to use reflection below, as MultiLangDaemon doesn't expose some key classes and methods :/

		Field f1 = daemonConfig.getClass().getDeclaredField("kinesisClient");
		f1.setAccessible(true);
		BuilderDynaBean kinesisClient = (BuilderDynaBean)f1.get(daemonConfig);


//		SdkAsyncHttpClient httpClient = NettyNioAsyncHttpClient.builder()
//				.protocol(Protocol.HTTP1_1).build();
//		Object httpClientBuilder = NettyNioAsyncHttpClient.builder()
//				.protocol(Protocol.HTTP1_1);
//		KinesisAsyncClientBuilder builder = KinesisAsyncClient.builder().httpClient(httpClient);
//		f1.set(daemonConfig, builder);

		//		kinesisClient.httpClient(httpClient);
		Field f2 = daemonConfig.getClass().getDeclaredField("utilsBean");
		f2.setAccessible(true);
		BeanUtilsBean utilsBean = (BeanUtilsBean)f2.get(daemonConfig);
		System.out.println(utilsBean.getProperty(kinesisClient, "httpClient"));
		System.out.println(utilsBean.getProperty(kinesisClient, "httpClientBuilder"));
//		utilsBean.setProperty(kinesisClient, "httpClient", httpClient);
		Field f3 = kinesisClient.getClass().getDeclaredField("dynaBeanBuilderSupport");
		f3.setAccessible(true);
		Object dynaBeanBuilderSupport = f3.get(kinesisClient);
		Field f4 = dynaBeanBuilderSupport.getClass().getDeclaredField("properties");
		f4.setAccessible(true);
		Object properties = f4.get(dynaBeanBuilderSupport);
		System.out.println("properties " + properties);
		Field f5 = dynaBeanBuilderSupport.getClass().getDeclaredField("values");
		f5.setAccessible(true);
		Map<String, Object> values = (Map<String, Object>)f5.get(dynaBeanBuilderSupport);
		System.out.println("values " + values);

		Object httpClientDynaBean = values.get("httpClient");
		Field f6 = httpClientDynaBean.getClass().getDeclaredField("dynaBeanBuilderSupport");
		f6.setAccessible(true);
		Object httpClientDynaBeanSupport = f6.get(httpClientDynaBean);
		System.out.println("httpClientDynaBeanSupport " + httpClientDynaBeanSupport);
		if (httpClientDynaBeanSupport != null) {
			Field f7 = httpClientDynaBeanSupport.getClass().getDeclaredField("values");
			f7.setAccessible(true);
			Map<String, Object> values1 = (Map<String, Object>) f7.get(httpClientDynaBeanSupport);
			System.out.println("values1 " + values1);
		}

		Object clientBuilderDynaBean = values.get("httpClientBuilder");
		Field f8 = clientBuilderDynaBean.getClass().getDeclaredField("dynaBeanBuilderSupport");
		f8.setAccessible(true);
		Object clientBuilderDynaBeanSupport = f8.get(clientBuilderDynaBean);
		System.out.println("clientBuilderDynaBeanSupport " + clientBuilderDynaBeanSupport);
		if (clientBuilderDynaBeanSupport != null) {
			Field f9 = clientBuilderDynaBeanSupport.getClass().getDeclaredField("values");
			f9.setAccessible(true);
			Map<String, Object> values2 = (Map<String, Object>) f9.get(clientBuilderDynaBeanSupport);
			System.out.println("values2 " + values2);
		} else {
//			dynaBeanBuilderSupport = new DynaBeanBuilderSupport(
//					NettyNioAsyncHttpClient.class, convertUtilsBean, classPrefixSearchList);
//			f8.set(clientBuilderDynaBean, dynaBeanBuilderSupport);
		}


		// utilsBean.setProperty(kinesisClient, "httpClientBuilder", httpClientBuilder);


		Method m1 = daemon.getClass().getDeclaredMethod("buildScheduler", config.getClass());
		m1.setAccessible(true);
		Scheduler scheduler = (Scheduler)m1.invoke(daemon, config);

		Class<?> clazz = getMultiLangRunner(daemon);
		Constructor ctor = clazz.getDeclaredConstructors()[0];
		ctor.setAccessible(true);
		Object runner = ctor.newInstance(scheduler);

		Method m2 = daemon.getClass().getDeclaredMethod("submitRunnerAndWait", config.getClass(), runner.getClass());
		m2.setAccessible(true);
		int exitCode = (Integer)m2.invoke(daemon, config, runner);
		System.exit(exitCode);
	}

	private static Class<?> getMultiLangRunner(MultiLangDaemon daemon) {
		Class<?> clazz = null;
		for (Class<?> c : daemon.getClass().getDeclaredClasses()) {
			if (c.getSimpleName().equals("MultiLangRunner")) {
				clazz = c;
				break;
			}
		}
		return clazz;
	}
	
	private static Properties loadProps(String file) throws Exception {
		Properties props = new Properties();
		props.load(Thread.currentThread().getContextClassLoader().getResourceAsStream(file));
		return props;
	}
}