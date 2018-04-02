package cloud.localstack;

import com.amazonaws.util.IOUtils;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.InitializationError;
import org.ow2.proactive.process_tree_killer.ProcessTree;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

/**
 * Simple JUnit test runner that automatically downloads, installs, starts,
 * and stops the LocalStack local cloud infrastructure components.
 *
 * Should work cross-OS, however has been only tested under Unix (Linux/MacOS).
 *
 * @author Waldemar Hummer
 */
public class LocalstackTestRunner extends BlockJUnit4ClassRunner {
	private static final Logger LOG = Logger.getLogger(LocalstackTestRunner.class.getName());

	private static final boolean IS_WINDOWS = System.getProperty("os.name").toLowerCase().contains("windows");

	private static final AtomicReference<Process> INFRA_STARTED = new AtomicReference<Process>();

	private static final String INFRA_READY_MARKER = "Ready.";
	private static final String LOCAL_INSTALL_DIR = "localstack_install_dir";
	private static final String ADDITIONAL_PATH = "/usr/local/bin/";
	private static final String LOCALSTACK_REPO_URL = "https://github.com/localstack/localstack";
	private static final String INSTALLATION_FINISHED_MARKER = "installation_finished_marker";

	public static final String ENV_CONFIG_USE_SSL = "USE_SSL";
	private static final String ENV_LOCALSTACK_PROCESS_GROUP = "ENV_LOCALSTACK_PROCESS_GROUP";

	private static String tmpInstallDir = null;

	public LocalstackTestRunner(Class<?> klass) throws InitializationError {
		super(klass);
	}

	/* SERVICE ENDPOINTS */

	public static String getEndpointS3() {
		String s3Endpoint = ensureInstallationAndGetEndpoint(ServiceName.S3);
		/*
		 * Use the domain name wildcard *.localhost.atlassian.io which maps to 127.0.0.1
		 * We need to do this because S3 SDKs attempt to access a domain <bucket-name>.<service-host-name>
		 * which by default would result in <bucket-name>.localhost, but that name cannot be resolved
		 * (unless hardcoded in /etc/hosts)
		 */
		s3Endpoint = s3Endpoint.replace("localhost", "test.localhost.atlassian.io");
		return s3Endpoint;
	}

	public static String getEndpointKinesis() {
		return ensureInstallationAndGetEndpoint(ServiceName.KINESIS);
	}

	public static String getEndpointLambda() {
		return ensureInstallationAndGetEndpoint(ServiceName.LAMBDA);
	}

	public static String getEndpointDynamoDB() {
		return ensureInstallationAndGetEndpoint(ServiceName.DYNAMO);
	}

	public static String getEndpointDynamoDBStreams() {
		return ensureInstallationAndGetEndpoint(ServiceName.DYNAMO_STREAMS);
	}

	public static String getEndpointAPIGateway() {
		return ensureInstallationAndGetEndpoint(ServiceName.API_GATEWAY);
	}

	public static String getEndpointElasticsearch() {
		return ensureInstallationAndGetEndpoint(ServiceName.ELASTICSEARCH);
	}

	public static String getEndpointElasticsearchService() {
		return ensureInstallationAndGetEndpoint(ServiceName.ELASTICSEARCH_SERVICE);
	}

	public static String getEndpointFirehose() {
		return ensureInstallationAndGetEndpoint(ServiceName.FIREHOSE);
	}

	public static String getEndpointSNS() {
		return ensureInstallationAndGetEndpoint(ServiceName.SNS);
	}

	public static String getEndpointSQS() {
		return ensureInstallationAndGetEndpoint(ServiceName.SQS);
	}

	public static String getEndpointRedshift() {
		return ensureInstallationAndGetEndpoint(ServiceName.REDSHIFT);
	}

	public static String getEndpointSES() {
		return ensureInstallationAndGetEndpoint(ServiceName.SES);
	}

	public static String getEndpointRoute53() {
		return ensureInstallationAndGetEndpoint(ServiceName.ROUTE53);
	}

	public static String getEndpointCloudFormation() {
		return ensureInstallationAndGetEndpoint(ServiceName.CLOUDFORMATION);
	}

	public static String getEndpointCloudWatch() {
		return ensureInstallationAndGetEndpoint(ServiceName.CLOUDWATCH);
	}

	public static String getEndpointSSM() {
		return ensureInstallationAndGetEndpoint(ServiceName.SSM);
	}

	/* OVERRIDE METHODS FROM JUNIT TEST RUNNER */

	@Override
	public void run(RunNotifier notifier) {
		setupInfrastructure();
		super.run(notifier);
	}

	/* UTILITY METHODS */

	/**
	 * for paths that will be passed into bash/linux we need to convert windows file paths to linux file paths
	 * (assuming the linux subsystem for windows is being used)
	 */
	private static String getTmpInstallDir() {
		if (null == tmpInstallDir) {
			String tempDir = getRawTmpInstallDir();
			tempDir = tempDir.replaceAll("^((c:)|(C:))", "/mnt/c");
			tmpInstallDir = tempDir.replaceAll("\\\\", "/");
		}
		return tmpInstallDir;
	}

	/**
	 * only add a trailing path separator if one doesn't already exist
	 */
	private static String getRawTmpInstallDir() {
		String tempDir = System.getProperty("java.io.tmpdir");
		if (!tempDir.endsWith(File.separator)) {
			tempDir += File.separator;
		}
		return tempDir + LOCAL_INSTALL_DIR;
	}

	private static void ensureInstallation() {
		File dir = new File(getRawTmpInstallDir());

		File constantsFile = new File(dir, "localstack/constants.py");
		String logMsg = "Installing LocalStack to temporary directory (this may take a while): " + getTmpInstallDir();
		boolean messagePrinted = false;

		if(!constantsFile.exists()) {
			LOG.info(logMsg);
			messagePrinted = true;
			deleteDirectory(dir);
			LOG.info("cloning...");
			exec("git clone " + LOCALSTACK_REPO_URL + " " + getTmpInstallDir());
		}

		File installationDoneMarker = new File(getRawTmpInstallDir() + "/localstack/infra/" + INSTALLATION_FINISHED_MARKER);
		LOG.info("checking installation...");
		if (!installationDoneMarker.getAbsoluteFile().exists()) {
			if(!messagePrinted) {
				LOG.info(logMsg);
			}
			LOG.info("installing...");
			exec("cd '" + getTmpInstallDir() + "'; make install");
			/* create marker file */
			if (IS_WINDOWS) {
				exec(false, "cd '" + getTmpInstallDir() + "/localstack/infra'; cat > " + INSTALLATION_FINISHED_MARKER);
			} else {
				try {
					installationDoneMarker.createNewFile();
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}
	}

	private static void deleteDirectory(File dir) {
		try {
			if(dir.exists())
				Files.walk(dir.toPath())
						.sorted(Comparator.reverseOrder())
						.map(Path::toFile)
						.forEach(File::delete);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private static void killProcess(Process p) {
		try {
			ProcessTree.get().killAll(Collections.singletonMap(
					ENV_LOCALSTACK_PROCESS_GROUP, ENV_LOCALSTACK_PROCESS_GROUP));
		} catch (Exception e) {
			LOG.warning("Unable to terminate processes: " + e);
		}
	}

	private static String ensureInstallationAndGetEndpoint(String service) {
		ensureInstallation();
		return getEndpoint(service);
	}

	public static boolean useSSL() {
		return isEnvConfigSet(ENV_CONFIG_USE_SSL);
	}

	public static boolean isEnvConfigSet(String configName) {
		String value = System.getenv(configName);
		return value != null && !Arrays.asList("false", "0", "").contains(value.trim());
	}

	private static String getEndpoint(String service) {
		LOG.info(String.format("fetching endpoint for '%s'...", service));
		String result = IS_WINDOWS ? getEndpointOnWindows(service) : getEndpointOnLinux(service);
		LOG.info(String.format("'%s' located at %s", service, result));
		return result;
	}

	private static String getEndpointOnLinux(String service) {
		String useSSL = useSSL() ? "USE_SSL=1" : "";
		String cmd = "cd '" + getTmpInstallDir() + "'; "
				+ ". .venv/bin/activate; "
				+ useSSL + " python -c 'import localstack_client.config; "
				+ "print(localstack_client.config.get_service_endpoint(\"" + service + "\"))'";
		Process p = exec(cmd);
		try {
			return IOUtils.toString(p.getInputStream()).trim();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private static String getEndpointOnWindows(String service) {
		return ServiceName.getServiceUrl(service);
	}

	private static Process exec(String ... cmd) {
		return exec(true, cmd);
	}

	private static Process exec(boolean wait, String ... cmd) {
		return IS_WINDOWS ? execWindows(wait, cmd) : execLinux(wait, cmd);
	}

	private static Process execLinux(boolean wait, String ... cmd) {
		try {
			if (cmd.length == 1 && !new File(cmd[0]).exists()) {
				cmd = new String[]{"bash", "-c", cmd[0]};
			}
			Map<String, String> env = new HashMap<>(System.getenv());
			ProcessBuilder builder = new ProcessBuilder(cmd);
			builder.environment().put("PATH", ADDITIONAL_PATH + ":" + env.get("PATH"));
			builder.environment().put(ENV_LOCALSTACK_PROCESS_GROUP, ENV_LOCALSTACK_PROCESS_GROUP);
			final Process p = builder.start();
			if (wait) {
				int code = p.waitFor();
				if(code != 0) {
					String stderr = IOUtils.toString(p.getErrorStream());
					String stdout = IOUtils.toString(p.getInputStream());
					throw new IllegalStateException("Failed to run command '" + String.join(" ", cmd) + "', return code " + code +
							".\nSTDOUT: " + stdout + "\nSTDERR: " + stderr);
				}
			} else {
				/* make sure we destroy the process on JVM shutdown */
				Runtime.getRuntime().addShutdownHook(new Thread() {
					public void run() {
						killProcess(p);
					}
				});
			}
			return p;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * for Windows there are a several key differnces:
	 *   1.  the command passed in to bash needs to be surrounded by quotes
	 *   2.  windows automatically appends the system path onto the linux path when invoking bash
	 *   3.  windows file paths need to be converted to work in linux (i.e. change '\' to '/' and 'c:' to '/mnt/c')
	 *   4.  Process.waitFor() never returns when the java process invokes bash and thus waitFor(timeout) is being used
	 */
	private static Process execWindows(boolean wait, String ... cmd) {
		try {
			int timeout = 15;
			if (cmd.length == 1 && !new File(cmd[0]).exists()) {
				String commandArg = "\"" + cmd[0] + "; exit\"";
				timeout = getProcessTimeout(commandArg);
				LOG.info(String.format("executing (timeout = %ds) : bash -c %s", timeout, commandArg));
				cmd = new String[]{"bash", "-c", commandArg};
			}
			ProcessBuilder builder = new ProcessBuilder(cmd);
			builder.environment().put(ENV_LOCALSTACK_PROCESS_GROUP, ENV_LOCALSTACK_PROCESS_GROUP);

			final Process p = builder.start();

			if (wait) {
				if (!p.waitFor(timeout, TimeUnit.SECONDS)) {
					LOG.info("process timeout, assume completed successfully...");
					Runtime.getRuntime().addShutdownHook(new Thread() {
						public void run() {
							killProcess(p);
						}
					});
				}
			} else {
				/* make sure we destroy the process on JVM shutdown */
				Runtime.getRuntime().addShutdownHook(new Thread() {
					public void run() {
						killProcess(p);
					}
				});
			}
			return p;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 *  these numbers are based on empirical observations with some padding added in
	 */
	private static int getProcessTimeout(String cmd) {
		int result = 15;

		if (cmd.contains("make ") && cmd.contains(" infra")) {
			result = 120;
		} else if (cmd.contains("make install")) {
			result = 300;
		} else if (cmd.contains("git clone ")) {
			result = 10;
		}

		return result;
	}

	private void setupInfrastructure() {
		synchronized (INFRA_STARTED) {
			// make sure everything is installed locally
			ensureInstallation();
			// make sure we avoid any errors related to locally generated SSL certificates
			TestUtils.disableSslCertChecking();

			// check to see if the server process is already running or created
			if (INFRA_STARTED.get() != null || isAlive()) return;

			Process proc;
			try {
				LOG.info("starting...");
				proc = exec(false, "make -C '" + getTmpInstallDir() + "' infra");
				BufferedReader r1 = new BufferedReader(new InputStreamReader(proc.getInputStream()));
				String line;
				LOG.info(getTmpInstallDir());
				LOG.info("Waiting for infrastructure to be spun up");
				boolean ready = false;
				String output = "";
				while((line = r1.readLine()) != null) {
					output += line + "\n";
					if(INFRA_READY_MARKER.equals(line)) {
						ready = true;
						break;
					}
				}
				if(!ready) {
					throw new RuntimeException("Unable to start local infrastructure. Debug output: " + output);
				}
				INFRA_STARTED.set(proc);
				LOG.info("started...");
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
	}

	/**
	 *  determine if the services are already running;  if so, this may or may not be ok - issue a warning and continue
	 */
	private static boolean isAlive() {
		boolean result = false;

		try {
			URL url = new URL(ServiceName.getServiceUrl(ServiceName.S3));

			HttpURLConnection.setFollowRedirects(false);
			HttpURLConnection connection = (HttpURLConnection)url.openConnection();
			connection.setRequestMethod("HEAD");

			int responseCode = connection.getResponseCode();
			result = responseCode == HttpURLConnection.HTTP_OK;

			if (result) {
				LOG.warning("Services already running.  Please stop the running instance if it is interfering with your tests.");
			}
		} catch (IOException e) {
			// this is ok
		}

		return result;
	}

	public static void teardownInfrastructure() {
		Process proc = INFRA_STARTED.get();
		if(proc == null) {
			return;
		}
		killProcess(proc);
		INFRA_STARTED.set(null);
	}

	public static String getDefaultRegion() {
		return TestUtils.DEFAULT_REGION;
	}
}
