package cloud.localstack.deprecated;

import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.InitializationError;

/**
 * Simple JUnit test runner that automatically downloads, installs, starts,
 * and stops the LocalStack local cloud infrastructure components.
 *
 * Should work cross-OS, however has been only tested under Unix (Linux/MacOS).
 *
 * Update 2019-12-07: This test runner has now been deprecated. The main reason is that
 * it attempts to install various dependencies on the local machine, which frequently
 * causes issues for users running in different OSs or environments. Please use the
 * Docker-based test running instead, which is now the default.
 *
 * @author Waldemar Hummer
 * @author Patrick Allain
 */
@Deprecated
public class LocalstackOutsideDockerTestRunner extends BlockJUnit4ClassRunner {

    public LocalstackOutsideDockerTestRunner(Class<?> klass) throws InitializationError {
        super(klass);
    }

    @Override
    public void run(RunNotifier notifier) {
        Localstack.INSTANCE.setupInfrastructure();
        super.run(notifier);
    }

}
