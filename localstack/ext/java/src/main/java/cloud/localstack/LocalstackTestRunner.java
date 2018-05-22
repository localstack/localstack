package cloud.localstack;

import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.InitializationError;

/**
 * Simple JUnit test runner that automatically downloads, installs, starts,
 * and stops the LocalStack local cloud infrastructure components.
 *
 * Should work cross-OS, however has been only tested under Unix (Linux/MacOS).
 *
 * @author Waldemar Hummer
 * @author Patrick Allain
 */
public class LocalstackTestRunner extends BlockJUnit4ClassRunner {

    public LocalstackTestRunner(Class<?> klass) throws InitializationError {
        super(klass);
    }

    @Override
    public void run(RunNotifier notifier) {
        Localstack.INSTANCE.setupInfrastructure();
        super.run(notifier);
    }

}
