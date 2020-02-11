package cloud.localstack.deprecated;

import org.junit.jupiter.api.extension.BeforeTestExecutionCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * Simple JUnit extension for JUnit 5.
 *
 * @author Patrick Allain
 */
@Deprecated
public class LocalstackExtension implements BeforeTestExecutionCallback {

    @Override
    public void beforeTestExecution(final ExtensionContext context) {
        Localstack.INSTANCE.setupInfrastructure();
    }
}
