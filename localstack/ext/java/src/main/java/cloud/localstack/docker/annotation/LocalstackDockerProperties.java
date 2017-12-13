package cloud.localstack.docker.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * An annotation to provide parameters to the LocalstackDockerTestRunner
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface LocalstackDockerProperties {

    Class<? extends IHostNameResolver> hostNameResolver();
}

