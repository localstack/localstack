package cloud.localstack.docker.exception;

public class LocalstackDockerException extends RuntimeException {

    public LocalstackDockerException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
