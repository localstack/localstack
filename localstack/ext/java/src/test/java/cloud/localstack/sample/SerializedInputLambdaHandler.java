package cloud.localstack.sample;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;

/**
 * Test Lambda handler class
 */
public class SerializedInputLambdaHandler implements RequestHandler<SerializedInputLambdaHandler.S3Input, Object> {

    @Override
    public Object handleRequest(S3Input input, Context context) {
        System.err.println(input);
        input.setValidated(true);
        return input;
    }

    public static class S3Input {

        public S3Input() {}

        private String bucket;

        private String key;

        private boolean validated = false;

        public String getBucket() {
            return bucket;
        }

        public void setBucket(String bucket) {
            this.bucket = bucket;
        }

        public String getKey() {
            return key;
        }

        public void setKey(String key) {
            this.key = key;
        }

        public void setValidated(boolean validated) {
            this.validated = validated;
        }

        public boolean isValidated() {
            return validated;
        }
    }
}
