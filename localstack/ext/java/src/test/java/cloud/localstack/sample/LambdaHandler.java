package cloud.localstack.sample;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;

/**
 * Test Lambda handler class
 */
public class LambdaHandler implements RequestHandler<Object, Object> {

    @Override
    public Object handleRequest(Object event, Context context) {
        System.err.println(event);
        return event.getClass();
    }

}
