package cloud.localstack.sample;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;

import java.util.Map;

public class SQSLambdaHandler implements RequestHandler<Object, Object> {

    @Override
    public Object handleRequest(Object event, Context context) {
        if(event instanceof SQSEvent) {
            return handleRequest((SQSEvent)event, context);
        }
        return handleRequest((Map<?, ?>)event, context);
    }

    public Object handleRequest(Map<?, ?> event, Context context) {
        System.err.println("SQSMessage record: " + event);
        return "{}";
    }

    public Object handleRequest(SQSEvent event, Context context) {
        for (SQSEvent.SQSMessage message : event.getRecords()) {
            System.err.println("SQSMessage message: " + message.getBody());
        }
        return "{}";
    }

}
