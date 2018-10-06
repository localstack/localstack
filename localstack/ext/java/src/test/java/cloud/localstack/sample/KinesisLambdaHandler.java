package cloud.localstack.sample;

import java.util.Map;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.KinesisEvent;

/**
 * Test Lambda handler class triggered from a Kinesis event
 */
public class KinesisLambdaHandler implements RequestHandler<Object, Object> {

	@Override
	public Object handleRequest(Object event, Context context) {
		if(event instanceof KinesisEvent) {
			return handleRequest((KinesisEvent)event, context);
		}
		return handleRequest((Map<?, ?>)event, context);
	}

	public Object handleRequest(Map<?, ?> event, Context context) {
		System.err.println("Kinesis record: " + event);
		return "{}";
	}

	public Object handleRequest(KinesisEvent event, Context context) {
		for (KinesisEvent.KinesisEventRecord rec : event.getRecords()) {
			String msg = new String(rec.getKinesis().getData().array());
			System.err.println("Kinesis record: " + msg);
		}
		return "{}";
	}

}
