package cloud.localstack.sample;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.KinesisEvent;

/**
 * Test Lambda handler class triggered from a Kinesis event
 */
public class KinesisLambdaHandler implements RequestHandler<KinesisEvent, Object> {

	@Override
	public Object handleRequest(KinesisEvent event, Context context) {
		for (KinesisEvent.KinesisEventRecord rec : event.getRecords()) {
			String msg = new String(rec.getKinesis().getData().array());
			System.err.println("Kinesis record: " + msg);
		}
		return "{}";
	}

}
