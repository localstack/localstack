package com.atlassian.localstack.sample;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.KinesisEvent;

/**
 * Test Kinesis handler class
 */
public class KinesisHandler implements RequestHandler<KinesisEvent, Object> {

    @Override
    public Object handleRequest(KinesisEvent kinesisEvent, Context context) {
        System.out.println(kinesisEvent);
        return "done";
    }

}
