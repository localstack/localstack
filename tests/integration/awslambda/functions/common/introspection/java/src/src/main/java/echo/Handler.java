package echo;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class ReturnValue {
    public Map<String, String> environment;
    public Map<String, String> ctx;
    public List<String> packages;

    public ReturnValue(Context context) {
        this.environment = System.getenv();
        this.ctx = new HashMap<>();
        this.ctx.put("function_name", context.getFunctionName());
        this.ctx.put("function_version", context.getFunctionVersion());
        this.ctx.put("invoked_function_arn", context.getInvokedFunctionArn());
        this.ctx.put("memory_limit_in_mb", Integer.toString(context.getMemoryLimitInMB()));
        this.ctx.put("aws_request_id", context.getAwsRequestId());
        this.ctx.put("log_group_name", context.getLogGroupName());
        this.ctx.put("log_stream_name", context.getLogStreamName());
        this.ctx.put("remaining_time_in_millis", Integer.toString(context.getRemainingTimeInMillis()));
        this.packages = new ArrayList<>();
    }
}

public class Handler implements RequestHandler<Map<String, String>, ReturnValue> {

    public ReturnValue handleRequest(Map<String, String> event, Context context) {
        return new ReturnValue(context);
    }
}
