package echo;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;


import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class Handler implements RequestHandler<Map<String,String>,Map<String,String>>{

  public Map<String,String> handleRequest(Map<String,String> event, Context context) {
    return event;
  }
}
