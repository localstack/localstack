package com.atlassian;

import java.util.logging.Level;
import java.util.logging.Logger;

import com.amazonaws.services.lambda.runtime.ClientContext;
import com.amazonaws.services.lambda.runtime.CognitoIdentity;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;

public class LambdaContext implements Context {

	private final Logger LOG = Logger.getLogger(LambdaContext.class.getName());

	public LambdaLogger getLogger() {
		return new LambdaLogger() {
			public void log(String msg) {
				LOG.log(Level.INFO, msg);
			}
		};
	}

	public String getAwsRequestId() {
		// TODO Auto-generated method stub
		return null;
	}

	public ClientContext getClientContext() {
		// TODO Auto-generated method stub
		return null;
	}

	public String getFunctionName() {
		// TODO Auto-generated method stub
		return null;
	}

	public String getFunctionVersion() {
		// TODO Auto-generated method stub
		return null;
	}

	public CognitoIdentity getIdentity() {
		// TODO Auto-generated method stub
		return null;
	}

	public String getInvokedFunctionArn() {
		// TODO Auto-generated method stub
		return null;
	}

	public String getLogGroupName() {
		// TODO Auto-generated method stub
		return null;
	}

	public String getLogStreamName() {
		// TODO Auto-generated method stub
		return null;
	}

	public int getMemoryLimitInMB() {
		// TODO Auto-generated method stub
		return 0;
	}

	public int getRemainingTimeInMillis() {
		// TODO Auto-generated method stub
		return 0;
	}

}
