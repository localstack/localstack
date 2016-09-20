package com.atlassian;

import java.util.Map;

import com.amazonaws.auth.STSAssumeRoleSessionCredentialsProvider;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;

public class DefaultSTSAssumeRoleSessionCredentialsProvider extends STSAssumeRoleSessionCredentialsProvider {

	public DefaultSTSAssumeRoleSessionCredentialsProvider() {
		super(getDefaultCredentials(), getDefaultRoleARN(), getDefaultRoleSessionName());
	}

	private static String getDefaultRoleARN() {
		Map<String, String> env = System.getenv();
		return env.get("AWS_ASSUME_ROLE_ARN");
	}

	private static String getDefaultRoleSessionName() {
		Map<String, String> env = System.getenv();
		return env.get("AWS_ASSUME_ROLE_SESSION_NAME");
	}

	private static AWSCredentials getDefaultCredentials() {
		Map<String, String> env = System.getenv();
		if(env.containsKey("AWS_SESSION_TOKEN")) {
			return new BasicSessionCredentials(
				env.get("AWS_ACCESS_KEY_ID"),
				env.get("AWS_SECRET_ACCESS_KEY"),
				env.get("AWS_SESSION_TOKEN"));
		}
		return new BasicAWSCredentials(
				env.get("AWS_ACCESS_KEY_ID"),
				env.get("AWS_SECRET_ACCESS_KEY"));
	}

}