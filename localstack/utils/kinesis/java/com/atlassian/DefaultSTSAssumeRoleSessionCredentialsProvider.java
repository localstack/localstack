package com.atlassian;

import java.util.Map;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.auth.InstanceProfileCredentialsProvider;
import com.amazonaws.auth.STSAssumeRoleSessionCredentialsProvider;
import com.amazonaws.internal.StaticCredentialsProvider;

/**
 * Custom session credentials provider that can be configured to assume a given IAM role.
 * Configure the role to assume via the following environment variables:
 * - AWS_ASSUME_ROLE_ARN : ARN of the role to assume
 * - AWS_ASSUME_ROLE_SESSION_NAME : name of the session to be used when calling assume-role
 *
 * As long lived credentials, this credentials provider attempts to uses the following:
 * - an STS token, via environment variables AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
 * - instance profile credentials provider (see Google hits for "EC2 instance metadata service")
 * 
 * TODO: Potentially we could simply use the default credentials provider to obtain the long-lived credentials.
 *
 * @author Waldemar Hummer
 */
public class DefaultSTSAssumeRoleSessionCredentialsProvider extends STSAssumeRoleSessionCredentialsProvider {

	public DefaultSTSAssumeRoleSessionCredentialsProvider() {
		super(getLongLivedCredentialsProvider(), getDefaultRoleARN(), getDefaultRoleSessionName());
	}

	private static String getDefaultRoleARN() {
		Map<String, String> env = System.getenv();
		return env.get("AWS_ASSUME_ROLE_ARN");
	}

	private static String getDefaultRoleSessionName() {
		Map<String, String> env = System.getenv();
		return env.get("AWS_ASSUME_ROLE_SESSION_NAME");
	}

	private static AWSCredentialsProvider getLongLivedCredentialsProvider() {
		Map<String, String> env = System.getenv();
		if(env.containsKey("AWS_SESSION_TOKEN")) {
			return new StaticCredentialsProvider(
				new BasicSessionCredentials(
					env.get("AWS_ACCESS_KEY_ID"),
					env.get("AWS_SECRET_ACCESS_KEY"),
					env.get("AWS_SESSION_TOKEN")));
		}
		return new InstanceProfileCredentialsProvider();
	}

	public static void main(String args[]) throws Exception {
		System.out.println(new DefaultSTSAssumeRoleSessionCredentialsProvider().getCredentials());
	}

}