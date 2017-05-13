package com.atlassian.localstack;

import java.io.File;
import java.nio.ByteBuffer;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.KinesisEvent;
import com.amazonaws.services.lambda.runtime.events.KinesisEvent.KinesisEventRecord;
import com.amazonaws.services.lambda.runtime.events.KinesisEvent.Record;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.Charsets;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

/**
 * Simple implementation of a Java Lambda function executor.
 *
 * @author Waldemar Hummer
 */
public class LambdaExecutor {

	@SuppressWarnings("unchecked")
	public static void main(String[] args) throws Exception {
		if(args.length < 2) {
			System.err.println("Usage: java " + LambdaExecutor.class.getSimpleName() +
					"<lambdaClass> <recordsFilePath>");
			System.exit(1);
		}

		String fileContent = readFile(args[1]);
		ObjectMapper reader = new ObjectMapper();
		@SuppressWarnings("deprecation")
		Map<String,Object> map = reader.reader(Map.class).readValue(fileContent);

		List<Map<String,Object>> records = (List<Map<String, Object>>) get(map, "Records");
		RequestHandler handler;
		Object event;


		if (records != null) {
			Class<RequestHandler<KinesisEvent, ?>> clazz = (Class<RequestHandler<KinesisEvent, ?>>) Class.forName(args[0]);
			handler = clazz.newInstance();
			KinesisEvent kinesisEvent = new KinesisEvent();
			event = kinesisEvent;
			kinesisEvent.setRecords(new LinkedList<>());
			for(Map<String,Object> record : records) {
				KinesisEventRecord r = new KinesisEventRecord();
				kinesisEvent.getRecords().add(r);
				Record kinesisRecord = new Record();
				Map<String,Object> kinesis = (Map<String, Object>) get(record, "Kinesis");
				kinesisRecord.setData(ByteBuffer.wrap(get(kinesis, "Data").toString().getBytes()));
				kinesisRecord.setPartitionKey((String) get(kinesis, "PartitionKey"));
				kinesisRecord.setApproximateArrivalTimestamp(new Date());
				r.setKinesis(kinesisRecord);
			}
		} else {
			Class<RequestHandler<?, ?>> clazz = (Class<RequestHandler<?, ?>>) Class.forName(args[0]);
			handler = clazz.newInstance();
			event = map;
		}

		Context ctx = new LambdaContext();
		handler.handleRequest(event, ctx);
	}

	private static <T> T get(Map<String,T> map, String key) {
		T result = map.get(key);
		if(result != null) {
			return result;
		}
		key = StringUtils.uncapitalize(key);
		result = map.get(key);
		if(result != null) {
			return result;
		}
		return map.get(key.toLowerCase());
	}

	private static String readFile(String file) throws Exception {
		if(!file.startsWith("/")) {
			file = System.getProperty("user.dir") + "/" + file;
		}
		return FileUtils.readFileToString(new File(file), Charsets.UTF_8);
	}

}
