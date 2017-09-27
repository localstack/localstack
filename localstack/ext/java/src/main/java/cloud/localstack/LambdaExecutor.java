package cloud.localstack;

import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.amazonaws.services.lambda.runtime.events.SNSEvent;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.KinesisEvent;
import com.amazonaws.services.lambda.runtime.events.KinesisEvent.KinesisEventRecord;
import com.amazonaws.services.lambda.runtime.events.KinesisEvent.Record;
import com.amazonaws.util.StringInputStream;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.Charsets;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;

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
					" <lambdaClass> <recordsFilePath>");
			System.exit(1);
		}

		String fileContent = readFile(args[1]);
		ObjectMapper reader = new ObjectMapper();
		@SuppressWarnings("deprecation")
		Map<String,Object> map = reader.reader(Map.class).readValue(fileContent);

		List<Map<String,Object>> records = (List<Map<String, Object>>) get(map, "Records");
		@SuppressWarnings("rawtypes")
		Object inputObject = map;

		if (records != null) {
			if (records.stream().filter(record -> record.containsKey("Kinesis")).count() > 0) {
				KinesisEvent kinesisEvent = new KinesisEvent();
				inputObject = kinesisEvent;
				kinesisEvent.setRecords(new LinkedList<>());
				for (Map<String, Object> record : records) {
					KinesisEventRecord r = new KinesisEventRecord();
					kinesisEvent.getRecords().add(r);
					Record kinesisRecord = new Record();
					Map<String, Object> kinesis = (Map<String, Object>) get(record, "Kinesis");
				String dataString = new String(get(kinesis, "Data").toString().getBytes());
				byte[] decodedData = Base64.getDecoder().decode(dataString);
				kinesisRecord.setData(ByteBuffer.wrap(decodedData));
					kinesisRecord.setPartitionKey((String) get(kinesis, "PartitionKey"));
					kinesisRecord.setApproximateArrivalTimestamp(new Date());
					r.setKinesis(kinesisRecord);
				}
			} else if (records.stream().filter(record -> record.containsKey("Sns")).count() > 0) {
				SNSEvent snsEvent = new SNSEvent();
				inputObject = snsEvent;
				snsEvent.setRecords(new LinkedList<>());
				for (Map<String, Object> record : records) {
					SNSEvent.SNSRecord r = new SNSEvent.SNSRecord();
					snsEvent.getRecords().add(r);
					SNSEvent.SNS snsRecord = new SNSEvent.SNS();
					Map<String, Object> sns = (Map<String, Object>) get(record, "Sns");
					snsRecord.setMessage((String) get(sns, "Message"));
					snsRecord.setMessageAttributes((Map<String, SNSEvent.MessageAttribute>) get(sns, "MessageAttributes"));
					snsRecord.setType("Notification");
					snsRecord.setTimestamp(new DateTime());
					r.setSns(snsRecord);
				}
			}
			//TODO: Support other events (S3, SQS...)
		}

		Object handler = getHandler(args[0]);
		Context ctx = new LambdaContext();
		if (handler instanceof RequestHandler) {
			Object result = ((RequestHandler) handler).handleRequest(inputObject, ctx);
			// The contract with lambci is to print the result to stdout, whereas logs go to stderr
			System.out.println(result);
		} else if (handler instanceof RequestStreamHandler) {
			OutputStream os = new ByteArrayOutputStream();
			((RequestStreamHandler) handler).handleRequest(
				new StringInputStream(fileContent), os, ctx);
			System.out.println(os);
		}
	}

	private static Object getHandler(String handlerName) throws NoSuchMethodException, IllegalAccessException,
		InvocationTargetException, InstantiationException, ClassNotFoundException {
		Class<?> clazz = Class.forName(handlerName);
		return clazz.getConstructor().newInstance();
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
