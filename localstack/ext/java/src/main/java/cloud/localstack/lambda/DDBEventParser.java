package cloud.localstack.lambda;

import com.amazonaws.services.dynamodbv2.model.*;
import com.amazonaws.services.lambda.runtime.events.DynamodbEvent;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.Collectors;

import static cloud.localstack.LambdaExecutor.get;

public class DDBEventParser {

    public static DynamodbEvent parse(List<Map<String, Object>> records) {

        DynamodbEvent dynamoDbEvent = new DynamodbEvent();
        dynamoDbEvent.setRecords(new LinkedList<>());
        for (Map<String, Object> record : records) {
            DynamodbEvent.DynamodbStreamRecord r = new DynamodbEvent.DynamodbStreamRecord();
            dynamoDbEvent.getRecords().add(r);

            r.setEventSourceARN((String) get(record, "eventSourceARN"));
            r.setEventSource((String) get(record, "eventSource"));
            r.setEventName(OperationType.fromValue((String) get(record, "eventName")));
            r.setEventVersion((String) get(record, "eventVersion"));

            r.setEventID((String) get(record, "eventID"));
            r.setAwsRegion((String) get(record, "awsRegion"));
            r.setUserIdentity((Identity) get(record, "userIdentity"));

            Map<String, Object> ddbMap = (Map<String, Object>) record.get("dynamodb");

            //DynamodbEvent
            StreamRecord streamRecord = new StreamRecord();
            r.setDynamodb(streamRecord);

            Date date = (Date) get(ddbMap, "approximateCreationDateTime");
            streamRecord.setApproximateCreationDateTime(date != null ? date : new Date());

            streamRecord.setSequenceNumber(UUID.randomUUID().toString());

            streamRecord.setKeys(fromSimpleMap((Map<String, Object>) get(ddbMap, "Keys")));
            streamRecord.setNewImage(fromSimpleMap((Map<String, Object>) get(ddbMap, "NewImage")));
            streamRecord.setOldImage(fromSimpleMap((Map<String, Object>) get(ddbMap, "OldImage")));

            streamRecord.setSizeBytes(((Integer) get(ddbMap, "SizeBytes")).longValue());
            streamRecord.setStreamViewType((String) get(ddbMap, "StreamViewType"));

        }

        return dynamoDbEvent;
    }

    public static Map<String, AttributeValue> fromSimpleMap(Map<String, Object> map) {
        if(map == null) {
            return null;
        } else {
            LinkedHashMap<String, AttributeValue> result = new LinkedHashMap<>();
            map.entrySet().stream().forEach(entry ->
                    result.put(entry.getKey(),toAttributeValue(entry.getValue()))
            );

            return result;
        }
    }

    /**
     * Reads a previously created Map of Maps in cloud.localstack.LambdaExecutor into Attribute Value
     * @param value the object which is expected to be Map<String,Object>
     * @return parsed AttributeValue
     */
    public static AttributeValue toAttributeValue(Object value) {

        AttributeValue result = new AttributeValue();

        if(value instanceof Map) {
            Map.Entry<String,Object> entry = ((Map<String,Object>) value).entrySet().iterator().next();
            String key = entry.getKey();

            switch (key) {
                case "M":
                    Map<String, Object> in1 = (Map<String,Object>) entry.getValue();
                    result.setM(new LinkedHashMap<>());
                    in1.entrySet().stream().forEach(mapEntry ->
                        result.addMEntry(mapEntry.getKey(), toAttributeValue(mapEntry.getValue()))
                    );
                    break;
                case "SS":
                    result.setSS((List<String>) entry.getValue());
                    break;
                case "BS":
                    List<String> in2 = (List<String>) entry.getValue();
                    result.setBS(in2.stream()
                            .map(element -> ByteBuffer.wrap(element.getBytes()))
                            .collect(Collectors.toList()));
                    break;
                case "NS":
                    List<Object> in3 = (List<Object>) entry.getValue();
                    result.setNS(in3.stream().map(Object::toString).collect(Collectors.toList()));
                    break;
                case "L":
                    List<Object> in4 =(List<Object>) entry.getValue();
                    result.setL(in4.stream()
                            .map(el -> toAttributeValue(el))
                            .collect(Collectors.toList())
                    );
                    break;
                case "NULL":
                    result.withNULL(Boolean.parseBoolean(entry.getValue().toString()));
                    break;
                case "BOOL":
                    result.withBOOL(Boolean.parseBoolean(entry.getValue().toString()));
                    break;
                case "S":
                    result.withS((String) entry.getValue());
                    break;
                case "N":
                    String stringValue = entry.getValue().toString();
                    result.withN(stringValue);
                    break;
                case "B":
                    result.withBS(ByteBuffer.wrap(entry.getValue().toString().getBytes()));
                    break;
                default:
                    result.setM(new LinkedHashMap<>());
                    break;
            }
        }
        return result;
    }

}
