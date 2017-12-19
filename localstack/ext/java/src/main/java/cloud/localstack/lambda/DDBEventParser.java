package cloud.localstack.lambda;

import cloud.localstack.LambdaExecutor;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.Identity;
import com.amazonaws.services.dynamodbv2.model.OperationType;
import com.amazonaws.services.dynamodbv2.model.StreamRecord;
import com.amazonaws.services.lambda.runtime.events.DynamodbEvent;

import java.nio.ByteBuffer;
import java.util.*;


public class DDBEventParser extends LambdaExecutor {

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

            streamRecord.setSequenceNumber((String) get(ddbMap, "SequenceNumber"));

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
            LinkedHashMap result = new LinkedHashMap();
            Iterator var2 = map.entrySet().iterator();

            while(var2.hasNext()) {
                Map.Entry entry = (Map.Entry)var2.next();
                result.put(entry.getKey(), toAttributeValue(entry.getValue()));
            }

            return result;
        }
    }


    public static AttributeValue toAttributeValue(Object value) {

        AttributeValue result = new AttributeValue();

        if(value instanceof Map){
            Map.Entry entry = (Map.Entry)((Map) value).entrySet().iterator().next();
            String key = (String)entry.getKey();
          if(key.equals("M")) {

              Map in2 = (Map)entry.getValue();
              if(in2.size() > 0) {
                  Iterator out2 = in2.entrySet().iterator();

                  while(out2.hasNext()) {
                      Map.Entry e2 = (Map.Entry)out2.next();
                      result.addMEntry((String)e2.getKey(), toAttributeValue(e2.getValue()));
                  }
              } else {
                  result.setM(new LinkedHashMap());
              }
          }
          else if(key.equals("SS")) {
               List in = (List)entry.getValue();
               result.setSS(in);
          }
          else if(key.equals("BS")) {
              List in = (List) entry.getValue();
              Set<ByteBuffer> out = new HashSet<>();
              Iterator outIt = in.iterator();
              while(outIt.hasNext()) {
                  byte[] buf1 = outIt.next().toString().getBytes();
                  out.add(ByteBuffer.wrap(buf1));
              }
              result.setBS(out);
          }
          else if(key.equals("NS")) {
              List in1 = (List)entry.getValue();
              ArrayList out1 = new ArrayList();
              Iterator e1 = in1.iterator();
              while(e1.hasNext()) {
                  String v1 =  e1.next().toString();
                  out1.add(v1);
              }
              result.setNS(out1);
          } else if(key.equals("L")) {
              List in1 = (List)entry.getValue();
              ArrayList out1 = new ArrayList();
              Iterator e1 = in1.iterator();
              while(e1.hasNext()) {
                  Object v1 = e1.next();
                  out1.add(toAttributeValue(v1));
              }
              result.setL(out1);
          } else if(key.equals("NULL")) {
              result.withNULL(Boolean.parseBoolean(entry.getValue().toString()));
          }
          else if(key.equals("BOOL")) {
              result.withBOOL(Boolean.parseBoolean(entry.getValue().toString()));
          } else if(key.equals("S")) {
             result.withS((String)entry.getValue());
          } else if(key.equals("N")) {
             String stringValue = entry.getValue().toString();
             result.withN(stringValue);
          } else if(key.equals("B")) {
             result.withBS(ByteBuffer.wrap(entry.getValue().toString().getBytes()));
          } else {
              result.setM(new LinkedHashMap());
          }
        }

        return result;
    }

}
