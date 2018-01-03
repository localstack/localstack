package cloud.localstack;

import cloud.localstack.lambda.DDBEventParser;
import com.amazonaws.services.lambda.runtime.events.DynamodbEvent;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.Assert;
import org.junit.Test;

import java.util.*;

import static cloud.localstack.LambdaExecutor.readFile;
import static cloud.localstack.LambdaExecutor.get;

public class DDBEventMappingTest {

    static String fileName = "src/test/resources/DDBEventLambda.json";

    @Test
    public void testParseDDBEvent() throws Exception {
        String fileContent = readFile(fileName);

        ObjectMapper reader = new ObjectMapper();
        @SuppressWarnings("deprecation")
        Map<String,Object> map = reader.reader(Map.class).readValue(fileContent);

        List<Map<String,Object>> records = (List<Map<String, Object>>) get(map, "Records");

        DynamodbEvent ddbEvent = DDBEventParser.parse(records);

        DynamodbEvent.DynamodbStreamRecord record = ddbEvent.getRecords().iterator().next();


        Assert.assertTrue("The map must be empty", record.getDynamodb().getOldImage().isEmpty());
        Assert.assertEquals("The numbers must match",record.getDynamodb().getNewImage().get("number").getN(), "1" );
        Assert.assertArrayEquals("The set must match",
                record.getDynamodb().getNewImage().get("numbers").getNS().toArray(), Arrays.asList("1","3","5","6").toArray());
    }
}
