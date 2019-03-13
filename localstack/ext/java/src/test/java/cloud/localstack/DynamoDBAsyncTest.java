package cloud.localstack;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDBAsync;
import com.amazonaws.services.dynamodbv2.model.AttributeDefinition;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.CreateTableRequest;
import com.amazonaws.services.dynamodbv2.model.CreateTableResult;
import com.amazonaws.services.dynamodbv2.model.KeySchemaElement;
import com.amazonaws.services.dynamodbv2.model.KeyType;
import com.amazonaws.services.dynamodbv2.model.ListTablesResult;
import com.amazonaws.services.dynamodbv2.model.ProvisionedThroughput;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;
import com.amazonaws.services.dynamodbv2.model.PutItemResult;
import com.amazonaws.services.dynamodbv2.model.QueryRequest;
import com.amazonaws.services.dynamodbv2.model.QueryResult;

import org.assertj.core.api.Assertions;
import org.junit.Assert;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testcontainers.shaded.com.google.common.collect.Lists;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import cloud.localstack.docker.LocalstackDockerExtension;
import cloud.localstack.util.PromiseAsyncHandler;

/**
 * Test integration of DynamoDB
 */
@ExtendWith(LocalstackDockerExtension.class)
public class DynamoDBAsyncTest {

    public static final String ID_TENANT_VALUE = "1-CKNP";
    public static final String TRACK_DATE_VALUE = "2019-02-20T17:18:59.703474Z";
    public static final String ID_TENANT = "id_tenant";
    public static final String TRACK_DATE = "track_date";
    public static final String ATTRIBUTE_TYPE_S = "S";
    private final String DYNAMODB_TABLE_NAME = "DYNAMODB_TABLE_NAME";


    @org.junit.jupiter.api.Test
    public void createTableAndPutItem() throws InterruptedException, ExecutionException, TimeoutException {
        AmazonDynamoDBAsync clientDynamoDb = TestUtils.getClientDynamoDBAsync();

        ListTablesResult tablesResult = clientDynamoDb.listTables();
        Assertions.assertThat(tablesResult.getTableNames()).hasSize(0);

        final PromiseAsyncHandler<CreateTableRequest, CreateTableResult> promiseCreateTable = createTable(clientDynamoDb);

        final CompletableFuture<PutItemResult> promissePutItem = promiseCreateTable.thenCompose(createTableResult -> {
            Assertions.assertThat(createTableResult.getTableDescription().getTableName()).contains(DYNAMODB_TABLE_NAME);
            return putItem(clientDynamoDb);
        });

        final CompletableFuture<QueryResult> queryResultCompletableFuture = promissePutItem.thenCompose(putItemResult -> queryByIdTenant(clientDynamoDb));

        final CompletableFuture<List<Map<String, AttributeValue>>> listCompletableFuture = queryResultCompletableFuture.thenApply(e -> e.getItems());


        final List<Map<String, AttributeValue>> maps = listCompletableFuture.get(5, TimeUnit.SECONDS);

        Assert.assertEquals(1, maps.size());
        Assert.assertEquals("[{id_tenant={S: 1-CKNP,}, track_date={S: 2019-02-20T17:18:59.703474Z,}}]",
            maps.toString());

    }

    private PromiseAsyncHandler<QueryRequest, QueryResult> queryByIdTenant(final AmazonDynamoDBAsync clientDynamoDb) {
        Map<String, AttributeValue> key = Collections.singletonMap(":id_tenant", new AttributeValue(ID_TENANT_VALUE));

        QueryRequest queryRequest = new QueryRequest().withTableName(DYNAMODB_TABLE_NAME)
                .withKeyConditionExpression("id_tenant = :id_tenant")
                .withExpressionAttributeValues(key);

        final PromiseAsyncHandler<QueryRequest, QueryResult> promisseQuery = new PromiseAsyncHandler<>();
        clientDynamoDb.queryAsync(queryRequest, promisseQuery);

        return promisseQuery;
    }

    private PromiseAsyncHandler<PutItemRequest, PutItemResult> putItem(final AmazonDynamoDBAsync clientDynamoDb) {
        Map<String, AttributeValue> item = new HashMap<>();
        item.put(ID_TENANT, new AttributeValue(ID_TENANT_VALUE));
        item.put(TRACK_DATE, new AttributeValue(TRACK_DATE_VALUE));

        final PromiseAsyncHandler<PutItemRequest, PutItemResult> promisePutItem = new PromiseAsyncHandler<>();
        clientDynamoDb.putItemAsync(DYNAMODB_TABLE_NAME, item, promisePutItem);

        return promisePutItem;
    }

    private PromiseAsyncHandler<CreateTableRequest, CreateTableResult> createTable(final AmazonDynamoDBAsync clientDynamoDb) {

        ArrayList<AttributeDefinition> attributeDefinitions =
            Lists.newArrayList(new AttributeDefinition(ID_TENANT, ATTRIBUTE_TYPE_S),
                new AttributeDefinition(TRACK_DATE, ATTRIBUTE_TYPE_S));

        final ArrayList<KeySchemaElement> keySchemaElements =
            Lists.newArrayList(new KeySchemaElement(ID_TENANT, KeyType.HASH),
                new KeySchemaElement(TRACK_DATE, KeyType.RANGE));

        CreateTableRequest request = new CreateTableRequest().withTableName(DYNAMODB_TABLE_NAME)
                .withAttributeDefinitions(attributeDefinitions)
                .withKeySchema(keySchemaElements)
                .withProvisionedThroughput(new ProvisionedThroughput(Long.valueOf(1), Long.valueOf(1)));

        final PromiseAsyncHandler<CreateTableRequest, CreateTableResult> promiseCreateTable =
            new PromiseAsyncHandler<>();

        clientDynamoDb.createTableAsync(request, promiseCreateTable);

        return promiseCreateTable;
    }

}
