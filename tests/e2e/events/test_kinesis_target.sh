#!/bin/bash

EVENT_BUS_NAME="test-event-bus"
EVENT_RULE_NAME="test-rule"
EVENT_RULE_CUSTOM_PARTITION_KEY="$.detail-type"
KINESIS_STREAM_NAME="test-stream"

SAMPLE_EVENTS='[{
  "Time": "2021-04-21T19:08:27.425Z",
  "Source": "com.localstack",
  "Resources": [],
  "DetailType": "myDetailType",
  "Detail": "{}",
  "EventBusName": "'$EVENT_BUS_NAME'"
}]'

KINESIS_TARGET='{
  "Id": "TargetId",
  "Arn": "arn:aws:kinesis:us-east-1:000000000000:stream/'$KINESIS_STREAM_NAME'",
  "KinesisParameters": {
    "PartitionKeyPath": "'$EVENT_RULE_CUSTOM_PARTITION_KEY'"
  }
}'

function assert_eq {
  ACTUAL_VAL=$1;
  EXPECTED_VAL=$2;

  if [[ "$ACTUAL_VAL" != "$EXPECTED_VAL" ]]; then
    echo "Expected $EXPECTED_VAL but got $ACTUAL_VAL";
    exit 1;
  fi
}

function assert_matches {
  ACTUAL_VAL=$1;
  REGEX=$2;

  if ! [[ "$ACTUAL_VAL" =~ $REGEX ]]; then
    echo "Expected $ACTUAL_VAL to match $REGEX";
    exit 1;
  fi
}

awslocal events create-event-bus --name "$EVENT_BUS_NAME";
awslocal events put-rule --name "$EVENT_RULE_NAME" --event-bus-name "$EVENT_BUS_NAME";
awslocal kinesis create-stream --stream-name "$KINESIS_STREAM_NAME" --shard-count 1;
awslocal events put-targets --rule "$EVENT_RULE_NAME" --event-bus-name "$EVENT_BUS_NAME" --targets "$KINESIS_TARGET";
awslocal events put-events --entries "$SAMPLE_EVENTS";

SHARD_ID=$(awslocal kinesis describe-stream --stream-name "$KINESIS_STREAM_NAME" | jq -r .StreamDescription.Shards[0].ShardId);
SHARD_ITERATOR=$(awslocal kinesis get-shard-iterator --stream-name "$KINESIS_STREAM_NAME" --shard-id "$SHARD_ID" --shard-iterator-type AT_TIMESTAMP --timestamp "2000-01-01" | jq -r .ShardIterator);
KINESIS_RECORD=$(awslocal kinesis get-records --shard-iterator "$SHARD_ITERATOR" | jq .Records[0]);
KINESIS_RECORD_PARTITION_KEY=$(echo "$KINESIS_RECORD" | jq -r .PartitionKey);
KINESIS_RECORD_DATA=$(echo "$KINESIS_RECORD" | jq -r .Data | base64 --decode);

assert_eq "$KINESIS_RECORD_PARTITION_KEY" "myDetailType";
assert_matches "$KINESIS_RECORD_DATA" '"detail-type": "myDetailType"';

echo "All Good!";
