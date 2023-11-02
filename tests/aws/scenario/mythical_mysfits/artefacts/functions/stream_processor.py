# Source adapted from: https://github.com/aws-samples/aws-modern-application-workshop/blob/python-cdk
# The code to be used as an AWS Lambda function for processing real-time
# user click records from Kinesis Firehose and adding additional attributes
# to them before they are stored in Amazon S3.
from __future__ import print_function

import base64
import json

# TODO: when properly integrating Fargate into the sample, re-add this code fetching the data through the microservices
# beware, it will need packaging then because of `requests`
# import requests
import os

import boto3

# Send a request to the Mysfits Service API that we have created in previous
# modules to retrieve all of the attributes for the included MysfitId.
# def retrieveMysfit(mysfitId):
#     apiEndpoint = os.environ['MYSFITS_API_URL'] + '/mysfits/' + str(mysfitId) # eg: 'https://ljqomqjzbf.execute-api.us-east-1.amazonaws.com/prod/'
#     mysfit = requests.get(apiEndpoint).json()
#     return mysfit


client = boto3.client("dynamodb")


# Directly fetch the data from the DynamoDB table as we don't have the Mysfits microservice yet
# source adapted from https://github.com/aws-samples/aws-modern-application-workshop/blob/python-cdk/module-5/app/service/mysfitsTableClient.py
def retrieveMysfit(mysfitId):
    # use the DynamoDB API GetItem, which gives you the ability to retrieve
    # a single item from a DynamoDB table using its unique key with super low latency.
    response = client.get_item(
        TableName=os.environ["MYSFITS_TABLE_NAME"], Key={"MysfitId": {"S": mysfitId}}
    )

    item = response["Item"]

    mysfit = {
        "mysfitId": item["MysfitId"]["S"],
        "name": item["Name"]["S"],
        "age": int(item["Age"]["N"]),
        "goodevil": item["GoodEvil"]["S"],
        "lawchaos": item["LawChaos"]["S"],
        "species": item["Species"]["S"],
        "thumbImageUri": item["ThumbImageUri"]["S"],
        "profileImageUri": item["ProfileImageUri"]["S"],
        "likes": item["Likes"]["N"],
        "adopted": item["Adopted"]["BOOL"],
    }

    return mysfit


# The below method will serve as the "handler" for the Lambda function. The
# handler is the method that AWS Lambda will invoke with events, which in this
# case will include records from the Kinesis Firehose Delivery Stream.
def processRecord(event, context):
    output = []

    # retrieve the list of records included with the event and loop through
    # them to retrieve the full list of mysfit attributes and add the additional
    # attributes that a hypothetical BI/Analyitcs team would like to analyze.
    for record in event["records"]:
        print("Processing record: " + record["recordId"])
        # kinesis firehose expects record payloads to be sent as encoded strings,
        # so we must decode the data first to retrieve the click record.
        click = json.loads(base64.b64decode(record["data"]))

        mysfitId = click["mysfitId"]
        mysfit = retrieveMysfit(mysfitId)

        enrichedClick = {
            "userId": click["userId"],
            "mysfitId": mysfitId,
            "goodevil": mysfit["goodevil"],
            "lawchaos": mysfit["lawchaos"],
            "species": mysfit["species"],
        }

        # create the output record that Kinesis Firehose will store in S3.
        output_record = {
            "recordId": record["recordId"],
            "result": "Ok",
            "data": base64.b64encode(json.dumps(enrichedClick).encode("utf-8") + b"\n").decode(
                "utf-8"
            ),
        }
        output.append(output_record)

    print("Successfully processed {} records.".format(len(event["records"])))

    # return the enriched records to Kiesis Firehose.
    return {"records": output}
