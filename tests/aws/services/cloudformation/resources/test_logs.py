import os.path

from localstack.testing.pytest import markers


@markers.aws.validated
def test_logstream(deploy_cfn_template, snapshot, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/logs_group_and_stream.yaml"
        )
    )
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.key_value("LogGroupNameOutput"))

    group_name = stack.outputs["LogGroupNameOutput"]
    stream_name = stack.outputs["LogStreamNameOutput"]

    snapshot.match("outputs", stack.outputs)

    streams = aws_client.logs.describe_log_streams(
        logGroupName=group_name, logStreamNamePrefix=stream_name
    )["logStreams"]
    assert aws_client.logs.meta.partition == streams[0]["arn"].split(":")[1]
    snapshot.match("describe_log_streams", streams)


TEST_TEMPLATE_9 = (
    """
    Parameters:
      gitBranch:
        Type: String
        Default: dev
    
    Mappings:
      AccountInfo:
        "%s":
          ID: 10000000
          ENV: dev
    
    Conditions:
      FeatureBranch:
        Fn::Equals:
          - Ref: gitBranch
          - 'dev'
    
    Resources:
      HeartbeatHandlerLogGroup:
        Type: AWS::Logs::LogGroup
        Properties:
          RetentionInDays: 1
          LogGroupName:
            Fn::Join:
              - '_'
              - - '/aws/lambda/AWS_DUB_LAM'
                - !FindInMap [ AccountInfo, !Ref "AWS::AccountId", ID ]
                - !If [ FeatureBranch, !Ref "gitBranch", !Ref "AWS::NoValue" ]
                - 'MessageFooHandler'
                - !FindInMap [ AccountInfo, !Ref "AWS::AccountId", ENV ]
    """
    % TEST_AWS_ACCOUNT_ID
)


@markers.aws.unknown
def test_cfn_handle_log_group_resource(self, deploy_cfn_template, aws_client):
    log_group_prefix = "/aws/lambda/AWS_DUB_LAM_10000000"

    stack = deploy_cfn_template(template=TEST_TEMPLATE_9)

    rs = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_prefix)
    assert len(rs["logGroups"]) == 1
    assert (
        rs["logGroups"][0]["logGroupName"]
        == "/aws/lambda/AWS_DUB_LAM_10000000_dev_MessageFooHandler_dev"
    )

    # clean up and assert deletion
    stack.destroy()
    rs = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_prefix)
    assert len(rs["logGroups"]) == 0
