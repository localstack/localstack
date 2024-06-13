from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

DEFAULT_TASK_LIST = {"name": "default"}
SWF_VERSION = "1.0"


class TestSwf:
    # FIXME: This test does not clean up after itself, and does not use fixtures
    # It seems you cannot delete an AWS SWF `Domain` after its been registered, only deprecate it
    # The `Domain` resource will deprecate all `Workflow` and `Activity` it holds, so this might be useful.
    # You cannot delete `Workflow` and `Activity` if they're not deprecated first.
    @markers.aws.needs_fixing
    def test_run_workflow(self, aws_client):
        swf_client = aws_client.swf

        swf_unique_id = short_uid()
        workflow_domain_name = "test-swf-domain-{}".format(swf_unique_id)
        workflow_type_name = "test-swf-workflow-{}".format(swf_unique_id)
        workflow_activity_name = "test-swf-activity-{}".format(swf_unique_id)

        swf_client.register_domain(
            name=workflow_domain_name, workflowExecutionRetentionPeriodInDays="1"
        )

        # Given a workflow
        swf_client.register_workflow_type(
            domain=workflow_domain_name,
            name=workflow_type_name,
            version=SWF_VERSION,
            defaultExecutionStartToCloseTimeout="500",
            defaultTaskStartToCloseTimeout="300",
            defaultTaskList=DEFAULT_TASK_LIST,
            defaultChildPolicy="TERMINATE",
        )

        workflow_types = swf_client.list_workflow_types(
            domain=workflow_domain_name, registrationStatus="REGISTERED"
        )

        assert workflow_type_name in (
            workflow_type["workflowType"]["name"] for workflow_type in workflow_types["typeInfos"]
        )

        swf_client.register_activity_type(
            domain=workflow_domain_name,
            name=workflow_activity_name,
            version=SWF_VERSION,
            defaultTaskList=DEFAULT_TASK_LIST,
            defaultTaskStartToCloseTimeout="NONE",
            defaultTaskScheduleToStartTimeout="NONE",
            defaultTaskScheduleToCloseTimeout="NONE",
            defaultTaskHeartbeatTimeout="100",
        )

        # When workflow is started
        workflow_execution = swf_client.start_workflow_execution(
            domain=workflow_domain_name,
            workflowId=swf_unique_id,
            workflowType={"name": workflow_type_name, "version": SWF_VERSION},
        )

        # Then workflow components execute
        decision_task = swf_client.poll_for_decision_task(
            domain=workflow_domain_name, taskList=DEFAULT_TASK_LIST
        )
        swf_client.respond_decision_task_completed(
            taskToken=decision_task["taskToken"],
            decisions=[
                {
                    "decisionType": "ScheduleActivityTask",
                    "scheduleActivityTaskDecisionAttributes": {
                        "activityType": {
                            "name": workflow_activity_name,
                            "version": SWF_VERSION,
                        },
                        "activityId": "10",
                    },
                }
            ],
        )
        activity_task = swf_client.poll_for_activity_task(
            domain=workflow_domain_name, taskList=DEFAULT_TASK_LIST
        )
        swf_client.respond_activity_task_completed(
            taskToken=activity_task["taskToken"], result="activity success"
        )
        decision_task = swf_client.poll_for_decision_task(
            domain=workflow_domain_name, taskList=DEFAULT_TASK_LIST
        )
        swf_client.respond_decision_task_completed(
            taskToken=decision_task["taskToken"],
            decisions=[
                {
                    "decisionType": "CompleteWorkflowExecution",
                    "completeWorkflowExecutionDecisionAttributes": {"result": "workflow success"},
                }
            ],
        )

        # Then workflow history has expected events
        history = swf_client.get_workflow_execution_history(
            domain=workflow_domain_name,
            execution={
                "workflowId": swf_unique_id,
                "runId": workflow_execution["runId"],
            },
        )
        events = (event["eventType"] for event in history["events"])
        for event_type in [
            "WorkflowExecutionStarted",
            "DecisionTaskCompleted",
            "ActivityTaskCompleted",
            "WorkflowExecutionCompleted",
        ]:
            assert event_type in events
