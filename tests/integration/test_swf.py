import datetime
import unittest

from localstack.utils.aws import aws_stack

DEFAULT_TASK_LIST = {"name": "default"}


class TestSwf(unittest.TestCase):
    def setUp(self):
        self.swf_client = aws_stack.create_external_boto_client("swf")

        self.swf_unique_id = datetime.datetime.now().isoformat()
        self.swf_version = "1.0"
        self.workflow_domain_name = "unit-test-swf-domain-{}".format(self.swf_unique_id)
        self.workflow_type_name = "unit-test-swf-workflow-{}".format(self.swf_unique_id)
        self.workflow_activity_name = "unit-test-swf-activity-{}".format(self.swf_unique_id)
        self.swf_client.register_domain(
            name=self.workflow_domain_name, workflowExecutionRetentionPeriodInDays="1"
        )

    def test_run_workflow(self):
        self.given_workflow()
        self.when_workflow_is_started()
        self.then_workflow_components_execute()
        self.then_workflow_history_has_expected_events()

    def given_workflow(self):
        self.swf_client.register_workflow_type(
            domain=self.workflow_domain_name,
            name=self.workflow_type_name,
            version=self.swf_version,
            defaultExecutionStartToCloseTimeout="500",
            defaultTaskStartToCloseTimeout="300",
            defaultTaskList=DEFAULT_TASK_LIST,
            defaultChildPolicy="TERMINATE",
        )
        workflow_types = self.swf_client.list_workflow_types(
            domain=self.workflow_domain_name, registrationStatus="REGISTERED"
        )
        self.assertIn(
            self.workflow_type_name,
            map(
                lambda workflow_type: workflow_type["workflowType"]["name"],
                workflow_types["typeInfos"],
            ),
        )
        self.swf_client.register_activity_type(
            domain=self.workflow_domain_name,
            name=self.workflow_activity_name,
            version=self.swf_version,
            defaultTaskList=DEFAULT_TASK_LIST,
            defaultTaskStartToCloseTimeout="NONE",
            defaultTaskScheduleToStartTimeout="NONE",
            defaultTaskScheduleToCloseTimeout="NONE",
            defaultTaskHeartbeatTimeout="100",
        )

    def when_workflow_is_started(self):
        self.workflow_execution = self.swf_client.start_workflow_execution(
            domain=self.workflow_domain_name,
            workflowId=self.swf_unique_id,
            workflowType={"name": self.workflow_type_name, "version": self.swf_version},
        )

    def then_workflow_components_execute(self):
        decision_task = self.swf_client.poll_for_decision_task(
            domain=self.workflow_domain_name, taskList=DEFAULT_TASK_LIST
        )
        self.swf_client.respond_decision_task_completed(
            taskToken=decision_task["taskToken"],
            decisions=[
                {
                    "decisionType": "ScheduleActivityTask",
                    "scheduleActivityTaskDecisionAttributes": {
                        "activityType": {
                            "name": self.workflow_activity_name,
                            "version": self.swf_version,
                        },
                        "activityId": "10",
                    },
                }
            ],
        )
        activity_task = self.swf_client.poll_for_activity_task(
            domain=self.workflow_domain_name, taskList=DEFAULT_TASK_LIST
        )
        self.swf_client.respond_activity_task_completed(
            taskToken=activity_task["taskToken"], result="activity success"
        )
        decision_task = self.swf_client.poll_for_decision_task(
            domain=self.workflow_domain_name, taskList=DEFAULT_TASK_LIST
        )
        self.swf_client.respond_decision_task_completed(
            taskToken=decision_task["taskToken"],
            decisions=[
                {
                    "decisionType": "CompleteWorkflowExecution",
                    "completeWorkflowExecutionDecisionAttributes": {"result": "workflow success"},
                }
            ],
        )

    def then_workflow_history_has_expected_events(self):
        history = self.swf_client.get_workflow_execution_history(
            domain=self.workflow_domain_name,
            execution={
                "workflowId": self.swf_unique_id,
                "runId": self.workflow_execution["runId"],
            },
        )
        events = map(lambda event: event["eventType"], history["events"])
        for event_type in [
            "WorkflowExecutionStarted",
            "DecisionTaskCompleted",
            "ActivityTaskCompleted",
            "WorkflowExecutionCompleted",
        ]:
            self.assertIn(event_type, events)
