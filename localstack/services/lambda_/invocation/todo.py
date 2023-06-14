# class EventManager:
#     def process_event_destinations(
#         self,
#         invocation_result: InvocationResult | InvocationError,
#         queued_invocation: QueuedInvocation,
#         last_invoke_time: Optional[datetime],
#         original_payload: bytes,
#     ) -> None:
#         """TODO refactor"""
#         LOG.debug("Got event invocation with id %s", invocation_result.request_id)
#
#         # 1. Handle DLQ routing
#         if (
#             isinstance(invocation_result, InvocationError)
#             and self.function_version.config.dead_letter_arn
#         ):
#             try:
#                 dead_letter_queue._send_to_dead_letter_queue(
#                     source_arn=self.function_arn,
#                     dlq_arn=self.function_version.config.dead_letter_arn,
#                     event=json.loads(to_str(original_payload)),
#                     error=InvocationException(
#                         message="hi", result=to_str(invocation_result.payload)
#                     ),  # TODO: check message
#                     role=self.function_version.config.role,
#                 )
#             except Exception as e:
#                 LOG.warning(
#                     "Error sending to DLQ %s: %s", self.function_version.config.dead_letter_arn, e
#                 )
#
#         # 2. Handle actual destination setup
#         event_invoke_config = self.function.event_invoke_configs.get(
#             self.function_version.id.qualifier
#         )
#
#         if event_invoke_config is None:
#             return
#
#         if isinstance(invocation_result, InvocationResult):
#             LOG.debug("Handling success destination for %s", self.function_arn)
#             success_destination = event_invoke_config.destination_config.get("OnSuccess", {}).get(
#                 "Destination"
#             )
#             if success_destination is None:
#                 return
#             destination_payload = {
#                 "version": "1.0",
#                 "timestamp": timestamp_millis(),
#                 "requestContext": {
#                     "requestId": invocation_result.request_id,
#                     "functionArn": self.function_version.qualified_arn,
#                     "condition": "Success",
#                     "approximateInvokeCount": queued_invocation.retries + 1,
#                 },
#                 "requestPayload": json.loads(to_str(original_payload)),
#                 "responseContext": {
#                     "statusCode": 200,
#                     "executedVersion": self.function_version.id.qualifier,
#                 },
#                 "responsePayload": json.loads(to_str(invocation_result.payload or {})),
#             }
#
#             target_arn = event_invoke_config.destination_config["OnSuccess"]["Destination"]
#             try:
#                 send_event_to_target(
#                     target_arn=target_arn,
#                     event=destination_payload,
#                     role=self.function_version.config.role,
#                     source_arn=self.function_version.id.unqualified_arn(),
#                     source_service="lambda",
#                 )
#             except Exception as e:
#                 LOG.warning("Error sending invocation result to %s: %s", target_arn, e)
#
#         elif isinstance(invocation_result, InvocationError):
#             LOG.debug("Handling error destination for %s", self.function_arn)
#
#             failure_destination = event_invoke_config.destination_config.get("OnFailure", {}).get(
#                 "Destination"
#             )
#
#             max_retry_attempts = event_invoke_config.maximum_retry_attempts
#             if max_retry_attempts is None:
#                 max_retry_attempts = 2  # default
#             previous_retry_attempts = queued_invocation.retries
#
#             if self.function.reserved_concurrent_executions == 0:
#                 failure_cause = "ZeroReservedConcurrency"
#                 response_payload = None
#                 response_context = None
#                 approx_invoke_count = 0
#             else:
#                 if max_retry_attempts > 0 and max_retry_attempts > previous_retry_attempts:
#                     delay_queue_invoke_seconds = config.LAMBDA_RETRY_BASE_DELAY_SECONDS * (
#                         previous_retry_attempts + 1
#                     )
#
#                     time_passed = datetime.now() - last_invoke_time
#                     enough_time_for_retry = (
#                         event_invoke_config.maximum_event_age_in_seconds
#                         and ceil(time_passed.total_seconds()) + delay_queue_invoke_seconds
#                         <= event_invoke_config.maximum_event_age_in_seconds
#                     )
#
#                     if (
#                         event_invoke_config.maximum_event_age_in_seconds is None
#                         or enough_time_for_retry
#                     ):
#                         time.sleep(delay_queue_invoke_seconds)
#                         LOG.debug("Retrying lambda invocation for %s", self.function_arn)
#                         self.invoke(
#                             invocation=queued_invocation.invocation,
#                             current_retry=previous_retry_attempts + 1,
#                         )
#                         return
#
#                     failure_cause = "EventAgeExceeded"
#                 else:
#                     failure_cause = "RetriesExhausted"
#
#                 response_payload = json.loads(to_str(invocation_result.payload))
#                 response_context = {
#                     "statusCode": 200,
#                     "executedVersion": self.function_version.id.qualifier,
#                     "functionError": "Unhandled",
#                 }
#                 approx_invoke_count = previous_retry_attempts + 1
#
#             if failure_destination is None:
#                 return
#
#             destination_payload = {
#                 "version": "1.0",
#                 "timestamp": timestamp_millis(),
#                 "requestContext": {
#                     "requestId": invocation_result.request_id,
#                     "functionArn": self.function_version.qualified_arn,
#                     "condition": failure_cause,
#                     "approximateInvokeCount": approx_invoke_count,
#                 },
#                 "requestPayload": json.loads(to_str(original_payload)),
#             }
#
#             if response_context:
#                 destination_payload["responseContext"] = response_context
#             if response_payload:
#                 destination_payload["responsePayload"] = response_payload
#
#             target_arn = event_invoke_config.destination_config["OnFailure"]["Destination"]
#             try:
#                 send_event_to_target(
#                     target_arn=target_arn,
#                     event=destination_payload,
#                     role=self.function_version.config.role,
#                     source_arn=self.function_version.id.unqualified_arn(),
#                     source_service="lambda",
#                 )
#             except Exception as e:
#                 LOG.warning("Error sending invocation result to %s: %s", target_arn, e)
#         else:
#             raise ValueError("Unknown type for invocation result received.")
