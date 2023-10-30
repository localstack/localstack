import json
from datetime import datetime

from localstack.utils.aws.aws_models import Component
from localstack.utils.time import timestamp_millis

MAX_FUNCTION_ENVVAR_SIZE_BYTES = 4 * 1024


class InvalidEnvVars(ValueError):
    def __init__(self, envvars_string):
        self.envvars_string = envvars_string

    def __str__(self) -> str:
        return self.envvars_string


class LambdaFunction(Component):
    QUALIFIER_LATEST: str = "$LATEST"

    def __init__(self, arn):
        super(LambdaFunction, self).__init__(arn)
        self.event_sources = []
        self.targets = []
        self.versions = {}
        self.aliases = {}
        self._envvars = {}
        self.tags = {}
        self.concurrency = None
        self.runtime = None
        self.handler = None
        self.cwd = None
        self.zip_dir = None
        self.timeout = None
        self.last_modified = None
        self.vpc_config = None
        self.role = None
        self.kms_key_arn = None
        self.memory_size = None
        self.code = None
        self.dead_letter_config = None
        self.on_successful_invocation = None
        self.on_failed_invocation = None
        self.max_retry_attempts = None
        self.max_event_age = None
        self.description = ""
        self.code_signing_config_arn = None
        self.package_type = None
        self.architectures = ["x86_64"]
        self.image_config = {}
        self.tracing_config = {}
        self.state = None
        self.url_config = None

    def set_dead_letter_config(self, data):
        config = data.get("DeadLetterConfig")
        if not config:
            return
        self.dead_letter_config = config
        target_arn = config.get("TargetArn") or ""
        if ":sqs:" not in target_arn and ":sns:" not in target_arn:
            raise Exception(
                'Dead letter queue ARN "%s" requires a valid SQS queue or SNS topic' % target_arn
            )

    def get_function_event_invoke_config(self):
        response = {}

        if self.max_retry_attempts is not None:
            response["MaximumRetryAttempts"] = self.max_retry_attempts
        if self.max_event_age is not None:
            response["MaximumEventAgeInSeconds"] = self.max_event_age
        if self.on_successful_invocation or self.on_failed_invocation:
            response["DestinationConfig"] = {}
        if self.on_successful_invocation:
            response["DestinationConfig"].update(
                {"OnSuccess": {"Destination": self.on_successful_invocation}}
            )
        if self.on_failed_invocation:
            response["DestinationConfig"].update(
                {"OnFailure": {"Destination": self.on_failed_invocation}}
            )
        if not response:
            return None
        response.update(
            {
                "LastModified": timestamp_millis(self.last_modified),
                "FunctionArn": str(self.id),
            }
        )
        return response

    def clear_function_event_invoke_config(self):
        if hasattr(self, "dead_letter_config"):
            self.dead_letter_config = None
        if hasattr(self, "on_successful_invocation"):
            self.on_successful_invocation = None
        if hasattr(self, "on_failed_invocation"):
            self.on_failed_invocation = None
        if hasattr(self, "max_retry_attempts"):
            self.max_retry_attempts = None
        if hasattr(self, "max_event_age"):
            self.max_event_age = None

    def put_function_event_invoke_config(self, data):
        if not isinstance(data, dict):
            return

        updated = False
        if "DestinationConfig" in data:
            if "OnFailure" in data["DestinationConfig"]:
                dlq_arn = data["DestinationConfig"]["OnFailure"]["Destination"]
                self.on_failed_invocation = dlq_arn
                updated = True

            if "OnSuccess" in data["DestinationConfig"]:
                sq_arn = data["DestinationConfig"]["OnSuccess"]["Destination"]
                self.on_successful_invocation = sq_arn
                updated = True

        if "MaximumRetryAttempts" in data:
            try:
                max_retry_attempts = int(data["MaximumRetryAttempts"])
            except Exception:
                max_retry_attempts = 3

            self.max_retry_attempts = max_retry_attempts
            updated = True

        if "MaximumEventAgeInSeconds" in data:
            try:
                max_event_age = int(data["MaximumEventAgeInSeconds"])
            except Exception:
                max_event_age = 3600

            self.max_event_age = max_event_age
            updated = True

        if updated:
            self.last_modified = datetime.utcnow()

        return self

    def destination_enabled(self):
        return self.on_successful_invocation is not None or self.on_failed_invocation is not None

    def get_version(self, version):
        return self.versions.get(version)

    def max_version(self):
        versions = [int(key) for key in self.versions.keys() if key != self.QUALIFIER_LATEST]
        return versions and max(versions) or 0

    def name(self):
        # Example ARN: arn:aws:lambda:aws-region:acct-id:function:helloworld:1
        return self.id.split(":")[6]

    def region(self):
        return self.id.split(":")[3]

    def arn(self):
        return self.id

    def get_qualifier_version(self, qualifier: str = None) -> str:
        if not qualifier:
            qualifier = self.QUALIFIER_LATEST
        return (
            qualifier
            if qualifier in self.versions
            else self.aliases.get(qualifier).get("FunctionVersion")
        )

    def qualifier_exists(self, qualifier):
        return qualifier in self.aliases or qualifier in self.versions

    @property
    def envvars(self):
        """Get the environment variables for the function.

        When setting the environment variables, perform the following
        validations:

        - environment variables must be less than 4KiB in size
        """
        return self._envvars

    @envvars.setter
    def envvars(self, new_envvars):
        encoded_envvars = json.dumps(new_envvars, separators=(",", ":"))
        if len(encoded_envvars.encode("utf-8")) > MAX_FUNCTION_ENVVAR_SIZE_BYTES:
            raise InvalidEnvVars(encoded_envvars)

        self._envvars = new_envvars

    def __str__(self):
        return "<%s:%s>" % (self.__class__.__name__, self.name())


class CodeSigningConfig:
    def __init__(self, arn, id, signing_profile_version_arns):
        self.arn = arn
        self.id = id
        self.signing_profile_version_arns = signing_profile_version_arns
        self.description = ""
        self.untrusted_artifact_on_deployment = "Warn"
        self.last_modified = None
