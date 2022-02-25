import datetime
import logging

from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import aws_stack

LOG = logging.getLogger(__name__)

# simple mock state
default_repos_per_stack = {}


# TODO: might make sense to limit this only for resources with logical id "ContainerAssetsRepository"
class ECRRepository(GenericBaseModel):
    """
    This is a mock repository to support modern CDK bootstrapping templates.
    It is not intended to be used with other ECR resources.
    """

    @staticmethod
    def cloudformation_type():
        return "AWS::ECR::Repository"

    def get_physical_resource_id(self, attribute, **kwargs):
        repo_name = self.props.get("RepositoryName")
        return aws_stack.get_ecr_repository_arn(repo_name)

    def fetch_state(self, stack_name, resources):
        repo_name = default_repos_per_stack.get(stack_name)
        if repo_name:
            return {
                "repositoryArn": aws_stack.get_ecr_repository_arn(repo_name),
                "registryId": "000000000000",
                "repositoryName": repo_name,
                "repositoryUri": "http://localhost:4566",
                "createdAt": datetime.time(),
                "imageTagMutability": "MUTABLE",
                "imageScanningConfiguration": {"scanOnPush": True},
            }
        else:
            return None

    @staticmethod
    def get_deploy_templates():
        def _create_repo(resource_id, resources, resource_type, func, stack_name):
            resource = resources[resource_id]
            default_repos_per_stack[stack_name] = resource["Properties"]["RepositoryName"]
            LOG.warning(
                "Creating a Mock ECR Repository for CloudFormation. This is only intended to be used for allowing a successful CDK bootstrap and does not provision any underlying ECR repository."
            )

        def _delete_repo(resource_id, resources, resource_type, func, stack_name):
            if default_repos_per_stack.get(stack_name):
                del default_repos_per_stack[stack_name]

        return {
            "create": {
                "function": _create_repo,
            },
            "delete": {
                "function": _delete_repo,
            },
        }
