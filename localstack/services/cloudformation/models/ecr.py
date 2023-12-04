import datetime
import logging

from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import arns

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

    def fetch_state(self, stack_name, resources):
        repo_name = default_repos_per_stack.get(stack_name)
        if repo_name:
            return {
                "repositoryArn": arns.ecr_repository_arn(
                    repo_name, self.account_id, self.region_name
                ),
                "registryId": self.account_id,
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
        def _create_repo(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            default_repos_per_stack[stack_name] = resource["Properties"]["RepositoryName"]
            LOG.warning(
                "Creating a Mock ECR Repository for CloudFormation. This is only intended to be used for allowing a successful CDK bootstrap and does not provision any underlying ECR repository."
            )

        def _delete_repo(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            if default_repos_per_stack.get(stack_name):
                del default_repos_per_stack[stack_name]

        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            repo_name = resource["Properties"]["RepositoryName"]
            resource["PhysicalResourceId"] = arns.ecr_repository_arn(
                repo_name, account_id, region_name
            )

            # add in some properties required for GetAtt and Ref
            resource["Properties"]["Arn"] = arns.ecr_repository_arn(
                repo_name, account_id, region_name
            )
            resource["Properties"]["RepositoryUri"] = "http://localhost:4566"

        return {
            "create": {
                "function": _create_repo,
                "result_handler": _handle_result,
            },
            "delete": {
                "function": _delete_repo,
            },
        }
