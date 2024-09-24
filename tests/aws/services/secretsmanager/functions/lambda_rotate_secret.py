# Adepted from: https://github.com/aws-samples/aws-secrets-manager-rotation-lambdas/blob/252449551d58075f353444743e81a8c56d9f96db/SecretsManagerRotationTemplate/lambda_function.py
# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import logging
import os
from urllib.parse import urlparse

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)


# Returns the secret string used to update the version of the secret to version bounded to the
# provided secret id.
def secret_of_rotation_from_version_id(version_id: str) -> str:
    return f"lambda_rotate_secret_rotation_{version_id}"


# Returns the SecretId used when signalling that a ResourceNotFoundException was received when
# requesting the secret value for a pending secret version during create_secret stage.
# The version_id given represents the version_id of the current secret value after rotation.
def secret_signal_resource_not_found_exception_on_create(version_id: str) -> str:
    return f"ResourceNotFoundException_{version_id}"


def handler(event, context):
    """Secrets Manager Rotation Template

    This is a template for creating an AWS Secrets Manager rotation lambda

    Args:
        event (dict): Lambda dictionary of event parameters. These keys must include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)

        context (LambdaContext): The Lambda runtime information

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not properly configured for rotation

        KeyError: If the event parameters do not contain the expected keys

    """
    # Client setup.
    region = os.environ["AWS_REGION"]
    endpoint_url = os.environ.get("AWS_ENDPOINT_URL")

    if endpoint_url:
        verify = urlparse(endpoint_url).scheme == "https"
        service_client = boto3.client(
            "secretsmanager", endpoint_url=endpoint_url, verify=verify, region_name=region
        )
    else:
        service_client = boto3.client("secretsmanager", region_name=region)

    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)

    if not metadata["RotationEnabled"]:
        logger.error("Secret %s is not enabled for rotation", arn)
        raise ValueError(f"Secret {arn} is not enabled for rotation")
    #
    versions = metadata["VersionIdsToStages"]
    if token not in versions:
        logger.error("Secret version %s has no stage for rotation of secret %s.", token, arn)
        raise ValueError(f"Secret version {token} has no stage for rotation of secret {arn}.")
    if "AWSCURRENT" in versions[token]:
        logger.info("Secret version %s already set as AWSCURRENT for secret %s.", token, arn)
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error(
            "Secret version %s not set as AWSPENDING for rotation of secret %s.", token, arn
        )
        raise ValueError(
            f"Secret version {token} not set as AWSPENDING for rotation of secret {arn}."
        )

    if step == "createSecret":
        create_secret(service_client, arn, token)

    elif step == "setSecret":
        set_secret(service_client, arn, token)

    elif step == "testSecret":
        test_secret(service_client, arn, token)

    elif step == "finishSecret":
        finish_secret(service_client, arn, token)

    else:
        raise ValueError("Invalid step parameter")


def create_secret(service_client, arn, token):
    """Create the secret

    This method first checks for the existence of a secret for the passed in token. If one does not exist, it will generate a
    new secret and put it with the passed in token.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

    """
    # Make sure the current secret exists
    service_client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")

    # Now try to get the secret version, if that fails, put a new secret
    try:
        service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        logger.info("createSecret: Successfully retrieved secret for %s.", arn)
    except service_client.exceptions.ResourceNotFoundException:
        # Signal the correct exception was triggered during create_secret stage.
        sig_exception = secret_signal_resource_not_found_exception_on_create(token)
        service_client.create_secret(Name=sig_exception, SecretString=sig_exception)

        # Generate a random password
        passwd = secret_of_rotation_from_version_id(token)

        # Put the secret
        service_client.put_secret_value(
            SecretId=arn,
            ClientRequestToken=token,
            SecretString=passwd,
            VersionStages=["AWSPENDING"],
        )
        logger.info(
            "createSecret: Successfully put secret for ARN %s and version %s with passwd %s.",
            arn,
            token,
            passwd,
        )


def set_secret(service_client, arn, token):
    """Set the secret

    This method should set the AWSPENDING secret in the service that the secret belongs to. For example, if the secret is a database
    credential, this method should take the value of the AWSPENDING secret and set the user's password to this value in the database.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    """
    logger.info("lambda_rotate_secret: set_secret not implemented.")


def test_secret(service_client, arn, token):
    """Test the secret

    This method should validate that the AWSPENDING secret works in the service that the secret belongs to. For example, if the secret
    is a database credential, this method should validate that the user can login with the password in AWSPENDING and that the user has
    all of the expected permissions against the database.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    """
    logger.info("lambda_rotate_secret: test_secret not implemented.")


def finish_secret(service_client, arn, token):
    """Finish the secret

    This method finalizes the rotation process by marking the secret version passed in as the AWSCURRENT secret.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn does not exist

    """
    # First describe the secret to get the current version
    metadata = service_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info(
                    "finishSecret: Version %s already marked as AWSCURRENT for %s", version, arn
                )
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(
        SecretId=arn,
        VersionStage="AWSCURRENT",
        MoveToVersionId=token,
        RemoveFromVersionId=current_version,
    )
    logger.info(
        "finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s.",
        token,
        arn,
    )
