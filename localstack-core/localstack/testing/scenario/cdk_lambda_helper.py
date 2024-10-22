import base64
import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

from botocore.exceptions import ClientError

from localstack.utils.aws.resources import create_s3_bucket
from localstack.utils.docker_utils import DOCKER_CLIENT
from localstack.utils.run import LOG, run

if TYPE_CHECKING:
    from mypy_boto3_ecr import ECRClient
    from mypy_boto3_s3 import S3Client


def load_python_lambda_to_s3(
    s3_client: "S3Client",
    bucket_name: str,
    key_name: str,
    code_path: str,
    additional_python_packages: list[str] = None,
):
    """
    Helper function to setup Lambdas that need additional python libs.
    Will create a temp-zip and upload in the s3 bucket.
    Installs additional libs and package with the zip

    :param s3_client: client for S3
    :param bucket_name: bucket name (bucket will be created)
    :param key_name: key name for the uploaded zip file
    :param code_path: the path to the source code that should be included
    :param additional_python_packages: a list of strings with python packages that are required to run the lambda
    :return: None
    """
    try:
        temp_dir = tempfile.mkdtemp()
        tmp_zip_path = os.path.join(tempfile.gettempdir(), "helper.zip")
        # install python packages
        if additional_python_packages:
            try:
                run(f"cd {temp_dir} && pip install {' '.join(additional_python_packages)} -t .")
            except Exception as e:
                LOG.error(
                    "Could not install additional packages %s: %s", additional_python_packages, e
                )
        # add the lambda to the directory
        _zip_lambda_resources(
            lambda_code_path=code_path,
            handler_file_name="index.py",
            resources_dir=temp_dir,
            zip_path=tmp_zip_path,
        )
        _upload_to_s3(s3_client, bucket_name=bucket_name, key_name=key_name, file=tmp_zip_path)

    finally:
        if temp_dir:
            shutil.rmtree(temp_dir)
        if tmp_zip_path and os.path.exists(tmp_zip_path):
            os.remove(tmp_zip_path)


def load_nodejs_lambda_to_s3(
    s3_client: "S3Client",
    bucket_name: str,
    key_name: str,
    code_path: str,
    additional_nodjs_packages: list[str] = None,
    additional_nodejs_packages: list[str] = None,
    additional_resources: list[str] = None,
):
    """
    Helper function to setup nodeJS Lambdas that need additional libs.
    Will create a temp-zip and upload in the s3 bucket.
    Installs additional libs and package with the zip

    :param s3_client: client for S3
    :param bucket_name: bucket name (bucket will be created)
    :param key_name: key name for the uploaded zip file
    :param code_path: the path to the source code that should be included
    :param additional_nodjs_packages: a list of strings with nodeJS packages that are required to run the lambda
    :param additional_nodejs_packages: a list of strings with nodeJS packages that are required to run the lambda
    :param additional_resources: list of path-strings to resources or internal libs that should be packaged into the lambda
    :return: None
    """
    additional_resources = additional_resources or []

    if additional_nodjs_packages:
        additional_nodejs_packages = additional_nodejs_packages or []
        additional_nodejs_packages.extend(additional_nodjs_packages)

    try:
        temp_dir = tempfile.mkdtemp()
        tmp_zip_path = os.path.join(tempfile.gettempdir(), "helper.zip")

        # Install NodeJS packages
        if additional_nodejs_packages:
            try:
                os.mkdir(os.path.join(temp_dir, "node_modules"))
                run(f"cd {temp_dir} && npm install {' '.join(additional_nodejs_packages)} ")
            except Exception as e:
                LOG.error(
                    "Could not install additional packages %s: %s", additional_nodejs_packages, e
                )

        for r in additional_resources:
            try:
                path = Path(r)
                if path.is_dir():
                    dir_name = os.path.basename(path)
                    dest_dir = os.path.join(temp_dir, dir_name)
                    shutil.copytree(path, dest_dir)
                elif path.is_file():
                    new_resource_temp_path = os.path.join(temp_dir, os.path.basename(path))
                    shutil.copy2(path, new_resource_temp_path)
            except Exception as e:
                LOG.error("Could not copy additional resources %s: %s", r, e)

        _zip_lambda_resources(
            lambda_code_path=code_path,
            handler_file_name="index.js",
            resources_dir=temp_dir,
            zip_path=tmp_zip_path,
        )
        _upload_to_s3(s3_client, bucket_name=bucket_name, key_name=key_name, file=tmp_zip_path)
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir)
        if tmp_zip_path and os.path.exists(tmp_zip_path):
            os.remove(tmp_zip_path)


def _zip_lambda_resources(
    lambda_code_path: str, handler_file_name: str, resources_dir: str, zip_path: str
):
    # add the lambda to the directory
    new_resource_temp_path = os.path.join(resources_dir, handler_file_name)
    shutil.copy2(lambda_code_path, new_resource_temp_path)

    with zipfile.ZipFile(zip_path, "w") as temp_zip:
        # Add the contents of the existing ZIP file
        for root, _, files in os.walk(resources_dir):
            for file in files:
                file_path = os.path.join(root, file)
                archive_name = os.path.relpath(file_path, resources_dir)
                temp_zip.write(file_path, archive_name)


def generate_ecr_image_from_dockerfile(
    ecr_client: "ECRClient", repository_name: str, file_path: str
):
    """
    Helper function to generate an ECR image from a dockerfile.

    :param ecr_client: client for ECR
    :param repository_name: name for the repository to be created
    :param file_path: path of the file to be used
    :return: None
    """
    repository_uri = ecr_client.create_repository(
        repositoryName=repository_name,
    )["repository"]["repositoryUri"]

    auth_response = ecr_client.get_authorization_token()
    auth_token = auth_response["authorizationData"][0]["authorizationToken"].encode()
    username, password = base64.b64decode(auth_token).decode().split(":")
    registry = auth_response["authorizationData"][0]["proxyEndpoint"]
    DOCKER_CLIENT.login(username, password, registry=registry)

    temp_dir = tempfile.mkdtemp()
    destination_file = os.path.join(temp_dir, "Dockerfile")
    shutil.copy2(file_path, destination_file)
    DOCKER_CLIENT.build_image(dockerfile_path=destination_file, image_name=repository_uri)
    DOCKER_CLIENT.push_image(repository_uri)


def generate_ecr_image_from_docker_image(
    ecr_client: "ECRClient", repository_name: str, image_name: str, platform: str = "linux/amd64"
):
    """
    Parameters
    ----------
    ecr_client
    repository_name
    image_name
    platform

    Returns
    -------

    """

    DOCKER_CLIENT.pull_image(image_name, platform=platform)

    repository_uri = ecr_client.create_repository(
        repositoryName=repository_name,
    )["repository"]["repositoryUri"]

    auth_response = ecr_client.get_authorization_token()
    auth_token = auth_response["authorizationData"][0]["authorizationToken"].encode()
    username, password = base64.b64decode(auth_token).decode().split(":")
    registry = auth_response["authorizationData"][0]["proxyEndpoint"]
    DOCKER_CLIENT.login(username, password, registry=registry)

    DOCKER_CLIENT.tag_image(image_name, repository_uri)
    DOCKER_CLIENT.push_image(repository_uri)


def _upload_to_s3(s3_client: "S3Client", bucket_name: str, key_name: str, file: str):
    try:
        create_s3_bucket(bucket_name, s3_client)
    except ClientError as exc:
        # when creating an already existing bucket, regions differ in their behavior:
        # us-east-1 will silently pass (idempotent)
        # any other region will return a `BucketAlreadyOwnedByYou` exception.
        if exc.response["Error"]["Code"] != "BucketAlreadyOwnedByYou":
            raise exc
    s3_client.upload_file(Filename=file, Bucket=bucket_name, Key=key_name)
