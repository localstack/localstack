# LocalStack Resource Provider Scaffolding v2
from __future__ import annotations

from pathlib import Path
from typing import Optional, TypedDict

import hashlib
import localstack.services.cloudformation.provider_utils as util
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)


class EC2KeyPairProperties(TypedDict):
    KeyName: Optional[str]
    KeyFingerprint: Optional[str]
    KeyFormat: Optional[str]
    KeyPairId: Optional[str]
    KeyType: Optional[str]
    PublicKeyMaterial: Optional[str]
    Tags: Optional[list[Tag]]


class Tag(TypedDict):
    Key: Optional[str]
    Value: Optional[str]


REPEATED_INVOCATION = "repeated_invocation"


class EC2KeyPairProvider(ResourceProvider[EC2KeyPairProperties]):
    TYPE = "AWS::EC2::KeyPair"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def calculate_fingerprint(self, key_material: str, key_type: str) -> str:
        if key_type.lower() in ["ed25519", "ecdsa"]:
            return hashlib.sha256(key_material.encode()).hexdigest()
        else:
            return hashlib.md5(key_material.encode()).hexdigest()

    def create(
        self,
        request: ResourceRequest[EC2KeyPairProperties],
    ) -> ProgressEvent[EC2KeyPairProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/KeyName

        Required properties:
          - KeyName

        Create-only properties:
          - /properties/KeyName
          - /properties/KeyType
          - /properties/KeyFormat
          - /properties/PublicKeyMaterial
          - /properties/Tags

        Read-only properties:
          - /properties/KeyPairId
          - /properties/KeyFingerprint

        IAM permissions required:
          - ec2:CreateKeyPair
          - ec2:ImportKeyPair
          - ec2:CreateTags
          - ssm:PutParameter

        """
        model = request.desired_state

        if "KeyName" not in model:
            raise ValueError("Property 'KeyName' is required")

        if public_key_material := model.get("PublicKeyMaterial"):
            response = request.aws_client_factory.ec2.import_key_pair(
                KeyName=model["KeyName"],
                PublicKeyMaterial=public_key_material,
            )
        else:
            create_params = util.select_attributes(
                model, ["KeyName", "KeyType", "KeyFormat", "Tags"]
            )
            response = request.aws_client_factory.ec2.create_key_pair(**create_params)

        model["KeyPairId"] = response["KeyPairId"]
        model["KeyFingerprint"] = self.calculate_fingerprint(
            response["KeyMaterial"], model.get("KeyType", "rsa")
        )

        request.aws_client_factory.ssm.put_parameter(
            Name=f"/ec2/keypair/{model['KeyPairId']}",
            Value=model["KeyName"],
            Type="String",
            Overwrite=True,
        )

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
        )

    def read(
        self,
        request: ResourceRequest[EC2KeyPairProperties],
    ) -> ProgressEvent[EC2KeyPairProperties]:
        """
        Fetch resource information

        IAM permissions required:
          - ec2:DescribeKeyPairs
        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[EC2KeyPairProperties],
    ) -> ProgressEvent[EC2KeyPairProperties]:
        """
        Delete a resource

        IAM permissions required:
          - ec2:DeleteKeyPair
          - ssm:DeleteParameter
          - ec2:DescribeKeyPairs
        """

        model = request.desired_state
        ec2 = request.aws_client_factory.ec2
        ec2.delete_key_pair(KeyName=model["KeyName"])

        request.aws_client_factory.ssm.delete_parameter(
            Name=f"/ec2/keypair/{model['KeyPairId']}",
        )

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def update(
        self,
        request: ResourceRequest[EC2KeyPairProperties],
    ) -> ProgressEvent[EC2KeyPairProperties]:
        """
        Update a resource


        """
        raise NotImplementedError