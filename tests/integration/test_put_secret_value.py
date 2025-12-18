import textwrap

import pytest

def test_put_secret_value(
    aws_client_factory
):
    
    secretsmanager_client = aws_client_factory(region_name="uranus-south-1").secretsmanager
    # Create a secret: this works correctly
    secretsmanager_client.create_secret(Name="test-secret", SecretBinary=b"s3cret")
    result = secretsmanager_client.get_secret_value(SecretId="test-secret")
    assert result["SecretBinary"] == b's3cret'

    # Update the secret: this fails or returns garbage
    secretsmanager_client.put_secret_value(SecretId="test-secret", SecretBinary=b"tops3cret")
    result = secretsmanager_client.get_secret_value(SecretId="test-secret")
    assert result["SecretBinary"] == b'tops3cret'
    # # ERROR: Invalid base64-encoded string: number of data characters (9) cannot be 1 more than a multiple of 4

    # With 8-char value: no error but wrong data:
    secretsmanager_client.put_secret_value(SecretId="test-secret", SecretBinary=b"tops3cre")
    result = secretsmanager_client.get_secret_value(SecretId="test-secret")
    assert result["SecretBinary"] == b'tops3cre'
