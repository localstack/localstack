import json

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

# TODO remove after new IAM implementation of policies
# pytestmark = pytest.mark.skip

ASSUME_ROLE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

SAMPLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Sid": "Statement1", "Effect": "Allow", "Action": ["iam:ListUsers"], "Resource": "*"}
    ],
}

SAMPLE_POLICY_2 = {
    "Version": "2012-10-17",
    "Statement": [
        {"Sid": "Statement1", "Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": "*"}
    ],
}

SAMPLE_POLICY_3 = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Statement1",
            "Effect": "Allow",
            "Action": ["ec2:DescribeInstances"],
            "Resource": "*",
        }
    ],
}

# Invalid policy document test cases - each should raise MalformedPolicyDocument
INVALID_POLICY_DOCUMENTS = [
    # 0: Not valid JSON
    "This is not a json document",
    # 1: Missing Version field
    {
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
        }
    },
    # 2: Version too old (2008-10-17)
    {
        "Version": "2008-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 3: Invalid version string
    {
        "Version": "2013-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 4: Missing Statement field
    {"Version": "2012-10-17"},
    # 5: Statement array contains non-dict
    {"Version": "2012-10-17", "Statement": ["afd"]},
    # 6: Extra field at top level
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
        },
        "Extra field": "value",
    },
    # 7: Extra field in Statement
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Extra field": "value",
        },
    },
    # 8: Id is an array (should be string)
    {
        "Version": "2012-10-17",
        "Id": ["cd3a324d2343d942772346-34234234423404-4c2242343242349d1642ee"],
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 9: Id is an object (should be string)
    {
        "Version": "2012-10-17",
        "Id": {},
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 10: Invalid Effect value
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "invalid",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 11: Action missing vendor prefix
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "invalid",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 12: NotAction is empty string
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "NotAction": "",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 13: Vendor contains space
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "a a:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 14: Action contains multiple colons
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:List:Bucket",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 15: Multiple statements, one with multiple colons in Action
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3s:ListBucket",
                "Resource": "arn:aws:s3:::example_bucket",
            },
            {
                "Effect": "Allow",
                "Action": "s:3s:ListBucket",
                "Resource": "arn:aws:s3:::example_bucket",
            },
        ],
    },
    # 16: Resource not in ARN format
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "invalid resource",
        },
    },
    # 17: Empty string Resource in array
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableDisableHongKong",
                "Effect": "Allow",
                "Action": ["account:EnableRegion", "account:DisableRegion"],
                "Resource": "",
                "Condition": {"StringEquals": {"account:TargetRegion": "ap-east-1"}},
            },
            {
                "Sid": "ViewConsole",
                "Effect": "Allow",
                "Action": ["aws-portal:ViewAccount", "account:ListRegions"],
                "Resource": "",
            },
        ],
    },
    # 18: Resource not in ARN format (with bad action)
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s:3:ListBucket",
            "Resource": "sdfsadf",
        },
    },
    # 19: Resource array with invalid item
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": ["adf"],
        },
    },
    # 20: Empty string Resource
    {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": ""},
    },
    # 21: Invalid partition in Resource
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "NotAction": "s3s:ListBucket",
            "Resource": "a:bsdfdsafsad",
        },
    },
    # 22: Invalid partition in Resource (different format)
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "NotAction": "s3s:ListBucket",
            "Resource": "a:b:cadfsdf",
        },
    },
    # 23: Invalid partition in Resource (long format)
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "NotAction": "s3s:ListBucket",
            "Resource": "a:b:c:d:e:f:g:h",
        },
    },
    # 24: Resource missing arn: prefix
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "aws:s3:::example_bucket",
        },
    },
    # 25: Resource array with invalid partition
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": [
                "arn:error:s3:::example_bucket",
                "arn:error:s3::example_bucket",
            ],
        },
    },
    # 26: Empty Statement array
    {"Version": "2012-10-17", "Statement": []},
    # 27: Missing Resource field
    {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": "s3:ListBucket"},
    },
    # 28: Empty Resource array
    {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": []},
    },
    # 29: Action missing vendor prefix (no Resource)
    {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": "invalid"},
    },
    # 30: Missing Action field
    {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Resource": "arn:aws:s3:::example_bucket"},
    },
    # 31: Missing Effect field
    {
        "Version": "2012-10-17",
        "Statement": {
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 32: Missing Action field (Effect Allow only)
    {"Version": "2012-10-17", "Statement": {"Effect": "Allow"}},
    # 33: Empty Action array
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": [],
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 34: Multiple statements, first missing actions
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Deny"},
            {
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::example_bucket",
            },
        ],
    },
    # 35: Invalid IAM resource path
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:iam:::example_bucket",
        },
    },
    # 36: S3 ARN missing region separator
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3::example_bucket",
        },
    },
    # 37: Missing Resource and Action
    {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Resource": "arn:aws:s3::example_bucket"},
    },
    # 38: Resource vendor not fully qualified
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws",
        },
    },
    # 39: Resource is a dict
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": {"a": "arn:aws:s3:::example_bucket"},
        },
    },
    # 40: Resource array contains dict
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Deny",
            "Action": "s3:ListBucket",
            "Resource": ["adfdf", {}],
        },
    },
    # 41: Both Resource and NotResource present
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "NotAction": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "NotResource": [],
        },
    },
    # 42: Action array contains array
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Deny",
            "Action": [[]],
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 43: Both Action and NotAction present (Action empty)
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "NotAction": "s3s:ListBucket",
            "Action": [],
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 44: Action is a dict
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": {},
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 45: Condition is an array
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": [],
        },
    },
    # 46: Condition is a string
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": "a",
        },
    },
    # 47: Condition with invalid structure
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"a": "b"},
        },
    },
    # 48: Condition operator value is string (not dict)
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"DateGreaterThan": "b"},
        },
    },
    # 49: Condition operator value is array
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"DateGreaterThan": []},
        },
    },
    # 50: Condition key value is dict
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"DateGreaterThan": {"a": {}}},
        },
    },
    # 51: Condition without Action
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"DateGreaterThan": {"a": {}}},
        },
    },
    # 52: Invalid condition operator
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"x": {"a": "1"}},
        },
    },
    # 53: Invalid condition operator format (double colon)
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"ForAnyValue::StringEqualsIfExists": {"a": "asf"}},
        },
    },
    # 54: Condition is an array of dicts
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": [{"ForAllValues:StringEquals": {"aws:TagKeys": "Department"}}],
        },
    },
    # 55: IAM resource cannot contain region
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:iam:us-east-1::example_bucket",
        },
    },
    # 56: S3 resource cannot contain region
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:us-east-1::example_bucket",
        },
    },
    # 57: Sid is a dict
    {
        "Version": "2012-10-17",
        "Statement": {
            "Sid": {},
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 58: Sid is an array
    {
        "Version": "2012-10-17",
        "Statement": {
            "Sid": [],
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 59: Duplicate SIDs
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sdf",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::example_bucket",
            },
            {"Sid": "sdf", "Effect": "Allow"},
        ],
    },
    # 60: Missing Version with duplicate SIDs
    {
        "Statement": [
            {
                "Sid": "sdf",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::example_bucket",
            },
            {"Sid": "sdf", "Effect": "Allow"},
        ]
    },
    # 61: Both Action and NotAction present
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "NotAction": "s3:ListBucket",
            "Action": "iam:dsf",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 62: Both Resource and NotResource present (NotResource has value)
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "NotResource": "*",
        },
    },
    # 63: Effect case sensitivity (denY)
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "denY",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 64: Invalid date condition value
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"DateGreaterThan": {"a": "sdfdsf"}},
        },
    },
    # 65: Missing Version with invalid date condition
    {
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"DateGreaterThan": {"a": "sdfdsf"}},
        }
    },
    # 66: Missing Version with wrong Effect case
    {
        "Statement": {
            "Effect": "denY",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
        }
    },
    # 67: Missing Action with invalid date condition
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Condition": {"DateGreaterThan": {"a": "sdfdsf"}},
        },
    },
    # 68: Invalid ARN (missing separator)
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "NotAction": "s3:ListBucket",
            "Resource": "arn:aws::::example_bucket",
        },
    },
    # 69: Effect case sensitivity (allow)
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "allow",
            "Resource": "arn:aws:s3:us-east-1::example_bucket",
        },
    },
    # 70: Duplicate SIDs with wrong Effect case
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sdf",
                "Effect": "aLLow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::example_bucket",
            },
            {"Sid": "sdf", "Effect": "Allow"},
        ],
    },
    # 71: NotResource with missing region separator
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "NotResource": "arn:aws:s3::example_bucket",
        },
    },
    # 72: Invalid month in date condition
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"DateLessThanEquals": {"a": "234-13"}},
        },
    },
    # 73: Invalid timezone offset in date condition
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"DateLessThanEquals": {"a": "2016-12-13t2:00:00.593194+1"}},
        },
    },
    # 74: Too many decimal places in date condition
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"DateLessThanEquals": {"a": "2016-12-13t2:00:00.1999999999+10:59"}},
        },
    },
    # 75: Date epoch overflow
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"DateLessThan": {"a": "9223372036854775808"}},
        },
    },
    # 76: Invalid partition with invalid date condition
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:error:s3:::example_bucket",
            "Condition": {"DateGreaterThan": {"a": "sdfdsf"}},
        },
    },
    # 77: Invalid ARN (missing service)
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws::fdsasf",
        },
    },
]

# Valid policy documents - each should succeed
VALID_POLICY_DOCUMENTS = [
    # 0: Basic policy with Resource as array
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": ["arn:aws:s3:::example_bucket"],
        },
    },
    # 1: Action with spaces (unusual but valid)
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "iam: asdf safdsf af ",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 2: Mixed resources including wildcard
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": ["arn:aws:s3:::example_bucket", "*"],
        },
    },
    # 3: Wildcard action
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 4: Statement as array
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::example_bucket",
            }
        ],
    },
    # 5: Date conditions
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "service-prefix:action-name",
            "Resource": "*",
            "Condition": {
                "DateGreaterThan": {"aws:CurrentTime": "2017-07-01T00:00:00Z"},
                "DateLessThan": {"aws:CurrentTime": "2017-12-31T23:59:59Z"},
            },
        },
    },
    # 6: FSx service
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "fsx:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 7: IAM user resource
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:iam:::user/example_bucket",
        },
    },
    # 8: Unknown service in resource (valid)
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s33:::example_bucket",
        },
    },
    # 9: Short ARN format
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:fdsasf",
        },
    },
    # 10: Empty Condition
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {},
        },
    },
    # 11: ForAllValues condition
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"ForAllValues:StringEquals": {"aws:TagKeys": "Department"}},
        },
    },
    # 12: CloudWatch resource with region
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:cloudwatch:us-east-1::example_bucket",
        },
    },
    # 13: EC2 resource with region
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:ec2:us-east-1::example_bucket",
        },
    },
    # 14: Invalid service in resource (still valid policy)
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:invalid-service:::example_bucket",
        },
    },
    # 15: Invalid service with region
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:invalid-service:us-east-1::example_bucket",
        },
    },
    # 16: Multiple date conditions
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {
                "DateGreaterThan": {"aws:CurrentTime": "2017-07-01T00:00:00Z"},
                "DateLessThan": {"aws:CurrentTime": "2017-12-31T23:59:59Z"},
            },
        },
    },
    # 17: Empty DateGreaterThan condition
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"DateGreaterThan": {}},
        },
    },
    # 18: DateGreaterThan with empty array
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"DateGreaterThan": {"a": []}},
        },
    },
    # 19: Empty condition operator
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"a": {}},
        },
    },
    # 20: Statement with Sid
    {
        "Version": "2012-10-17",
        "Statement": {
            "Sid": "dsfsdfsdfsdfsdfsadfsd",
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 21: Complex policy with tags
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ConsoleDisplay",
                "Effect": "Allow",
                "Action": [
                    "iam:GetRole",
                    "iam:GetUser",
                    "iam:ListRoles",
                    "iam:ListRoleTags",
                    "iam:ListUsers",
                    "iam:ListUserTags",
                ],
                "Resource": "*",
            },
            {
                "Sid": "AddTag",
                "Effect": "Allow",
                "Action": ["iam:TagUser", "iam:TagRole"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:RequestTag/CostCenter": ["A-123", "B-456"]},
                    "ForAllValues:StringEquals": {"aws:TagKeys": "CostCenter"},
                },
            },
        ],
    },
    # 22: NotAction
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "NotAction": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 23: NotResource with Deny
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Deny",
            "Action": "s3:*",
            "NotResource": [
                "arn:aws:s3:::HRBucket/Payroll",
                "arn:aws:s3:::HRBucket/Payroll/*",
            ],
        },
    },
    # 24: Policy with Id
    {
        "Version": "2012-10-17",
        "Id": "sdfsdfsdf",
        "Statement": {
            "Effect": "Allow",
            "NotAction": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 25: Long vendor name
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "aaaaaadsfdsafsadfsadfaaaaa:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 26: Vendor with hyphen
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3-s:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 27: Vendor with dot
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3.s:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
        },
    },
    # 28: NotAction and NotResource
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "NotAction": "s3:ListBucket",
            "NotResource": "*",
        },
    },
    # 29: Multiple statements, one without Sid
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sdf",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::example_bucket",
            },
            {
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::example_bucket",
            },
        ],
    },
    # 30: Short date format in condition
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"DateGreaterThan": {"a": "01T"}},
        },
    },
    # 31: Multiple empty condition operators
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"x": {}, "y": {}},
        },
    },
    # 32: StringEqualsIfExists
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"StringEqualsIfExists": {"a": "asf"}},
        },
    },
    # 33: ForAnyValue:StringEqualsIfExists
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"ForAnyValue:StringEqualsIfExists": {"a": "asf"}},
        },
    },
    # 34: DateLessThanEquals with ISO timestamp
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"DateLessThanEquals": {"a": "2019-07-01T13:20:15Z"}},
        },
    },
    # 35: DateLessThanEquals with timezone
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"DateLessThanEquals": {"a": "2016-12-13T21:20:37.593194+00:00"}},
        },
    },
    # 36: DateLessThanEquals with numeric timezone
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"DateLessThanEquals": {"a": "2016-12-13t2:00:00.593194+23"}},
        },
    },
    # 37: DateLessThan with negative epoch
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example_bucket",
            "Condition": {"DateLessThan": {"a": "-292275054"}},
        },
    },
    # 38: Self-managed credentials policy
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowViewAccountInfo",
                "Effect": "Allow",
                "Action": [
                    "iam:GetAccountPasswordPolicy",
                    "iam:GetAccountSummary",
                    "iam:ListVirtualMFADevices",
                ],
                "Resource": "*",
            },
            {
                "Sid": "AllowManageOwnPasswords",
                "Effect": "Allow",
                "Action": ["iam:ChangePassword", "iam:GetUser"],
                "Resource": "arn:aws:iam::*:user/${aws:username}",
            },
            {
                "Sid": "AllowManageOwnAccessKeys",
                "Effect": "Allow",
                "Action": [
                    "iam:CreateAccessKey",
                    "iam:DeleteAccessKey",
                    "iam:ListAccessKeys",
                    "iam:UpdateAccessKey",
                ],
                "Resource": "arn:aws:iam::*:user/${aws:username}",
            },
            {
                "Sid": "AllowManageOwnSigningCertificates",
                "Effect": "Allow",
                "Action": [
                    "iam:DeleteSigningCertificate",
                    "iam:ListSigningCertificates",
                    "iam:UpdateSigningCertificate",
                    "iam:UploadSigningCertificate",
                ],
                "Resource": "arn:aws:iam::*:user/${aws:username}",
            },
            {
                "Sid": "AllowManageOwnSSHPublicKeys",
                "Effect": "Allow",
                "Action": [
                    "iam:DeleteSSHPublicKey",
                    "iam:GetSSHPublicKey",
                    "iam:ListSSHPublicKeys",
                    "iam:UpdateSSHPublicKey",
                    "iam:UploadSSHPublicKey",
                ],
                "Resource": "arn:aws:iam::*:user/${aws:username}",
            },
            {
                "Sid": "AllowManageOwnGitCredentials",
                "Effect": "Allow",
                "Action": [
                    "iam:CreateServiceSpecificCredential",
                    "iam:DeleteServiceSpecificCredential",
                    "iam:ListServiceSpecificCredentials",
                    "iam:ResetServiceSpecificCredential",
                    "iam:UpdateServiceSpecificCredential",
                ],
                "Resource": "arn:aws:iam::*:user/${aws:username}",
            },
            {
                "Sid": "AllowManageOwnVirtualMFADevice",
                "Effect": "Allow",
                "Action": ["iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice"],
                "Resource": "arn:aws:iam::*:mfa/${aws:username}",
            },
            {
                "Sid": "AllowManageOwnUserMFA",
                "Effect": "Allow",
                "Action": [
                    "iam:DeactivateMFADevice",
                    "iam:EnableMFADevice",
                    "iam:ListMFADevices",
                    "iam:ResyncMFADevice",
                ],
                "Resource": "arn:aws:iam::*:user/${aws:username}",
            },
            {
                "Sid": "DenyAllExceptListedIfNoMFA",
                "Effect": "Deny",
                "NotAction": [
                    "iam:CreateVirtualMFADevice",
                    "iam:EnableMFADevice",
                    "iam:GetUser",
                    "iam:ListMFADevices",
                    "iam:ListVirtualMFADevices",
                    "iam:ResyncMFADevice",
                    "sts:GetSessionToken",
                ],
                "Resource": "*",
                "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}},
            },
        ],
    },
    # 39: DynamoDB table access
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ListAndDescribe",
                "Effect": "Allow",
                "Action": [
                    "dynamodb:List*",
                    "dynamodb:DescribeReservedCapacity*",
                    "dynamodb:DescribeLimits",
                    "dynamodb:DescribeTimeToLive",
                ],
                "Resource": "*",
            },
            {
                "Sid": "SpecificTable",
                "Effect": "Allow",
                "Action": [
                    "dynamodb:BatchGet*",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:Get*",
                    "dynamodb:Query",
                    "dynamodb:Scan",
                    "dynamodb:BatchWrite*",
                    "dynamodb:CreateTable",
                    "dynamodb:Delete*",
                    "dynamodb:Update*",
                    "dynamodb:PutItem",
                ],
                "Resource": "arn:aws:dynamodb:*:*:table/MyTable",
            },
        ],
    },
    # 40: EC2 volume attach/detach with ArnEquals
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["ec2:AttachVolume", "ec2:DetachVolume"],
                "Resource": ["arn:aws:ec2:*:*:volume/*", "arn:aws:ec2:*:*:instance/*"],
                "Condition": {
                    "ArnEquals": {"ec2:SourceInstanceARN": "arn:aws:ec2:*:*:instance/instance-id"}
                },
            }
        ],
    },
    # 41: EC2 resource tags
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["ec2:AttachVolume", "ec2:DetachVolume"],
                "Resource": "arn:aws:ec2:*:*:instance/*",
                "Condition": {"StringEquals": {"ec2:ResourceTag/Department": "Development"}},
            },
            {
                "Effect": "Allow",
                "Action": ["ec2:AttachVolume", "ec2:DetachVolume"],
                "Resource": "arn:aws:ec2:*:*:volume/*",
                "Condition": {"StringEquals": {"ec2:ResourceTag/VolumeUser": "${aws:username}"}},
            },
        ],
    },
    # 42: EC2 with principal tags
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "StartStopIfTags",
                "Effect": "Allow",
                "Action": [
                    "ec2:StartInstances",
                    "ec2:StopInstances",
                    "ec2:DescribeTags",
                ],
                "Resource": "arn:aws:ec2:region:account-id:instance/*",
                "Condition": {
                    "StringEquals": {
                        "ec2:ResourceTag/Project": "DataAnalytics",
                        "aws:PrincipalTag/Department": "Data",
                    }
                },
            }
        ],
    },
    # 43: S3 with Cognito identity
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ListYourObjects",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": ["arn:aws:s3:::bucket-name"],
                "Condition": {
                    "StringLike": {
                        "s3:prefix": [
                            "cognito/application-name/${cognito-identity.amazonaws.com:sub}"
                        ]
                    }
                },
            },
            {
                "Sid": "ReadWriteDeleteYourObjects",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                "Resource": [
                    "arn:aws:s3:::bucket-name/cognito/application-name/${cognito-identity.amazonaws.com:sub}",
                    "arn:aws:s3:::bucket-name/cognito/application-name/${cognito-identity.amazonaws.com:sub}/*",
                ],
            },
        ],
    },
    # 44: S3 home folder pattern
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:ListAllMyBuckets", "s3:GetBucketLocation"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::bucket-name",
                "Condition": {"StringLike": {"s3:prefix": ["", "home/", "home/${aws:userid}/*"]}},
            },
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": [
                    "arn:aws:s3:::bucket-name/home/${aws:userid}",
                    "arn:aws:s3:::bucket-name/home/${aws:userid}/*",
                ],
            },
        ],
    },
    # 45: S3 console access
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ConsoleAccess",
                "Effect": "Allow",
                "Action": [
                    "s3:GetAccountPublicAccessBlock",
                    "s3:GetBucketAcl",
                    "s3:GetBucketLocation",
                    "s3:GetBucketPolicyStatus",
                    "s3:GetBucketPublicAccessBlock",
                    "s3:ListAllMyBuckets",
                ],
                "Resource": "*",
            },
            {
                "Sid": "ListObjectsInBucket",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": ["arn:aws:s3:::bucket-name"],
            },
            {
                "Sid": "AllObjectActions",
                "Effect": "Allow",
                "Action": "s3:*Object",
                "Resource": ["arn:aws:s3:::bucket-name/*"],
            },
        ],
    },
    # 46: Simpler self-managed credentials
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowViewAccountInfo",
                "Effect": "Allow",
                "Action": ["iam:GetAccountPasswordPolicy", "iam:GetAccountSummary"],
                "Resource": "*",
            },
            {
                "Sid": "AllowManageOwnPasswords",
                "Effect": "Allow",
                "Action": ["iam:ChangePassword", "iam:GetUser"],
                "Resource": "arn:aws:iam::*:user/${aws:username}",
            },
            {
                "Sid": "AllowManageOwnAccessKeys",
                "Effect": "Allow",
                "Action": [
                    "iam:CreateAccessKey",
                    "iam:DeleteAccessKey",
                    "iam:ListAccessKeys",
                    "iam:UpdateAccessKey",
                ],
                "Resource": "arn:aws:iam::*:user/${aws:username}",
            },
            {
                "Sid": "AllowManageOwnSigningCertificates",
                "Effect": "Allow",
                "Action": [
                    "iam:DeleteSigningCertificate",
                    "iam:ListSigningCertificates",
                    "iam:UpdateSigningCertificate",
                    "iam:UploadSigningCertificate",
                ],
                "Resource": "arn:aws:iam::*:user/${aws:username}",
            },
            {
                "Sid": "AllowManageOwnSSHPublicKeys",
                "Effect": "Allow",
                "Action": [
                    "iam:DeleteSSHPublicKey",
                    "iam:GetSSHPublicKey",
                    "iam:ListSSHPublicKeys",
                    "iam:UpdateSSHPublicKey",
                    "iam:UploadSSHPublicKey",
                ],
                "Resource": "arn:aws:iam::*:user/${aws:username}",
            },
            {
                "Sid": "AllowManageOwnGitCredentials",
                "Effect": "Allow",
                "Action": [
                    "iam:CreateServiceSpecificCredential",
                    "iam:DeleteServiceSpecificCredential",
                    "iam:ListServiceSpecificCredentials",
                    "iam:ResetServiceSpecificCredential",
                    "iam:UpdateServiceSpecificCredential",
                ],
                "Resource": "arn:aws:iam::*:user/${aws:username}",
            },
        ],
    },
    # 47: EC2 regional restriction
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "ec2:*",
                "Resource": "*",
                "Effect": "Allow",
                "Condition": {"StringEquals": {"ec2:Region": "region"}},
            }
        ],
    },
    # 48: RDS regional access
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "rds:*",
                "Resource": ["arn:aws:rds:region:*:*"],
            },
            {"Effect": "Allow", "Action": ["rds:Describe*"], "Resource": ["*"]},
        ],
    },
    # 49: RDS with empty Sids
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "",
                "Effect": "Allow",
                "Action": "rds:*",
                "Resource": ["arn:aws:rds:region:*:*"],
            },
            {
                "Sid": "",
                "Effect": "Allow",
                "Action": ["rds:Describe*"],
                "Resource": ["*"],
            },
        ],
    },
    # 50: S3 access point
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "",
                "Effect": "Allow",
                "Action": ["s3:*"],
                "Resource": [
                    "arn:aws:s3:us-west-2:123456789012:accesspoint/my-access-point",
                    "arn:aws:s3:us-west-2:123456789012:accesspoint/my-access-point/object/*",
                ],
            },
        ],
    },
]


@pytest.fixture(autouse=True)
def snapshot_transformers(snapshot):
    snapshot.add_transformers_list(snapshot.transform.iam_api())


class TestPolicies:
    @markers.aws.validated
    @pytest.mark.parametrize("path", ["/test/path/", "/", None])
    def test_policy_lifecycle(self, aws_client, snapshot, path):
        """Test the lifecycle of a basic IAM policy"""
        policy_name = f"test-policy-{short_uid()}"
        kwargs = {}
        if path:
            kwargs = {"Path": path}
        response = aws_client.iam.create_policy(
            PolicyName=policy_name, PolicyDocument=json.dumps(SAMPLE_POLICY), **kwargs
        )
        snapshot.match("create-policy-response", response)
        policy_arn = response["Policy"]["Arn"]

        response = aws_client.iam.get_policy(PolicyArn=policy_arn)
        snapshot.match("get-policy-response", response)

        response = aws_client.iam.list_policies()
        response = [
            policy for policy in response["Policies"] if policy["PolicyName"] == policy_name
        ]
        snapshot.match("filtered-policy-list", response)

        response = aws_client.iam.delete_policy(PolicyArn=policy_arn)
        snapshot.match("delete-policy-response", response)

    @markers.aws.validated
    def test_policy_errors(self, aws_client, create_policy, snapshot):
        """Tests error conditions on IAM policies"""
        policy_name = f"test-policy-{short_uid()}"
        response = create_policy(PolicyName=policy_name, PolicyDocument=json.dumps(SAMPLE_POLICY))
        snapshot.match("create-policy-response", response)

        with pytest.raises(ClientError) as e:
            aws_client.iam.create_policy(
                PolicyName=policy_name, PolicyDocument=json.dumps(SAMPLE_POLICY)
            )
        snapshot.match("policy-already-exists", e.value.response)

    @markers.aws.validated
    def test_policy_version_lifecycle(self, aws_client, create_policy, snapshot):
        """Test the full CRUD lifecycle of policy versions."""
        response = create_policy(PolicyDocument=json.dumps(SAMPLE_POLICY))
        snapshot.match("create-policy", response)
        policy_arn = response["Policy"]["Arn"]

        # Create v2 as default
        response = aws_client.iam.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=json.dumps(SAMPLE_POLICY_2),
            SetAsDefault=True,
        )
        snapshot.match("create-version-v2", response)

        # Get v2
        response = aws_client.iam.get_policy_version(PolicyArn=policy_arn, VersionId="v2")
        snapshot.match("get-version-v2", response)

        # Delete v1 (no longer default)
        aws_client.iam.delete_policy_version(PolicyArn=policy_arn, VersionId="v1")

        # Create v3 as non-default
        response = aws_client.iam.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=json.dumps(SAMPLE_POLICY_3),
        )
        snapshot.match("create-version-v3", response)

        # Get v3
        response = aws_client.iam.get_policy_version(PolicyArn=policy_arn, VersionId="v3")
        snapshot.match("get-version-v3", response)

        # List all versions — should show v2 (default) and v3
        response = aws_client.iam.list_policy_versions(PolicyArn=policy_arn)
        snapshot.match("list-versions", response)

    @markers.aws.validated
    def test_policy_version_set_default(self, aws_client, create_policy, snapshot):
        """Test setting the default policy version."""
        response = create_policy(PolicyDocument=json.dumps(SAMPLE_POLICY))
        policy_arn = response["Policy"]["Arn"]

        # Create v2 and v3 as default
        aws_client.iam.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=json.dumps(SAMPLE_POLICY_2),
            SetAsDefault=True,
        )
        aws_client.iam.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=json.dumps(SAMPLE_POLICY_3),
            SetAsDefault=True,
        )

        # List — v3 should be default
        response = aws_client.iam.list_policy_versions(PolicyArn=policy_arn)
        snapshot.match("list-after-create", response)

        # Set v1 as default
        response = aws_client.iam.set_default_policy_version(PolicyArn=policy_arn, VersionId="v1")
        snapshot.match("set-default-v1", response)

        # List — v1 should now be default
        response = aws_client.iam.list_policy_versions(PolicyArn=policy_arn)
        snapshot.match("list-after-set-default", response)

    @markers.aws.validated
    def test_policy_version_limit(self, aws_client, create_policy, snapshot):
        """Test the 5-version maximum for policy versions."""
        response = create_policy(PolicyDocument=json.dumps(SAMPLE_POLICY))
        policy_arn = response["Policy"]["Arn"]

        # Create 4 more versions (v2–v5)
        for _ in range(4):
            aws_client.iam.create_policy_version(
                PolicyArn=policy_arn,
                PolicyDocument=json.dumps(SAMPLE_POLICY),
            )

        # Creating a 6th version should fail
        with pytest.raises(ClientError) as e:
            aws_client.iam.create_policy_version(
                PolicyArn=policy_arn,
                PolicyDocument=json.dumps(SAMPLE_POLICY),
            )
        snapshot.match("err-version-limit-exceeded", e.value.response)

        # List — should show exactly 5 versions
        response = aws_client.iam.list_policy_versions(PolicyArn=policy_arn)
        snapshot.match("list-versions-at-limit", response)

        # Delete one version and verify a new one can be created
        aws_client.iam.delete_policy_version(PolicyArn=policy_arn, VersionId="v5")
        response = aws_client.iam.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=json.dumps(SAMPLE_POLICY),
        )
        snapshot.match("create-version-after-delete", response)

    @markers.aws.validated
    def test_policy_version_errors(
        self, aws_client, create_policy, snapshot, account_id, partition
    ):
        """Test error cases for policy version operations."""
        response = create_policy(PolicyDocument=json.dumps(SAMPLE_POLICY))
        snapshot.match("create-policy", response)
        policy_arn = response["Policy"]["Arn"]

        # Create v2
        aws_client.iam.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=json.dumps(SAMPLE_POLICY_2),
        )

        # Error: get version from non-existent policy
        non_existent_arn = f"arn:{partition}:iam::{account_id}:policy/TestNonExistingPolicy"
        with pytest.raises(ClientError) as e:
            aws_client.iam.get_policy_version(PolicyArn=non_existent_arn, VersionId="v1")
        snapshot.match("err-get-version-nonexistent-policy", e.value.response)

        # Error: get non-existent version
        with pytest.raises(ClientError) as e:
            aws_client.iam.get_policy_version(PolicyArn=policy_arn, VersionId="v9")
        snapshot.match("err-get-nonexistent-version", e.value.response)

        # Error: delete the default version (v1)
        with pytest.raises(ClientError) as e:
            aws_client.iam.delete_policy_version(PolicyArn=policy_arn, VersionId="v1")
        snapshot.match("err-delete-default-version", e.value.response)

        # Error: delete a non-existent version
        with pytest.raises(ClientError) as e:
            aws_client.iam.delete_policy_version(PolicyArn=policy_arn, VersionId="v9")
        snapshot.match("err-delete-nonexistent-version", e.value.response)

        # Error: set default on non-existent policy
        with pytest.raises(ClientError) as e:
            aws_client.iam.set_default_policy_version(PolicyArn=non_existent_arn, VersionId="v1")
        snapshot.match("err-set-default-nonexistent-policy", e.value.response)

        # Error: set default with invalid version format
        with pytest.raises(ClientError) as e:
            aws_client.iam.set_default_policy_version(
                PolicyArn=policy_arn, VersionId="wrong_version_id"
            )
        snapshot.match("err-set-default-invalid-version-format", e.value.response)

        # Error: set default with non-existent version
        with pytest.raises(ClientError) as e:
            aws_client.iam.set_default_policy_version(PolicyArn=policy_arn, VersionId="v4")
        snapshot.match("err-set-default-nonexistent-version", e.value.response)

        # Successfully delete v2 — confirm policy still works after errors
        aws_client.iam.delete_policy_version(PolicyArn=policy_arn, VersionId="v2")

        # List — only v1 should remain
        response = aws_client.iam.list_policy_versions(PolicyArn=policy_arn)
        snapshot.match("list-after-delete", response)


class TestPolicyTags:
    @markers.aws.validated
    def test_policy_tag_lifecycle(self, aws_client, create_policy, snapshot):
        """Test creating policies with tags and verifying they appear in responses."""
        # Create policy with two tags and a description
        response = create_policy(
            PolicyDocument=json.dumps(SAMPLE_POLICY),
            Tags=[
                {"Key": "somekey", "Value": "somevalue"},
                {"Key": "someotherkey", "Value": "someothervalue"},
            ],
            Description="testing",
        )
        snapshot.match("create-with-tags", response)
        policy_arn = response["Policy"]["Arn"]

        response = aws_client.iam.get_policy(PolicyArn=policy_arn)
        snapshot.match("get-with-tags", response)

        response = aws_client.iam.list_policy_tags(PolicyArn=policy_arn)
        snapshot.match("list-created-tags", response)

        # Create policy with empty tag value
        response = create_policy(
            PolicyDocument=json.dumps(SAMPLE_POLICY),
            Tags=[{"Key": "somekey", "Value": ""}],
        )
        snapshot.match("create-with-empty-tag-value", response)
        empty_tag_arn = response["Policy"]["Arn"]

        response = aws_client.iam.list_policy_tags(PolicyArn=empty_tag_arn)
        snapshot.match("list-empty-tag-value", response)

        # Create policy without tags
        response = create_policy(PolicyDocument=json.dumps(SAMPLE_POLICY))
        no_tags_arn = response["Policy"]["Arn"]

        response = aws_client.iam.get_policy(PolicyArn=no_tags_arn)
        snapshot.match("get-without-tags", response)

        # Create policy with case-sensitive tag keys (a and A are distinct)
        response = create_policy(
            PolicyDocument=json.dumps(SAMPLE_POLICY),
            Tags=[
                {"Key": "a", "Value": "lowercase"},
                {"Key": "A", "Value": "uppercase"},
            ],
        )
        snapshot.match("create-with-case-sensitive-tags", response)
        case_sensitive_arn = response["Policy"]["Arn"]

        response = aws_client.iam.list_policy_tags(PolicyArn=case_sensitive_arn)
        snapshot.match("list-case-sensitive-tags", response)

    @markers.aws.validated
    def test_policy_tag_operations(self, aws_client, create_policy, snapshot):
        """Test tag_policy, list_policy_tags (with pagination), updating tags, and untag_policy."""
        response = create_policy(PolicyDocument=json.dumps(SAMPLE_POLICY))
        snapshot.match("create-policy", response)
        policy_arn = response["Policy"]["Arn"]

        # Tag the policy
        aws_client.iam.tag_policy(
            PolicyArn=policy_arn,
            Tags=[
                {"Key": "somekey", "Value": "somevalue"},
                {"Key": "someotherkey", "Value": "someothervalue"},
            ],
        )

        response = aws_client.iam.get_policy(PolicyArn=policy_arn)
        snapshot.match("get-after-tag", response)

        response = aws_client.iam.list_policy_tags(PolicyArn=policy_arn)
        snapshot.match("list-tags", response)

        # Pagination
        response = aws_client.iam.list_policy_tags(PolicyArn=policy_arn, MaxItems=1)
        snapshot.match("list-tags-page1", response)

        response = aws_client.iam.list_policy_tags(PolicyArn=policy_arn, Marker=response["Marker"])
        snapshot.match("list-tags-page2", response)

        # Update existing tag value
        aws_client.iam.tag_policy(
            PolicyArn=policy_arn,
            Tags=[{"Key": "somekey", "Value": "somenewvalue"}],
        )

        response = aws_client.iam.list_policy_tags(PolicyArn=policy_arn)
        snapshot.match("list-after-update", response)

        # Update existing tag to empty value
        aws_client.iam.tag_policy(
            PolicyArn=policy_arn,
            Tags=[{"Key": "somekey", "Value": ""}],
        )

        response = aws_client.iam.list_policy_tags(PolicyArn=policy_arn)
        snapshot.match("list-after-update-empty", response)

        # Untag one key
        aws_client.iam.untag_policy(PolicyArn=policy_arn, TagKeys=["somekey"])

        response = aws_client.iam.list_policy_tags(PolicyArn=policy_arn)
        snapshot.match("list-after-untag-one", response)

        # Untag remaining key
        aws_client.iam.untag_policy(PolicyArn=policy_arn, TagKeys=["someotherkey"])

        response = aws_client.iam.list_policy_tags(PolicyArn=policy_arn)
        snapshot.match("list-after-untag-all", response)

        # Test case-sensitive tag operations (a and A are distinct keys)
        aws_client.iam.tag_policy(
            PolicyArn=policy_arn,
            Tags=[
                {"Key": "a", "Value": "lowercase"},
                {"Key": "A", "Value": "uppercase"},
            ],
        )

        response = aws_client.iam.list_policy_tags(PolicyArn=policy_arn)
        snapshot.match("list-case-sensitive-tags", response)

        # Untag only lowercase 'a', uppercase 'A' should remain
        aws_client.iam.untag_policy(PolicyArn=policy_arn, TagKeys=["a"])

        response = aws_client.iam.list_policy_tags(PolicyArn=policy_arn)
        snapshot.match("list-after-untag-lowercase", response)

    @markers.aws.validated
    def test_policy_tag_create_errors(self, aws_client, snapshot):
        """Test tag validation errors on create_policy."""
        policy_doc = json.dumps(SAMPLE_POLICY)

        # Too many tags (51)
        with pytest.raises(ClientError) as e:
            too_many_tags = [{"Key": str(x), "Value": str(x)} for x in range(51)]
            aws_client.iam.create_policy(
                PolicyName=f"test-policy-{short_uid()}",
                PolicyDocument=policy_doc,
                Tags=too_many_tags,
            )
        snapshot.match("err-too-many-tags", e.value.response)

        # Duplicate tag keys
        with pytest.raises(ClientError) as e:
            aws_client.iam.create_policy(
                PolicyName=f"test-policy-{short_uid()}",
                PolicyDocument=policy_doc,
                Tags=[{"Key": "0", "Value": ""}, {"Key": "0", "Value": ""}],
            )
        snapshot.match("err-duplicate-keys", e.value.response)

        # Key too long (129 chars)
        with pytest.raises(ClientError) as e:
            aws_client.iam.create_policy(
                PolicyName=f"test-policy-{short_uid()}",
                PolicyDocument=policy_doc,
                Tags=[{"Key": "0" * 129, "Value": ""}],
            )
        snapshot.match("err-large-key", e.value.response)

        # Value too long (257 chars)
        with pytest.raises(ClientError) as e:
            aws_client.iam.create_policy(
                PolicyName=f"test-policy-{short_uid()}",
                PolicyDocument=policy_doc,
                Tags=[{"Key": "0", "Value": "0" * 257}],
            )
        snapshot.match("err-large-value", e.value.response)

        # Invalid character in key
        with pytest.raises(ClientError) as e:
            aws_client.iam.create_policy(
                PolicyName=f"test-policy-{short_uid()}",
                PolicyDocument=policy_doc,
                Tags=[{"Key": "NOWAY!", "Value": ""}],
            )
        snapshot.match("err-invalid-character", e.value.response)

    @markers.aws.validated
    def test_policy_tag_update_errors(
        self, aws_client, create_policy, snapshot, account_id, partition
    ):
        """Test tag validation errors on tag_policy and untag_policy, plus non-existent policy."""
        response = create_policy(PolicyDocument=json.dumps(SAMPLE_POLICY))
        policy_arn = response["Policy"]["Arn"]

        aws_client.iam.tag_policy(
            PolicyArn=policy_arn,
            Tags=[
                {"Key": "somekey", "Value": "somevalue"},
                {"Key": "someotherkey", "Value": "someothervalue"},
            ],
        )

        # tag_policy: too many tags (51)
        with pytest.raises(ClientError) as e:
            too_many_tags = [{"Key": str(x), "Value": str(x)} for x in range(51)]
            aws_client.iam.tag_policy(PolicyArn=policy_arn, Tags=too_many_tags)
        snapshot.match("err-tag-too-many", e.value.response)

        # tag_policy: duplicate keys
        with pytest.raises(ClientError) as e:
            aws_client.iam.tag_policy(
                PolicyArn=policy_arn,
                Tags=[{"Key": "0", "Value": ""}, {"Key": "0", "Value": ""}],
            )
        snapshot.match("err-tag-duplicate-keys", e.value.response)

        # tag_policy: key too long
        with pytest.raises(ClientError) as e:
            aws_client.iam.tag_policy(
                PolicyArn=policy_arn,
                Tags=[{"Key": "0" * 129, "Value": ""}],
            )
        snapshot.match("err-tag-large-key", e.value.response)

        # tag_policy: value too long
        with pytest.raises(ClientError) as e:
            aws_client.iam.tag_policy(
                PolicyArn=policy_arn,
                Tags=[{"Key": "0", "Value": "0" * 257}],
            )
        snapshot.match("err-tag-large-value", e.value.response)

        # tag_policy: invalid character
        with pytest.raises(ClientError) as e:
            aws_client.iam.tag_policy(
                PolicyArn=policy_arn,
                Tags=[{"Key": "NOWAY!", "Value": ""}],
            )
        snapshot.match("err-tag-invalid-character", e.value.response)

        # tag_policy: non-existent policy
        non_existent_arn = f"arn:{partition}:iam::{account_id}:policy/NotAPolicy"
        with pytest.raises(ClientError) as e:
            aws_client.iam.tag_policy(
                PolicyArn=non_existent_arn,
                Tags=[{"Key": "some", "Value": "value"}],
            )
        snapshot.match("err-tag-nonexistent-policy", e.value.response)

        # untag_policy: too many keys (51)
        with pytest.raises(ClientError) as e:
            aws_client.iam.untag_policy(
                PolicyArn=policy_arn,
                TagKeys=[str(x) for x in range(51)],
            )
        snapshot.match("err-untag-too-many-keys", e.value.response)

        # untag_policy: key too long
        with pytest.raises(ClientError) as e:
            aws_client.iam.untag_policy(
                PolicyArn=policy_arn,
                TagKeys=["0" * 129],
            )
        snapshot.match("err-untag-large-key", e.value.response)

        # untag_policy: invalid character
        with pytest.raises(ClientError) as e:
            aws_client.iam.untag_policy(
                PolicyArn=policy_arn,
                TagKeys=["NOWAY!"],
            )
        snapshot.match("err-untag-invalid-character", e.value.response)

        # untag_policy: non-existent policy
        with pytest.raises(ClientError) as e:
            aws_client.iam.untag_policy(
                PolicyArn=non_existent_arn,
                TagKeys=["somevalue"],
            )
        snapshot.match("err-untag-nonexistent-policy", e.value.response)


class TestPolicyDocumentValidity:
    """Tests for policy document validation - migrated from moto test_iam_policies.py."""

    @markers.aws.validated
    @pytest.mark.parametrize(
        "policy_doc",
        INVALID_POLICY_DOCUMENTS,
        ids=[f"invalid-{i}" for i in range(len(INVALID_POLICY_DOCUMENTS))],
    )
    def test_create_policy_invalid_document(self, create_policy, snapshot, policy_doc):
        """Test that invalid policy documents are rejected with MalformedPolicyDocument."""
        with pytest.raises(ClientError) as e:
            create_policy(
                PolicyName=f"test-policy-{short_uid()}",
                PolicyDocument=json.dumps(policy_doc)
                if isinstance(policy_doc, dict)
                else policy_doc,
            )
        snapshot.match("error", e.value.response)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "policy_doc",
        VALID_POLICY_DOCUMENTS,
        ids=[f"valid-{i}" for i in range(len(VALID_POLICY_DOCUMENTS))],
    )
    def test_create_policy_valid_document(self, create_policy, snapshot, policy_doc):
        """Test that valid policy documents are accepted."""
        response = create_policy(PolicyDocument=json.dumps(policy_doc))
        snapshot.match("response", response)


class TestListEntitiesForPolicy:
    """Tests for list_entities_for_policy API - migrated from moto test_iam.py."""

    @markers.aws.validated
    def test_list_entities_for_policy(
        self,
        aws_client,
        snapshot,
        create_policy,
        create_user,
        create_group,
        create_role,
    ):
        """Test listing entities (users, groups, roles) attached to a policy."""
        # Create a policy
        policy_response = create_policy(PolicyDocument=json.dumps(SAMPLE_POLICY))
        snapshot.match("create-policy", policy_response)
        policy_arn = policy_response["Policy"]["Arn"]

        # List entities before attaching - should all be empty
        response = aws_client.iam.list_entities_for_policy(PolicyArn=policy_arn)
        snapshot.match("empty-entities", response)

        # Create user, group, and role
        user_response = create_user()
        snapshot.match("create-user", user_response)
        user_name = user_response["User"]["UserName"]

        group_response = create_group()
        snapshot.match("create-group", group_response)
        group_name = group_response["Group"]["GroupName"]

        role_response = create_role(AssumeRolePolicyDocument=ASSUME_ROLE_POLICY)
        snapshot.match("create-role", role_response)
        role_name = role_response["Role"]["RoleName"]

        # Attach the policy to user, group, and role
        aws_client.iam.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)
        aws_client.iam.attach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
        aws_client.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

        # Test filter by Role
        response = aws_client.iam.list_entities_for_policy(
            PolicyArn=policy_arn, EntityFilter="Role"
        )
        snapshot.match("filter-role", response)

        # Test filter by User
        response = aws_client.iam.list_entities_for_policy(
            PolicyArn=policy_arn, EntityFilter="User"
        )
        snapshot.match("filter-user", response)

        # Test filter by Group
        response = aws_client.iam.list_entities_for_policy(
            PolicyArn=policy_arn, EntityFilter="Group"
        )
        snapshot.match("filter-group", response)

        # Test filter by LocalManagedPolicy (returns all entities)
        response = aws_client.iam.list_entities_for_policy(
            PolicyArn=policy_arn, EntityFilter="LocalManagedPolicy"
        )
        snapshot.match("filter-local-managed-policy", response)

        # Test no filter (returns all entities)
        response = aws_client.iam.list_entities_for_policy(PolicyArn=policy_arn)
        snapshot.match("no-filter", response)

    @markers.aws.validated
    def test_list_entities_for_policy_errors(self, aws_client, snapshot, account_id, partition):
        """Test error cases for list_entities_for_policy."""
        # Non-existent policy
        non_existent_arn = f"arn:{partition}:iam::{account_id}:policy/NonExistentPolicy"
        with pytest.raises(ClientError) as e:
            aws_client.iam.list_entities_for_policy(PolicyArn=non_existent_arn)
        snapshot.match("err-nonexistent-policy", e.value.response)
