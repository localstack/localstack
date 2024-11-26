import threading
from typing import Optional

from moto.iam.models import (
    AccessKey,
    AWSManagedPolicy,
    IAMBackend,
    InlinePolicy,
    Policy,
)
from moto.iam.models import Role as MotoRole
from moto.iam.policy_validation import VALID_STATEMENT_ELEMENTS

from localstack import config
from localstack.utils.patch import patch

ADDITIONAL_MANAGED_POLICIES = {
    "AWSLambdaExecute": {
        "Arn": "arn:aws:iam::aws:policy/AWSLambdaExecute",
        "Path": "/",
        "CreateDate": "2017-10-20T17:23:10+00:00",
        "DefaultVersionId": "v4",
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["logs:*"],
                    "Resource": "arn:aws:logs:*:*:*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "arn:aws:s3:::*",
                },
            ],
        },
        "UpdateDate": "2019-05-20T18:22:18+00:00",
    }
}

IAM_PATCHED = False
IAM_PATCH_LOCK = threading.RLock()


def apply_iam_patches():
    global IAM_PATCHED

    # prevent patching multiple times, as this is called from both STS and IAM (for now)
    with IAM_PATCH_LOCK:
        if IAM_PATCHED:
            return

        IAM_PATCHED = True

    # support service linked roles
    moto_role_og_arn_prop = MotoRole.arn

    @property
    def moto_role_arn(self):
        return getattr(self, "service_linked_role_arn", None) or moto_role_og_arn_prop.__get__(self)

    MotoRole.arn = moto_role_arn

    # Add missing managed polices
    # TODO this might not be necessary
    @patch(IAMBackend._init_aws_policies)
    def _init_aws_policies_extended(_init_aws_policies, self):
        loaded_policies = _init_aws_policies(self)
        loaded_policies.extend(
            [
                AWSManagedPolicy.from_data(name, self.account_id, self.region_name, d)
                for name, d in ADDITIONAL_MANAGED_POLICIES.items()
            ]
        )
        return loaded_policies

    if "Principal" not in VALID_STATEMENT_ELEMENTS:
        VALID_STATEMENT_ELEMENTS.append("Principal")

    # patch policy __init__ to set document as attribute

    @patch(Policy.__init__)
    def policy__init__(
        fn,
        self,
        name,
        account_id,
        region,
        default_version_id=None,
        description=None,
        document=None,
        **kwargs,
    ):
        fn(self, name, account_id, region, default_version_id, description, document, **kwargs)
        self.document = document

    # patch unapply_policy

    @patch(InlinePolicy.unapply_policy)
    def inline_policy_unapply_policy(fn, self, backend):
        try:
            fn(self, backend)
        except Exception:
            # Actually role can be deleted before policy being deleted in cloudformation
            pass

    @patch(AccessKey.__init__)
    def access_key__init__(
        fn,
        self,
        user_name: Optional[str],
        prefix: str,
        account_id: str,
        status: str = "Active",
        **kwargs,
    ):
        if not config.PARITY_AWS_ACCESS_KEY_ID:
            prefix = "L" + prefix[1:]
        fn(self, user_name, prefix, account_id, status, **kwargs)
