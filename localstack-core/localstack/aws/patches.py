from importlib.util import find_spec

from localstack.runtime import hooks
from localstack.utils.patch import patch


def patch_moto_instance_tracker_meta():
    """
    Avoid instance collection for moto dashboard. Introduced in
    https://github.com/localstack/localstack/pull/3250.
    """
    from moto.core.base_backend import InstanceTrackerMeta
    from moto.core.common_models import BaseModel

    if hasattr(InstanceTrackerMeta, "_ls_patch_applied"):
        return  # ensure we're not applying the patch multiple times

    @patch(InstanceTrackerMeta.__new__, pass_target=False)
    def new_instance(meta, name, bases, dct):
        cls = super(InstanceTrackerMeta, meta).__new__(meta, name, bases, dct)
        if name == "BaseModel":
            return cls
        cls.instances = []
        return cls

    @patch(BaseModel.__new__, pass_target=False)
    def new_basemodel(cls, *args, **kwargs):
        # skip cls.instances.append(..) which is done by the original/upstream constructor
        instance = super(BaseModel, cls).__new__(cls)
        return instance

    InstanceTrackerMeta._ls_patch_applied = True


def patch_moto_iam_config():
    """
    Enable loading AWS IAM managed policies in moto by default.Introduced in
    https://github.com/localstack/localstack/pull/10112.
    """
    from moto.core.config import default_user_config

    default_user_config["iam"]["load_aws_managed_policies"] = True


# TODO: this could be improved by introducing a hook specifically for applying global patches that is run
#  before any other code is imported.
@hooks.on_infra_start(priority=100)
def apply_aws_runtime_patches():
    """
    Runtime patches specific to the AWS emulator.
    """
    if find_spec("moto"):
        # only load patches when moto is importable
        patch_moto_iam_config()
        patch_moto_instance_tracker_meta()
