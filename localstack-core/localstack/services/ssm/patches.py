from moto.ssm.models import SimpleSystemManagerBackend

from localstack.utils.patch import patch


def apply_all_patches():
    @patch(SimpleSystemManagerBackend.list_tags_for_resource)
    def ssm_validate_resource_type_and_id(fn, self, resource_type: str, resource_id: str):
        if resource_type != "Parameter":
            return fn(self, resource_type, resource_id)

        if resource_id.startswith("/") and resource_id.count("/") == 1:
            resource_id = resource_id.lstrip("/")

        return fn(self, resource_type, resource_id)
