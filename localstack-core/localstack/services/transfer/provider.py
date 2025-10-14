from localstack.aws.api import RequestContext
from localstack.aws.api.transfer import (
    CreateUserResponse,
    HomeDirectory,
    HomeDirectoryMappings,
    HomeDirectoryType,
    Policy,
    PosixProfile,
    Role,
    ServerId,
    SshPublicKeyBody,
    Tags,
    TransferApi,
    UserName,
)


class TransferProvider(TransferApi):
    def create_user(
        self,
        context: RequestContext,
        role: Role,
        server_id: ServerId,
        user_name: UserName,
        home_directory: HomeDirectory | None = None,
        home_directory_type: HomeDirectoryType | None = None,
        home_directory_mappings: HomeDirectoryMappings | None = None,
        policy: Policy | None = None,
        posix_profile: PosixProfile | None = None,
        ssh_public_key_body: SshPublicKeyBody | None = None,
        tags: Tags | None = None,
        **kwargs,
    ) -> CreateUserResponse:
        raise NotImplementedError
