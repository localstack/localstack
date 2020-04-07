import uuid
from moto.iam.responses import IamResponse, GENERIC_EMPTY_TEMPLATE
from moto.iam.models import iam_backend as moto_iam_backend, User
from localstack import config
from localstack.constants import DEFAULT_PORT_IAM_BACKEND
from localstack.services.infra import start_moto_server


def apply_patches():
    def iam_response_create_user(self):
        user = moto_iam_backend.create_user(
            self._get_param('UserName'),
            self._get_param('Path'),
            self._get_multi_param('Tags.member')
        )

        template = self.response_template(USER_RESPONSE_TEMPLATE)
        return template.render(
            action='Create',
            user=user,
            request_id=str(uuid.uuid4())
        )

    IamResponse.create_user = iam_response_create_user

    def iam_response_get_user(self):
        user_name = self._get_param('UserName')
        if not user_name:
            access_key_id = self.get_current_user()
            user = moto_iam_backend.get_user_from_access_key_id(access_key_id)
            if user is None:
                user = User('default_user')
        else:
            user = moto_iam_backend.get_user(user_name)

        template = self.response_template(USER_RESPONSE_TEMPLATE)
        return template.render(
            action='Get',
            user=user,
            request_id=str(uuid.uuid4())
        )

    IamResponse.get_user = iam_response_get_user

    def iam_response_delete_policy(self):
        policy_arn = self._get_param('PolicyArn')
        moto_iam_backend.managed_policies.pop(policy_arn, None)
        template = self.response_template(GENERIC_EMPTY_TEMPLATE)
        return template.render(name='DeletePolicyResponse')

    if not hasattr(IamResponse, 'delete_policy'):
        IamResponse.delete_policy = iam_response_delete_policy


def start_iam(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_IAM

    apply_patches()
    return start_moto_server('iam', port, name='IAM', asynchronous=asynchronous,
                             backend_port=DEFAULT_PORT_IAM_BACKEND, update_listener=update_listener)


USER_RESPONSE_TEMPLATE = """<{{ action }}UserResponse>
   <{{ action }}UserResult>
      <User>
         <Path>{{ user.path }}</Path>
         <UserName>{{ user.name }}</UserName>
         <UserId>{{ user.id }}</UserId>
         <Arn>{{ user.arn }}</Arn>
         <CreateDate>{{ user.created_iso_8601 }}</CreateDate>
         <Tags>
            {% for tag in user.tags %}<member>
                <Key>{{ tag.Key }}</Key>
                <Value>{{ tag.Value }}</Value>
            </member>{% endfor %}
         </Tags>
     </User>
   </{{ action }}UserResult>
   <ResponseMetadata>
      <RequestId>{{request_id}}</RequestId>
   </ResponseMetadata>
</{{ action }}UserResponse>"""
