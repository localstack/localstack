from localstack.runtime.ui_messages.ui_message_service import UIMessageService
from localstack.utils.objects import singleton_factory

@singleton_factory
def get_instance() -> UIMessageService:
    return UIMessageService()