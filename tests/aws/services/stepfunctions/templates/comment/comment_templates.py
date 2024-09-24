import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class CommentTemplates(TemplateLoader):
    COMMENTS_AS_PER_DOCS: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/comments_as_per_docs.json5"
    )
    COMMENT_IN_PARAMETERS: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/comment_in_parameters.json5"
    )
