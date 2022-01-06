import os

import jinja2

from localstack.utils.common import load_file


def load_template(tmpl_path: str, **template_vars) -> str:
    template = load_template_raw(tmpl_path)
    if template_vars:
        template = jinja2.Template(template).render(**template_vars)
    return template


def load_template_raw(tmpl_path: str) -> str:
    template = load_file(os.path.join(get_templates_folder(), tmpl_path))
    return template


def get_templates_folder():
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "templates")
