import os

import jinja2

from localstack.utils.common import load_file


def load_template(tmpl_path: str, **template_vars) -> str:
    template = load_template_raw(tmpl_path)
    return render_template(template, **template_vars)


def render_template(template_body: str, **template_vars) -> str:
    if template_vars:
        template_body = jinja2.Template(template_body).render(**template_vars)
    return template_body


def load_template_raw(tmpl_file: str) -> str:
    return load_file(template_path(tmpl_file))


def template_path(tmpl_file: str) -> str:
    return os.path.join(get_templates_folder(), tmpl_file)


def get_templates_folder() -> str:
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "templates")
