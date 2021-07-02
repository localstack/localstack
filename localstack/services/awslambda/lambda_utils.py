import os
from collections import defaultdict

from localstack.utils.common import to_str

# Lambda runtime constants
LAMBDA_RUNTIME_PYTHON36 = "python3.6"
LAMBDA_RUNTIME_PYTHON37 = "python3.7"
LAMBDA_RUNTIME_PYTHON38 = "python3.8"
LAMBDA_RUNTIME_NODEJS = "nodejs"
LAMBDA_RUNTIME_NODEJS43 = "nodejs4.3"
LAMBDA_RUNTIME_NODEJS610 = "nodejs6.10"
LAMBDA_RUNTIME_NODEJS810 = "nodejs8.10"
LAMBDA_RUNTIME_NODEJS10X = "nodejs10.x"
LAMBDA_RUNTIME_NODEJS12X = "nodejs12.x"
LAMBDA_RUNTIME_NODEJS14X = "nodejs14.x"
LAMBDA_RUNTIME_JAVA8 = "java8"
LAMBDA_RUNTIME_JAVA11 = "java11"
LAMBDA_RUNTIME_DOTNETCORE2 = "dotnetcore2.0"
LAMBDA_RUNTIME_DOTNETCORE21 = "dotnetcore2.1"
LAMBDA_RUNTIME_DOTNETCORE31 = "dotnetcore3.1"
LAMBDA_RUNTIME_GOLANG = "go1.x"
LAMBDA_RUNTIME_RUBY = "ruby"
LAMBDA_RUNTIME_RUBY25 = "ruby2.5"
LAMBDA_RUNTIME_RUBY27 = "ruby2.7"
LAMBDA_RUNTIME_PROVIDED = "provided"

# default handler and runtime
LAMBDA_DEFAULT_HANDLER = "handler.handler"
LAMBDA_DEFAULT_RUNTIME = LAMBDA_RUNTIME_PYTHON37
LAMBDA_DEFAULT_STARTING_POSITION = "LATEST"

# List of Dotnet Lambda runtime names
DOTNET_LAMBDA_RUNTIMES = [
    LAMBDA_RUNTIME_DOTNETCORE2,
    LAMBDA_RUNTIME_DOTNETCORE21,
    LAMBDA_RUNTIME_DOTNETCORE31,
]


def multi_value_dict_for_list(elements):
    temp_mv_dict = defaultdict(list)
    for key in elements:
        if isinstance(key, (list, tuple)):
            key, value = key
        else:
            value = elements[key]
        key = to_str(key)
        temp_mv_dict[key].append(value)

    return dict((k, tuple(v)) for k, v in temp_mv_dict.items())


def get_handler_file_from_name(handler_name, runtime=None):
    runtime = runtime or LAMBDA_DEFAULT_RUNTIME
    if runtime.startswith(LAMBDA_RUNTIME_PROVIDED):
        return "bootstrap"
    delimiter = "."
    if runtime.startswith(LAMBDA_RUNTIME_NODEJS):
        file_ext = ".js"
    elif runtime.startswith(LAMBDA_RUNTIME_GOLANG):
        file_ext = ""
    elif runtime.startswith(tuple(DOTNET_LAMBDA_RUNTIMES)):
        file_ext = ".dll"
        delimiter = ":"
    elif runtime.startswith(LAMBDA_RUNTIME_RUBY):
        file_ext = ".rb"
    else:
        handler_name = handler_name.rpartition(delimiter)[0].replace(delimiter, os.path.sep)
        file_ext = ".py"
    return "%s%s" % (handler_name.split(delimiter)[0], file_ext)
