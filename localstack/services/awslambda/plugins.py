from typing import List

from localstack.packages import Package, packages


@packages(api="lambda")
def awslambda_packages() -> List[Package]:
    from localstack.services.awslambda.packages import (
        awslambda_go_runtime_package,
        awslambda_runtime_package,
        lambda_java_libs_package,
    )

    return [awslambda_runtime_package, awslambda_go_runtime_package, lambda_java_libs_package]
