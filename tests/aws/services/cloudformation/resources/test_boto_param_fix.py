# import os
#
# from localstack.testing.pytest import markers
#
# @markers.aws.only_localstack
# def test_nested_boto_parameter_fix(deploy_cfn_template, snapshot):
#     deploy_cfn_template(
#         template_path=os.path.join(
#             os.path.dirname(__file__), "../../../templates/cdk_bootstrap_v12.yaml"
#         )
#     )
#
#     stack = deploy_cfn_template(
#         template_path=os.path.join(
#             os.path.dirname(__file__),
#             "../../../templates/boto_param_error_nested.yaml",
#         )
#     )
#     snapshot.match("stack-outputs", stack.outputs)
