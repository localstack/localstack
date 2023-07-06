import os.path


def test_temp_test_template(deploy_cfn_template, aws_client):
    """
    2 scenarios

    1. SingleTable parameter set to true
    2. SingleTable parameter set to false

    Scneario 1:

    SubnetRouteTableAssociationA: always deployed, RouteTableId references RouteTable and RouteTableA (which might not be deployed)
    SubnetA: always deployed
    Vpc: always deployed
    RouteTable: always deployed
    RouteTableA: not deployed due to Condition being false

    """
    deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../templates/stuff.yaml")
    )
