import unittest
from localstack.utils.aws import aws_stack

IMAGE_ID = 'ami-e4c81199'
DUMMY_INSTANCE_ID = 'ABC'
GROUP_ID = 'sg-1a2b3c4d'


class Ec2Test(unittest.TestCase):

    def setUp(self):
        self.ec2_client = aws_stack.connect_to_service('ec2')

    def test_run_instances(self):
        result_instance = self.ec2_client.run_instances(ImageId=IMAGE_ID, InstanceType='t2.micro', MaxCount=1,
                                                        MinCount=1)
        actual_instance_id = result_instance['Instances'][0]['InstanceId']
        self.assertIsNotNone(actual_instance_id)

    def test_run_and_describe_instances(self):
        result_instance = self.ec2_client.run_instances(ImageId=IMAGE_ID, InstanceType='t2.micro', MaxCount=1,
                                                        MinCount=1)
        actual_instance_id = result_instance['Instances'][0]['InstanceId']
        self.assertIsNotNone(actual_instance_id)

        result = self.ec2_client.describe_instances(InstanceIds=[actual_instance_id])
        instance_id = result['Reservations'][0]['Instances'][0]['InstanceId']
        instance_type = result['Reservations'][0]['Instances'][0]['InstanceType']
        self.assertEqual(actual_instance_id, instance_id)
        self.assertEqual(instance_type, 't2.micro')

    def test_stop_instances(self):
        result_instance = self.ec2_client.run_instances(ImageId=IMAGE_ID, InstanceType='t2.micro', MaxCount=1,
                                                        MinCount=1)
        actual_instance_id = result_instance['Instances'][0]['InstanceId']
        self.assertIsNotNone(actual_instance_id)

        result = self.ec2_client.stop_instances(InstanceIds=[actual_instance_id])
        current_state = result['StoppingInstances'][0]['CurrentState']['Name']
        previous_state = result['StoppingInstances'][0]['PreviousState']['Name']
        self.assertEqual(current_state, 'stopping')
        self.assertEqual(previous_state, 'running')

    def test_start_instances(self):
        result_instance = self.ec2_client.run_instances(ImageId=IMAGE_ID, InstanceType='t2.micro', MaxCount=1,
                                                        MinCount=1)
        actual_instance_id = result_instance['Instances'][0]['InstanceId']
        self.assertIsNotNone(actual_instance_id)

        result = self.ec2_client.start_instances(InstanceIds=[actual_instance_id])
        current_state = result['StartingInstances'][0]['CurrentState']['Name']
        self.assertEqual(current_state, 'pending')

