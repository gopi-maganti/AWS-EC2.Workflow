import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from unittest.mock import patch, MagicMock
from src.check_instance import instance_exists, create_instance, get_instance_public_ip

REGION = "us-east-1"
INSTANCE_ID = "i-1234567890abcdef0"
AMI_ID = "ami-0abc12345def67890"
INSTANCE_TYPE = "t3.micro"
KEY_NAME = "my-key-pair"

@patch("boto3.client")
def test_instance_exists_true(mock_boto):
    mock_ec2 = MagicMock()
    mock_ec2.describe_instances.return_value = {
        'Reservations': [{'Instances': [{'InstanceId': INSTANCE_ID}]}]
    }
    mock_boto.return_value = mock_ec2

    assert instance_exists(INSTANCE_ID, REGION) is True
    mock_ec2.describe_instances.assert_called_once_with(InstanceIds=[INSTANCE_ID])

@patch("boto3.client")
def test_instance_exists_false(mock_boto):
    mock_ec2 = MagicMock()
    mock_ec2.describe_instances.return_value = {
        'Reservations': []
    }
    mock_boto.return_value = mock_ec2

    assert instance_exists(INSTANCE_ID, REGION) is False

@patch("boto3.client")
def test_instance_exists_exception(mock_boto):
    mock_ec2 = MagicMock()
    mock_ec2.describe_instances.side_effect = Exception("Test error")
    mock_boto.return_value = mock_ec2

    assert instance_exists(INSTANCE_ID, REGION) is False

@patch("boto3.client")
def test_create_instance(mock_boto):
    mock_ec2 = MagicMock()

    # Mock run_instances return value
    mock_ec2.run_instances.return_value = {
        'Instances': [{'InstanceId': INSTANCE_ID}]
    }

    # Mock waiter
    mock_waiter = MagicMock()
    mock_ec2.get_waiter.return_value = mock_waiter

    mock_boto.return_value = mock_ec2

    result = create_instance(REGION, AMI_ID, INSTANCE_TYPE, KEY_NAME)

    assert result == INSTANCE_ID
    mock_ec2.run_instances.assert_called_once()
    mock_ec2.get_waiter.assert_called_once_with('instance_running')
    mock_waiter.wait.assert_called_once_with(InstanceIds=[INSTANCE_ID])

@patch("boto3.client")
def test_get_instance_public_ip_found(mock_boto):
    mock_ec2 = MagicMock()
    mock_ec2.describe_instances.return_value = {
        'Reservations': [{
            'Instances': [{
                'InstanceId': INSTANCE_ID,
                'PublicIpAddress': '203.0.113.25'
            }]
        }]
    }
    mock_boto.return_value = mock_ec2

    ip = get_instance_public_ip(INSTANCE_ID, REGION)
    assert ip == '203.0.113.25'

@patch("boto3.client")
def test_get_instance_public_ip_not_found(mock_boto):
    mock_ec2 = MagicMock()
    mock_ec2.describe_instances.return_value = {
        'Reservations': []
    }
    mock_boto.return_value = mock_ec2

    ip = get_instance_public_ip(INSTANCE_ID, REGION)
    assert ip is None
