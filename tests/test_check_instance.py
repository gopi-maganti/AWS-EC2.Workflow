# tests/test_check_instance.py
import sys
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.check_instance import (
    _find_running_or_pending_by_tag,
    get_or_create_instance,
    wait_for_ssm_managed,
    run_script_via_ssm,
)


REGION = "us-east-1"
INSTANCE_ID = "i-1234567890abcdef0"
AMI_ID = "ami-0abc12345def67890"
INSTANCE_TYPE = "t3.micro"
TAG_KEY = "Name"
TAG_VALUE = "fruitstore-ec2"


# ---------- _find_running_or_pending_by_tag ----------

@patch("boto3.client")
def test_find_running_or_pending_by_tag_found(mock_boto):
    mock_ec2 = MagicMock()
    mock_ec2.describe_instances.return_value = {
        "Reservations": [{"Instances": [{"InstanceId": INSTANCE_ID}]}]
    }
    mock_boto.return_value = mock_ec2

    iid = _find_running_or_pending_by_tag(
        mock_ec2, tag_key=TAG_KEY, tag_value=TAG_VALUE
    )
    assert iid == INSTANCE_ID
    mock_ec2.describe_instances.assert_called_once()


def test_find_running_or_pending_by_tag_none():
    mock_ec2 = MagicMock()
    mock_ec2.describe_instances.return_value = {"Reservations": []}
    iid = _find_running_or_pending_by_tag(
        mock_ec2, tag_key=TAG_KEY, tag_value=TAG_VALUE
    )
    assert iid is None


# ---------- get_or_create_instance ----------

@patch("boto3.client")
def test_get_or_create_instance_reuse_existing(mock_boto):
    """If an instance with the tag is running/pending, we reuse it and do not call run_instances."""
    mock_ec2 = MagicMock()
    mock_ec2.describe_instances.return_value = {
        "Reservations": [{"Instances": [{"InstanceId": INSTANCE_ID}]}]
    }
    mock_boto.return_value = mock_ec2

    iid = get_or_create_instance(
        region=REGION,
        ami_id=AMI_ID,
        instance_type=INSTANCE_TYPE,
        tag_value=TAG_VALUE,
    )
    assert iid == INSTANCE_ID
    mock_ec2.run_instances.assert_not_called()


@patch("boto3.client")
def test_get_or_create_instance_create_new(mock_boto):
    """When no instance exists, we create and wait for running."""
    mock_ec2 = MagicMock()
    # No existing instance
    mock_ec2.describe_instances.return_value = {"Reservations": []}
    # run_instances returns the new instance id
    mock_ec2.run_instances.return_value = {"Instances": [{"InstanceId": INSTANCE_ID}]}
    # waiter mock
    mock_waiter = MagicMock()
    mock_ec2.get_waiter.return_value = mock_waiter

    mock_boto.return_value = mock_ec2

    iid = get_or_create_instance(
        region=REGION,
        ami_id=AMI_ID,
        instance_type=INSTANCE_TYPE,
        tag_value=TAG_VALUE,
    )
    assert iid == INSTANCE_ID
    mock_ec2.run_instances.assert_called_once()
    mock_ec2.get_waiter.assert_called_once_with("instance_running")
    mock_waiter.wait.assert_called_once_with(InstanceIds=[INSTANCE_ID])


@patch("boto3.client")
def test_get_or_create_instance_with_profile_subnet_sgs_name_form(mock_boto):
    """Validate wiring of IamInstanceProfile (Name), SubnetId, SecurityGroupIds."""
    mock_ec2 = MagicMock()
    mock_ec2.describe_instances.return_value = {"Reservations": []}
    mock_ec2.run_instances.return_value = {"Instances": [{"InstanceId": INSTANCE_ID}]}
    mock_ec2.get_waiter.return_value = MagicMock()
    mock_boto.return_value = mock_ec2

    sgs = ["sg-11111111", "sg-22222222"]
    iid = get_or_create_instance(
        region=REGION,
        ami_id=AMI_ID,
        instance_type=INSTANCE_TYPE,
        tag_value=TAG_VALUE,
        iam_instance_profile="my-ssm-profile",   # Name form
        subnet_id="subnet-aaaa",
        security_group_ids=sgs,
    )
    assert iid == INSTANCE_ID

    # Capture kwargs passed to run_instances
    assert mock_ec2.run_instances.call_count == 1
    kwargs = mock_ec2.run_instances.call_args.kwargs
    assert kwargs["IamInstanceProfile"] == {"Name": "my-ssm-profile"}
    assert kwargs["SubnetId"] == "subnet-aaaa"
    assert kwargs["SecurityGroupIds"] == sgs


@patch("boto3.client")
def test_get_or_create_instance_with_profile_arn_form(mock_boto):
    """Validate IamInstanceProfile ARN usage."""
    mock_ec2 = MagicMock()
    mock_ec2.describe_instances.return_value = {"Reservations": []}
    mock_ec2.run_instances.return_value = {"Instances": [{"InstanceId": INSTANCE_ID}]}
    mock_ec2.get_waiter.return_value = MagicMock()
    mock_boto.return_value = mock_ec2

    profile_arn = "arn:aws:iam::123456789012:instance-profile/ssm-managed"
    _ = get_or_create_instance(
        region=REGION,
        ami_id=AMI_ID,
        instance_type=INSTANCE_TYPE,
        tag_value=TAG_VALUE,
        iam_instance_profile=profile_arn,
    )

    kwargs = mock_ec2.run_instances.call_args.kwargs
    assert kwargs["IamInstanceProfile"] == {"Arn": profile_arn}


@patch("boto3.client")
def test_get_or_create_instance_raises_on_run_error(mock_boto):
    mock_ec2 = MagicMock()
    mock_ec2.describe_instances.return_value = {"Reservations": []}
    mock_ec2.run_instances.side_effect = ClientError(
        error_response={"Error": {"Code": "UnauthorizedOperation", "Message": "nope"}},
        operation_name="RunInstances",
    )
    mock_boto.return_value = mock_ec2

    with pytest.raises(ClientError):
        get_or_create_instance(
            region=REGION,
            ami_id=AMI_ID,
            instance_type=INSTANCE_TYPE,
        )


# ---------- wait_for_ssm_managed ----------

@patch("time.sleep", return_value=None)
@patch("boto3.client")
def test_wait_for_ssm_managed_success(mock_boto, _sleep):
    """SSM returns Online quickly."""
    mock_ssm = MagicMock()
    # First call empty, second call Online
    mock_ssm.describe_instance_information.side_effect = [
        {"InstanceInformationList": []},
        {"InstanceInformationList": [{"PingStatus": "Online"}]},
    ]
    mock_boto.return_value = mock_ssm

    # Should not raise
    wait_for_ssm_managed(INSTANCE_ID, REGION, timeout=30)
    assert mock_ssm.describe_instance_information.call_count >= 2


@patch("time.sleep", return_value=None)
@patch("boto3.client")
def test_wait_for_ssm_managed_timeout(mock_boto, _sleep):
    mock_ssm = MagicMock()
    mock_ssm.describe_instance_information.return_value = {
        "InstanceInformationList": []
    }
    mock_boto.return_value = mock_ssm

    with pytest.raises(TimeoutError):
        wait_for_ssm_managed(INSTANCE_ID, REGION, timeout=1)


# ---------- run_script_via_ssm ----------

@patch("time.sleep", return_value=None)
@patch("boto3.client")
def test_run_script_via_ssm_success(mock_boto, _sleep, tmp_path: Path):
    script = tmp_path / "setup.sh"
    script.write_text("echo hello\n")

    mock_ssm = MagicMock()
    mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-123"}}
    mock_ssm.get_command_invocation.return_value = {
        "Status": "Success",
        "StandardOutputContent": "hello\n",
        "StandardErrorContent": "",
    }
    mock_boto.return_value = mock_ssm

    run_script_via_ssm(INSTANCE_ID, REGION, str(script), timeout_seconds=30)

    mock_ssm.send_command.assert_called_once()
    mock_ssm.get_command_invocation.assert_called()


@patch("time.sleep", return_value=None)
@patch("boto3.client")
def test_run_script_via_ssm_failure_status(mock_boto, _sleep, tmp_path: Path):
    script = tmp_path / "setup.sh"
    script.write_text("exit 1\n")

    mock_ssm = MagicMock()
    mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-999"}}
    mock_ssm.get_command_invocation.return_value = {
        "Status": "Failed",
        "StandardOutputContent": "",
        "StandardErrorContent": "boom",
    }
    mock_boto.return_value = mock_ssm

    with pytest.raises(RuntimeError):
        run_script_via_ssm(INSTANCE_ID, REGION, str(script), timeout_seconds=30)
