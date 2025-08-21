import boto3
import paramiko
import time
import logging
import argparse
from botocore.exceptions import ClientError, WaiterError

# -----------------------------
# Logging Configuration
# -----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# -----------------------------
# Check if an EC2 instance exists
# -----------------------------
def instance_exists(instance_id, region):
    ec2 = boto3.client("ec2", region_name=region)
    try:
        logger.info(f"Checking if instance {instance_id} exists in region {region}...")
        response = ec2.describe_instances(InstanceIds=[instance_id])
        exists = len(response["Reservations"]) > 0
        if exists:
            logger.info(f"Instance {instance_id} exists.")
        else:
            logger.info(f"Instance {instance_id} does not exist.")
        return exists
    except ClientError as e:
        logger.error(f"Failed to describe instance {instance_id}: {e}")
        return False


# -----------------------------
# Get or create an EC2 instance
# -----------------------------
def get_or_create_instance(region, ami_id, instance_type, key_name, tag_key="Name", tag_value="fruitstore-ec2"):
    ec2 = boto3.client("ec2", region_name=region)

    try:
        logger.info(f"Checking for existing EC2 instance with tag [{tag_key}: {tag_value}] in region {region}...")
        response = ec2.describe_instances(
            Filters=[
                {"Name": f"tag:{tag_key}", "Values": [tag_value]},
                {"Name": "instance-state-name", "Values": ["pending", "running"]}
            ]
        )

        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                logger.info(f"Reusing existing instance: {instance['InstanceId']}")
                return instance["InstanceId"]

    except ClientError as e:
        logger.error(f"Error while describing instances: {e}")
        raise

    try:
        logger.info("No existing instance found. Creating new EC2 instance...")

        instances = ec2.run_instances(
            ImageId=ami_id,
            InstanceType=instance_type,
            KeyName=key_name,
            MinCount=1,
            MaxCount=1,
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [{'Key': tag_key, 'Value': tag_value}]
            }]
        )
        instance_id = instances["Instances"][0]["InstanceId"]
        logger.info(f"Created instance: {instance_id}")

        waiter = ec2.get_waiter("instance_running")
        logger.info("Waiting for instance to enter 'running' state...")
        waiter.wait(InstanceIds=[instance_id])
        logger.info(f"Instance {instance_id} is now running.")
        return instance_id

    except ClientError as e:
        logger.error(f"Failed to create EC2 instance: {e}")
        raise

    except WaiterError as e:
        logger.error(f"Waiter failed while waiting for instance to run: {e}")
        raise

    except Exception as e:
        logger.exception("Unexpected error during instance creation")
        raise


# -----------------------------
# Get public IP of an EC2 instance
# -----------------------------
def get_instance_public_ip(instance_id, region):
    ec2 = boto3.client("ec2", region_name=region)
    try:
        logger.info(f"Fetching public IP for instance {instance_id}...")
        response = ec2.describe_instances(InstanceIds=[instance_id])
        reservations = response.get("Reservations", [])
        if reservations and reservations[0]["Instances"]:
            ip = reservations[0]["Instances"][0].get("PublicIpAddress")
            logger.info(f"Public IP of instance {instance_id}: {ip}")
            return ip
        logger.warning(f"No public IP found for instance {instance_id}.")
        return None
    except ClientError as e:
        logger.error(f"Failed to get public IP for {instance_id}: {e}")
        return None


# -----------------------------
# Run a script over SSH on an EC2 instance
# -----------------------------
def run_script_over_ssh(ip_address, ssh_key_path, script_path, username="ec2-user"):
    logger.info(f"Attempting SSH connection to {ip_address}...")

    try:
        key = paramiko.RSAKey.from_private_key_file(ssh_key_path)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connected = False
        for attempt in range(5):
            try:
                client.connect(hostname=ip_address, username=username, pkey=key, timeout=10)
                connected = True
                break
            except Exception as e:
                logger.warning(f"Attempt {attempt + 1}: SSH not ready. Retrying... ({e})")
                time.sleep(5)

        if not connected:
            raise RuntimeError("SSH connection failed after multiple attempts.")

        logger.info("SSH connection established.")

        with open(script_path, "r") as file:
            commands = file.read()

        logger.info(f"Executing script: {script_path}")
        stdin, stdout, stderr = client.exec_command(commands)

        stdout_output = stdout.read().decode()
        stderr_output = stderr.read().decode()

        logger.info("Script STDOUT:\n" + stdout_output)
        if stderr_output.strip():
            logger.warning("Script STDERR:\n" + stderr_output)

        client.close()

    except Exception as e:
        logger.exception(f"Error running SSH command on EC2 {ip_address}")
        raise


# -----------------------------
# Main Execution Block
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="Check or create EC2 and run setup script")

    parser.add_argument("--region", required=True, help="AWS region")
    parser.add_argument("--ami-id", required=True, help="AMI ID")
    parser.add_argument("--instance-type", required=True, help="EC2 instance type")
    parser.add_argument("--key-name", required=True, help="Key pair name")
    parser.add_argument("--tag-value", default="fruitstore-ec2", help="EC2 tag value")
    parser.add_argument("--ssh-key-path", required=True, help="Path to SSH private key (PEM)")
    parser.add_argument("--script-path", default="scripts/setup.sh", help="Path to setup script")

    args = parser.parse_args()

    # Step 1: Get or create EC2 instance
    instance_id = get_or_create_instance(
        region=args.region,
        ami_id=args.ami_id,
        instance_type=args.instance_type,
        key_name=args.key_name,
        tag_key="Name",
        tag_value=args.tag_value
    )

    # Step 2: Get public IP
    ip_address = get_instance_public_ip(instance_id, args.region)
    if not ip_address:
        logger.error("Public IP could not be retrieved.")
        exit(1)

    # Step 3: Run setup script via SSH
    run_script_over_ssh(ip_address, args.ssh_key_path, args.script_path)


if __name__ == "__main__":
    main()