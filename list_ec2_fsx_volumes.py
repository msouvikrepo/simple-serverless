import boto3
import csv
import io
import threading
from concurrent.futures import ThreadPoolExecutor
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger(__name__)

def lambda_handler(event, context):
    accounts = ['account1', 'account2', 'account3', 'account4', 'account5']
    region = 'aws-region-code'
    role_name = 'lambda_assumerole_manual'
    fsx_details = []
    
    def assume_role(account_id, role_name):
        sts_client = boto3.client('sts')
        try:
            credentials = sts_client.assume_role(
                RoleArn=f'arn:aws:iam::{account_id}:role/{role_name}', 
                RoleSessionName="ec2volumedatapuller"
            )["Credentials"]
            return credentials
        except ClientError as e:
            logger.error(f"Error assuming role for account {account_id}: {e}")
            return None
    
    def get_fsx_volumes(credentials, account_id):
        client = boto3.client(
            'fsx',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=region
        )

        fsx_data = []
        try:
            fsx_response = client.describe_file_systems()['FileSystems']
            for fsx in fsx_response:
                fsx_id = fsx['FileSystemId']
                storage_capacity = fsx['StorageCapacity']
                fsx_name = next((tag['Value'] for tag in fsx['Tags'] if tag['Key'] == 'Name'), 'N/A')
                
                paginator = client.get_paginator('describe_volumes')
                for page in paginator.paginate():
                    for volume in page['Volumes']:
                        if volume['FileSystemId'] == fsx_id:
                            volume_name = volume.get('Name', 'N/A')
                            vol_size = volume['OntapConfiguration']['SizeInMegabytes'] / 1024
                            volume_arn = volume['ResourceARN']
                            
                            vol_tag_details = client.list_tags_for_resource(ResourceARN=volume_arn)
                            ec2_list = [
                                tag['Value'] for tag in vol_tag_details['Tags'] 
                                if tag['Key'] == 'sap_instance'
                            ]
                            if not ec2_list:
                                ec2_list.append('N/A')
                            
                            fsx_data.append({
                                'Fsx_Name': fsx_name,
                                'Fsx_Storage_Capacity': storage_capacity,
                                'Fsx_Volume_Name': volume_name,
                                'Fsx_Volume_Size_In_GB': vol_size,
                                'Fsx_Volume_EC2': ec2_list,
                                'Account_Id': account_id,
                                'Client_Accounting_Number': get_client_accounting_number(credentials, ec2_list)
                            })
        except ClientError as e:
            logger.error(f"Error retrieving FSx volumes for account {account_id}: {e}")
        
        return fsx_data
    
    def get_client_accounting_number(credentials, ec2_list):
        ec2_client = boto3.client(
            'ec2',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=region
        )
        client_accounting_number = 'N/A'
        try:
            ec2_response = ec2_client.describe_instances(
                Filters=[
                    {'Name': 'tag:Name', 'Values': [f"{ec2}.client.com" for ec2 in ec2_list]}
                ]
            )
            for reservation in ec2_response['Reservations']:
                for instance in reservation['Instances']:
                    for tag in instance['Tags']:
                        if tag['Key'] == 'client_accounting_number':
                            return tag['Value']
        except ClientError as e:
            logger.error(f"Error retrieving EC2 instances: {e}")
        
        return client_accounting_number
    
    def process_account(account_id):
        credentials = assume_role(account_id, role_name)
        if credentials:
            return get_fsx_volumes(credentials, account_id)
        return []
    
    # Parallelize the account processing
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_account = {executor.submit(process_account, account): account for account in accounts}
        for future in future_to_account:
            account_fsx_data = future.result()
            if account_fsx_data:
                fsx_details.extend(account_fsx_data)

    # Write data to CSV in memory
    csv_buffer = io.StringIO()
    fieldnames = ['Account_Id', 'Fsx_Name', 'Fsx_Storage_Capacity', 'Fsx_Volume_Name', 'Fsx_Volume_Size_In_GB', 'Fsx_Volume_EC2', 'Client_Accounting_Number']
    writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
    writer.writeheader()
    for detail in fsx_details:
        writer.writerow(detail)

    # Upload CSV file to S3
    s3_client = boto3.client('s3')
    s3_client.put_object(
        Bucket='ec2-storage-report-csv',
        Key='fsx_volumes_28sep_2024.csv',
        Body=csv_buffer.getvalue()
    )

    return {
        'statusCode': 200,
        'body': 'CSV file created and uploaded to S3 successfully.'
    }
