import logging
import boto3
from botocore.exceptions import ClientError, NoRegionError
import csv
import argparse
import os


SESSION_NAME = 'ListResources'

logger = logging.getLogger('aws.list_resources')


def setup_logger():
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)


def count_ec2_instances(sts_creds, region):

    ec2_client = boto3.client('ec2',
                              aws_access_key_id=sts_creds['AccessKeyId'],
                              aws_secret_access_key=sts_creds['SecretAccessKey'],
                              aws_session_token=sts_creds['SessionToken'],
                              region_name=region)

    response = ec2_client.describe_instances()
    instance_count = sum(len(r['Instances']) for r in response['Reservations'])
    while 'NextToken' in response:
        logger.debug('EC2 pagination detected, getting more results')
        response = ec2_client.describe_instances(NextToken=response['NextToken'])
        instance_count += sum(len(r['Instances']) for r in response['Reservations'])

    return instance_count


def count_rds_instances(sts_creds, region):

    rds_client = boto3.client('rds',
                              aws_access_key_id=sts_creds['AccessKeyId'],
                              aws_secret_access_key=sts_creds['SecretAccessKey'],
                              aws_session_token=sts_creds['SessionToken'],
                              region_name=region)

    response = rds_client.describe_db_instances()
    instance_count = len(response['DBInstances'])
    while 'NextToken' in response:
        logger.debug('RDS pagination detected, getting more results')
        response = rds_client.describe_db_instances(NextToken=response['NextToken'])
        instance_count += len(response['DBInstances'])

    return instance_count


def write_output(filename, results):
    # output to csv
    with open(filename, 'wb') as csvfile:
        logger.info('Writing results to [{}]'.format(filename))
        writer = csv.writer(csvfile, quoting=csv.QUOTE_NONNUMERIC)
        writer.writerow(['Account Info', 'EC2 Instances', 'RDS Instances'])
        for account_id in results['accounts'].keys():
            account = results['accounts'][account_id]
            ec2_total = sum([r for r in results['ec2'][account['Id']].values()])
            rds_total = sum([r for r in results['rds'][account['Id']].values()])
            writer.writerow(("{} ({})".format(account['Name'], account['Id']), ec2_total, rds_total))

    return


def assume_role(account_id, role_name):
    sts_client = boto3.client('sts')
    role_arn = 'arn:aws:iam::{}:role/{}'.format(account_id, role_name)

    logger.debug("Assuming Role: {}".format(role_arn))
    new_role = sts_client.assume_role(RoleArn=role_arn, RoleSessionName=SESSION_NAME)

    # return temporary credentials
    return new_role['Credentials']


def main():

    setup_logger()

    # parse command line
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true', help='enable debug logging')
    parser.add_argument('-o', '--output', action='store', required=True, help='csv filename to write output results')
    parser.add_argument('-r', '--rolename', action='store', required=True, help='role name to assume in each account')
    args = parser.parse_args()

    # debug logging
    if args.debug:
        logger.setLevel(logging.DEBUG)

    # get Organization accounts
    organizations_client = boto3.client('organizations')
    response = organizations_client.list_accounts()
    accounts = response['Accounts']

    # store results here
    results = {
        "accounts": {},
        "ec2": {},
        "rds": {}
    }

    for account in accounts:
        account_id = account['Id']
        account_name = account['Name']

        results['accounts'][account_id] = account
        results['ec2'][account_id] = {}
        results['rds'][account_id] = {}

        # assume MasterRole in account
        try:
            creds = assume_role(account_id, args.rolename)
        except ClientError as e:
            logger.error('unable to get assume role for account [{}], error: {}'.format(account_id, e))
            continue

        # get region list
        try:
            regions = boto3.client('ec2',
                                   aws_access_key_id=creds['AccessKeyId'],
                                   aws_secret_access_key=creds['SecretAccessKey'],
                                   aws_session_token=creds['SessionToken']
                                   ).describe_regions()
        except NoRegionError:
            regions = boto3.client('ec2',
                                   aws_access_key_id=creds['AccessKeyId'],
                                   aws_secret_access_key=creds['SecretAccessKey'],
                                   aws_session_token=creds['SessionToken'],
                                   region_name='us-east-1'
                                   ).describe_regions()

        # generate results
        for region in regions['Regions']:
            region_name = region['RegionName']

            # get ec2 numbers
            try:
                ec2_resource_count = count_ec2_instances(creds, region_name)
                results['ec2'][account_id][region_name] = ec2_resource_count
                logger.info('Total [{}] EC2 instances for account [{}] in region [{}]'.format(ec2_resource_count, account_id, region_name))
            except ClientError as e:
                logger.error('unable to get EC2 data from account [{}] for region [{}], error: {}'.format(account_id, region_name, e))

            # get rds numbers
            try:
                rds_resource_count = count_rds_instances(creds, region['RegionName'])
                results['rds'][account_id][region_name] = rds_resource_count
                logger.info('Total [{}] RDS instances for account [{}] in region [{}]'.format(rds_resource_count, account_id, region_name))
            except ClientError as e:
                logger.error('unable to get RDS data from account [{}] for region [{}], error: {}'.format(account_id, region_name, e))

    # write csv
    write_output(args.output, results)

    return 0

if __name__ == '__main__':
    exit(main())
