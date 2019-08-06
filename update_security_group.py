'''
Script to refresh AWS security groups to use your current IP address
You need to install requirements.txt with PIP and awscli in your environment
Tested in Python 3.6

Author: Guilherme Junqueira (https://solyd.com.br)
Version: 1.0
License: MIT
'''

import requests
import boto3
from botocore.exceptions import ClientError

ec2 = boto3.client('ec2')

SECURITY_GROUPS = ['sg-05deed7c20eaef752']  # Specify a list with your security groups
IDENTIFIERS = {'udi', 'UDI'}  # Specify a set with descriptions to identify what rules to refresh with your IP


def get_ingress_rules(sg_id):
    try:
        response = ec2.describe_security_groups(GroupIds=[sg_id])
        ingress_rules = response['SecurityGroups'][0]['IpPermissions']
        print(ingress_rules)
        return ingress_rules
    except ClientError as e:
        print(e)


def del_ingress_rule(sg_id, protocol, from_port, to_port, cidr_ip):
    print('Deleting ingress rule')
    try:
        response = ec2.revoke_security_group_ingress(GroupId=sg_id,
                                                     IpProtocol=protocol,
                                                     FromPort=from_port,
                                                     ToPort=to_port,
                                                     CidrIp=cidr_ip)
        print(response)
    except ClientError as e:
        print(e)


def create_ingress_rule(sg_id, protocol, from_port, to_port, cidr_ip, description):
    print('Creating ingress rule')
    try:
        response = ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {'FromPort': from_port,
                 'ToPort': to_port,
                 'IpProtocol': protocol,
                 'IpRanges': [
                     {
                         'CidrIp': cidr_ip,
                         'Description': description
                     },
                 ],
                 }
            ],
        )
        print(response)
    except ClientError as e:
        print(e)


def filter_ingress_rule(sg_id, ingress_rules, new_ip):
    for rule in ingress_rules:
        ip_ranges = rule['IpRanges']
        if ip_ranges:
            for ip in ip_ranges:
                try:
                    description = ip['Description']
                    if description in IDENTIFIERS:
                        from_port = rule['FromPort']
                        to_port = rule['ToPort']
                        protocol = rule['IpProtocol']
                        cidr_ip = ip['CidrIp']
                        del_ingress_rule(sg_id, protocol, from_port, to_port, cidr_ip)
                        create_ingress_rule(sg_id, protocol, from_port, to_port, new_ip + "/32", description)
                except:
                    pass


def get_ip_address():
    try:
        ip = requests.get('https://api.ipify.org').text
        print('My public IP address: {}'.format(ip))
        return ip
    except Exception as e:
        print("Error getting IP address")
        print(e)


if __name__ == '__main__':
    new_ip = get_ip_address()
    if new_ip:
        for sg_id in SECURITY_GROUPS:
            ingress_rules = get_ingress_rules(sg_id)
            if ingress_rules:
                filter_ingress_rule(sg_id, ingress_rules, new_ip)
