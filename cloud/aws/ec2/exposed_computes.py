from botocore.config import Config
from botocore.exceptions import ClientError as awsClientError
import boto3
import time
import traceback
import logging
from netaddr import IPNetwork

# Logging
logger =logging.getLogger(__name__)
FORMAT = "%(asctime)s — %(relativeCreated)6d — %(threadName)s — %(name)s — %(levelname)s — %(funcName)s:%(lineno)d — %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

# aws Configuration to escape throttling
config = Config(
   retries = {
                'max_attempts': 10,
                'mode': 'adaptive'
   }
)

def get_regions(profile=None, region=None):
    regions = ["us-east-2",
                "us-east-1",
                "us-west-1",
                "us-west-2",
                "af-south-1",
                "ap-east-1",
                "ap-south-1",
                "ap-northeast-3",
                "ap-northeast-2",
                "ap-southeast-1",
                "ap-southeast-2",
                "ap-northeast-1",
                "ca-central-1",
                "eu-central-1",
                "eu-west-1",
                "eu-west-2",
                "eu-south-1",
                "eu-west-3",
                "eu-north-1",
                "me-south-1",
                "sa-east-1"
               ]
    return regions

def get_security_groups(profile=None, region=None):
    global config
    global global_region_block
    response = None
    client_token_refresh_retry=3
    while True:
        try:
            session = boto3.Session(profile_name=profile)
            response = session.client('ec2', region_name=region, config=config).describe_security_groups()
            break
        except awsClientError as error:
            if error.response['Error']['Code'] in ["RequestTimeout",
                                                   "RequestTimeoutException",
                                                   "PriorRequestNotComplete",
                                                   "ConnectionError",
                                                   "HTTPClientError",
                                                   "Throttling",
                                                   "ThrottlingException",
                                                   "ThrottledException",
                                                   "RequestThrottledException",
                                                   "TooManyRequestsException",
                                                   "ProvisionedThroughputExceededException",
                                                   "TransactionInProgressException",
                                                   "RequestLimitExceeded",
                                                   "BandwidthLimitExceeded",
                                                   "LimitExceededException",
                                                   "RequestThrottled",
                                                   "SlowDown",
                                                   "EC2ThrottledException"]:
                logger.error("Encountered Error: {} !! Sleeping for 5 seconds".format(error.response['Error']['Code']))
                logger.info(traceback.format_exc())
                time.sleep(5)
            elif error.response['Error']['Code'] in ["InvalidClientTokenId"]:
                logger.error("Encountered Error: {} !! Sleeping for 5 seconds".format(error.response['Error']['Code']))
                logger.info(traceback.format_exc())
                time.sleep(5)
                if client_token_refresh_retry == 0:
                    logger.error("Ignoring the attempt since retry attempts are exhausted !!")
                    break
                logger.error("Trying {} more time !!".format(client_token_refresh_retry))
                client_token_refresh_retry -= 1

            else:
                logger.error("Encountered Error: {} !! Ommitting region {} for profile {}".format(error.response['Error']['Code'], region, profile))
                logger.info(traceback.format_exc())
                break
    if response:
        return {"profile": profile,
                "region": region,
                "security_groups": response['SecurityGroups']
                }
    return None

def list_to_ranges(list_values):
    # Link : https: // stackoverflow.com / a / 43531212
    ret = []
    for val in sorted(list_values):
        if not ret or ret[-1][-1]+1 != val:
            ret.append([val])
        else:
            ret[-1].append(val)
    return ",".join([str(x[0]) if len(x)==1 else str(x[0])+"-"+str(x[-1]) for x in ret])


def normalize_ports(permission=None):

    allowed_ports = set()
    if permission.get("IpProtocol") == "-1":
        allowed_ports = set([*range(0, 65536, 1)])
    # 0 is considered as False and misses this check. Hence the additional condition.
    elif permission.get("FromPort") or permission.get("FromPort") == 0:
        # Non ICMP related checks
        # Refer https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-groups.html
        if permission.get("FromPort") >= 0:  # To ignore cases of ICMP codes
            if permission.get("FromPort") == permission.get("ToPort"):
                allowed_ports = set([permission.get("FromPort")])
            else:
                allowed_ports = set([*range(permission.get("FromPort"), permission.get("ToPort") + 1, 1)])
    normalized_ports = list_to_ranges(list_values=list(allowed_ports))
    return normalized_ports

def check_permission(permission=None):

    office_ips = []

    permissions = dict()
    permissions["ips"] = []
    for cidrip in permission.get('IpRanges'):
        p =dict()
        ipv4 = IPNetwork(cidrip.get('CidrIp'))
        p["ip"] = ipv4.__str__()
        if p["ip"] in office_ips:
            p["ip_status"] = "Office IP IPv4"
        elif ipv4.is_private():
            p["ip_status"] = "Private IPv4"
        else:
            p["ip_status"] = "Public IPv4"
        p["description"] = cidrip.get('Description')
        permissions["ips"].append(p)

    for cidripv6 in permission.get('Ipv6Ranges'):
        p = dict()
        ipv6 = IPNetwork(cidripv6.get('CidrIpv6'))
        p["ip"] = ipv6.__str__()
        if p["ip"] in office_ips:
            p["ip_status"] = "Office IP IPv6"
        elif ipv6.is_private():
            p["ip_status"] = "Private IPv6"
        else:
            p["ip_status"] = "Public IPv6"

        p["description"] = cidripv6.get('Description')
        permissions["ips"].append(p)

    if permissions["ips"]:
        permissions["ports"] = normalize_ports(permission=permission)
        if not permissions["ports"]: # In case of icmp
            return
    else:
        # If the permission has mapped security groups , it is of no interest to us
        return

    return permissions


def get_enis(profile=None, region=None):
    global config
    response = None
    next_token = None
    client_token_refresh_retry = 3
    network_interfaces = []
    while response is None or response.get('NextToken'):
        try:
            session = boto3.Session(profile_name=profile)
            if next_token:
                response = session.client('ec2', region_name=region, config=config).describe_network_interfaces(NextToken=next_token)
                network_interfaces += response.get("NetworkInterfaces", [])
            else:
                response = session.client('ec2', region_name=region, config=config).describe_network_interfaces()
            network_interfaces += response.get("NetworkInterfaces", [])
        except awsClientError as error:
            if error.response['Error']['Code'] in ["RequestTimeout",
                                                   "RequestTimeoutException",
                                                   "PriorRequestNotComplete",
                                                   "ConnectionError",
                                                   "HTTPClientError",
                                                   "Throttling",
                                                   "ThrottlingException",
                                                   "ThrottledException",
                                                   "RequestThrottledException",
                                                   "TooManyRequestsException",
                                                   "ProvisionedThroughputExceededException",
                                                   "TransactionInProgressException",
                                                   "RequestLimitExceeded",
                                                   "BandwidthLimitExceeded",
                                                   "LimitExceededException",
                                                   "RequestThrottled",
                                                   "SlowDown",
                                                   "EC2ThrottledException"]:
                logger.error("Encountered Error: {} !! Sleeping for 5 seconds".format(error.response['Error']['Code']))
                logger.info(traceback.format_exc())
                time.sleep(5)
            elif error.response['Error']['Code'] in ["InvalidClientTokenId"]:
                logger.error("Encountered Error: {} !! Sleeping for 5 seconds".format(error.response['Error']['Code']))
                logger.info(traceback.format_exc())
                time.sleep(5)
                if client_token_refresh_retry == 0:
                    logger.error("Ignoring the attempt since retry attempts are exhausted !!")
                    break
                logger.error("Trying {} more time !!".format(client_token_refresh_retry))
                client_token_refresh_retry -= 1

            else:
                logger.error("Encountered Error: {} !! Ommitting region {} for profile {}".format(
                    error.response['Error']['Code'], region, profile))
                logger.info(traceback.format_exc())
                break

    if network_interfaces:
        return network_interfaces
    return []


def return_ingress_details(sg=None):

    ingress = []
    ingress_permissions = sg.get('IpPermissions')
    for permission in ingress_permissions:
        temp = check_permission(permission=permission)
        if temp:
            ingress.append(temp)
    return ingress

if __name__ == "__main__":

    with open('profiles', 'r') as file_in:
        content = file_in.readlines()

    profiles = [profile.replace("\n", "") for profile in content]

    print(",".join(["account","region", "eni_id", "eni_description","eni_public_ip","eni_public_dns", "eni_ip_owner","attached_security_group_id","attached_security_group_name","attached_security_group_description","attached_security_group_permission_description","attached_security_group_permission_allowed_source_ip_type","attached_security_group_permission_allowed_source_ip","attached_security_group_permission_allowed_ports"]))
    for profile in profiles:
        logger.debug("Checking for profile {}".format(profile))
        regions = get_regions(profile=profile, region='us-east-1')
        try:
            # These are new non-default opted-in regions which would require v2 tokens.
            # and default v1 generated tokens may not be applicable.
            # This ignorace of below regions is to save from InvaliClienTokenId Error.
            # Ref : https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html
            regions.pop(regions.index("ap-east-1"))
            regions.pop(regions.index("me-south-1"))
        except Exception as e:
            pass
        for region in regions:
            sgs = dict()
            logger.debug("Checking for region {}".format(region))
            security_group_details = get_security_groups(profile=profile, region=region)

            if security_group_details:
                logger.debug("Security Groups found for profile {}".format(profile))
                profile = security_group_details['profile']
                region = security_group_details['region']

                for sg in security_group_details['security_groups']:
                    sg_description = sg.get('Description')
                    name = sg.get('GroupName')
                    id = sg.get('GroupId')
                    ingress = return_ingress_details(sg)
                    if ingress:
                        sgs[id] = {"description": sg_description, "name":name, "ingress": ingress}
            if sgs:
                for eni in get_enis(profile=profile, region=region):
                    logger.debug("ENIs found for profile {} region {}".format(profile, region))
                    try:
                        if eni.get("Groups"): # NAT Gateway doesnt have security groups and is of no interest to us
                            target_eni_id = eni["NetworkInterfaceId"]
                            target_eni_description = eni["Description"]
                            target_public_ip = eni["Association"]["PublicIp"] # May give KeyError Exception, if instance does not have public ip
                            target_public_dns = eni["Association"]["PublicDnsName"]
                            target_ip_owner_id = eni["Association"]["IpOwnerId"]
                            for group in eni.get("Groups"):
                                sg_id = group['GroupId']
                                sg_name = group['GroupName']
                                sg_description = sgs[group['GroupId']]["description"]
                                for permission in sgs[group['GroupId']]["ingress"]:
                                    sg_permission_allowed_ports = permission["ports"]
                                    for ip in permission["ips"]:
                                        sg_permission_source_ip = ip["ip"]
                                        sg_permission_source_ip_status = ip["ip_status"]
                                        sg_permission_description = ip["description"]
                                        print('","'.join([profile, region, target_eni_id, str(target_eni_description), target_public_ip, str(target_public_dns), target_ip_owner_id, sg_id, str(sg_name), str(sg_description), str(sg_permission_description), sg_permission_source_ip_status, sg_permission_source_ip, sg_permission_allowed_ports]))
                    except KeyError:
                        pass