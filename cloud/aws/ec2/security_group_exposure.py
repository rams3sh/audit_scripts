from botocore.config import Config
from botocore.exceptions import ClientError as awsClientError
import boto3
import time
import jmespath
import traceback
import logging
import re
import sys
from netaddr import IPNetwork

# Logging
logger =logging.getLogger(__name__)
FORMAT = "%(asctime)s — %(relativeCreated)6d — %(threadName)s — %(name)s — %(levelname)s — %(funcName)s:%(lineno)d — %(message)s"
logging.basicConfig(filename="security-group-exposure-"+str(time.time())+".log", format=FORMAT)
logger.setLevel(logging.DEBUG)

# aws Configuration to escape throttling
config = Config(
   retries = {
                'max_attempts': 10,
                'mode': 'adaptive'
   }
)

authorized_ips = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]  # Private IPv4 Ranges

authorized_ports = []

def get_regions(profile=None, region=None):
    while True:
        try:
            session = boto3.Session(profile_name=profile)
            response = session.client('ec2', region_name=region, config=config).describe_regions()
            return jmespath.search('Regions[].RegionName', response)
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
                logger.error("Encountered Error: {} !! Sleeping for 20 seconds".format(error.response['Error']['Code']))
                logger.info(traceback.format_exc())
                time.sleep(20)
            elif error.response['Error']['Code'] in ["UnauthorizedOperation"]:
                logger.error("Encountered Error: {} !! Sleeping for 20 seconds".format(error.response['Error']['Code']))
                logger.info(traceback.format_exc())
                region = "ap-south-1"
                time.sleep(20)
            else:
                logger.error("Encountered Error: {} !! Ommitting region {} for profile {}".format(error.response['Error']['Code'], region, profile))
                logger.info(traceback.format_exc())
                return []

def get_security_groups(profile=None, region=None):
    global config
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
                logger.error("Encountered Error: {} !! Sleeping for 20 seconds".format(error.response['Error']['Code']))
                logger.info(traceback.format_exc())
                time.sleep(20)
            elif error.response['Error']['Code'] in ["InvalidClientTokenId"]:
                logger.error("Encountered Error: {} !! Sleeping for 20 seconds".format(error.response['Error']['Code']))
                logger.info(traceback.format_exc())
                time.sleep(20)
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

def check_unauthorised_ports(permission=None, direction=None):

    global authorized_ports

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

    consolidated_authorised_ports = set()

    for port in authorized_ports:
        if type(port) == str:
            try:
                # Supports range 0-65535
                # Link : https://github.com/cusspvz/proxywrap/blob/9fb60d7f3132d556c5186598248ab2d9ff56303f/lib/proxy-protocol.regexp.js#L85
                if re.match("^([0-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-3][0-9]|6553[0-5])"
                            "\-([0-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-3][0-9]|6553[0-5])$",
                            port):
                    if int(port.split("-")[0]) > int(port.split("-")[1]):
                        raise ValueError("Invalid Range - {}".format(port))
                    consolidated_authorised_ports = consolidated_authorised_ports.union(
                        set([*range(int(port.split("-")[0]), int(port.split("-")[1]) + 1, 1)]))
                else:
                    # Supports port as string
                    consolidated_authorised_ports.add(int(port))
            except ValueError as e:
                print("Check if the provided range is correct. Provide non-zero prefixed numbers as ranges. "
                      "The valid port ranges start with 0 and ends with 65535. Error : {}".format(e))
                sys.exit(1)
        else:
            # Supports port as int
            consolidated_authorised_ports.add(port)
    unauthorised_ports = list_to_ranges(list_values=list(allowed_ports.difference(consolidated_authorised_ports)))
    if unauthorised_ports:
        return "Unauthorised port(s) / port ranges '{}' found in {} !!".format(unauthorised_ports, direction)
    return None

def check_permission(permission=None, direction=None):

    global authorized_ips

    observations =[]
    for cidrip in permission.get('IpRanges'):
        ipv4 = IPNetwork(cidrip.get('CidrIp'))

        if ipv4.is_private():
            ipv4_public_status = "private"
        else:
            ipv4_public_status = "public"

        description = cidrip.get('Description')
        ipv4_present = False
        for ip in authorized_ips:
            if ipv4 in IPNetwork(ip):
                ipv4_present = True
                break
        if not ipv4_present:
            observations.append("Unauthorised {} IPv4 : '{}' with description '{}' found in {} !!".format(ipv4_public_status,
                                                                                                               ipv4, description, direction))
    for cidripv6 in permission.get('Ipv6Ranges'):
        ipv6 = IPNetwork(cidripv6.get('CidrIpv6'))

        if ipv6.is_private():
            ipv6_public_status = "private"
        else:
            ipv6_public_status = "public"

        description = cidripv6.get('Description')
        ipv6_present = False

        for ip in authorized_ips:
            if ipv6 in IPNetwork(ip):
                ipv6_present = True
                break

        if not ipv6_present:
            observations.append("Unauthorised {} IPv6 : '{}' with description '{}' found in {} !!".format(ipv6_public_status,
                                                                                                               ipv6, description, direction))
    unauthorised_port_finding = check_unauthorised_ports(permission=permission, direction=direction)
    if unauthorised_port_finding:
        observations.append(unauthorised_port_finding)
    return observations

def return_sg_findings(sg=None, ingress=True, egress=False):

    finding = []

    if ingress:
        ingress_permissions = sg.get('IpPermissions')
        for permission in ingress_permissions:
            finding += check_permission(permission=permission, direction="ingress")
    if egress:
        egress_permissions = sg.get('IpPermissionsEgress')
        for permission in egress_permissions:
            finding += check_permission(permission=permission, direction="egress")
    return finding

if __name__ == "__main__":

    with open('profiles', 'r') as file_in:
        content = file_in.readlines()

    profiles = [profile.replace("\n", "") for profile in content]

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
            logger.debug("Checking for region {}".format(region))
            security_group_details = get_security_groups(profile=profile, region=region)

            if security_group_details:
                logger.debug("Security Groups found for profile {}".format(profile))
                profile = security_group_details['profile']
                region = security_group_details['region']

                for sg in security_group_details['security_groups']:
                    description = sg.get('Description')
                    name = sg.get('GroupName')
                    id = sg.get('GroupId')
                    findings = return_sg_findings(sg, ingress=True, egress=False)
                    if findings:
                        for finding in findings:
                            print(",".join([profile, region, id, name, description, finding]))
            else:
                logger.debug("No security groups found for profile {}".format(profile))
