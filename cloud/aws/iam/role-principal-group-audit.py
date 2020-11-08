from datetime import datetime
from botocore.config import Config
from botocore.exceptions import ClientError as awsClientError
import time
import boto3
import logging
import traceback
import jmespath

# Logging
logger =logging.getLogger(__name__)
FORMAT = "%(asctime)s — %(relativeCreated)6d — %(threadName)s — %(name)s — %(levelname)s — %(funcName)s:%(lineno)d — %(message)s"
logging.basicConfig(filename="access_advisor-"+str(time.time())+".log", format=FORMAT)
logger.setLevel(logging.DEBUG)

# aws Configuration to escape throttling
config = Config(
   retries = {
                'max_attempts': 10,
                'mode': 'adaptive'
   }
)

def dump_gaa(profile=None):
    global config
    session = boto3.Session(profile_name=profile)
    iam_client = session.client('iam', config=config)
    response = None
    marker = None
    role_details = []
    user_details = []
    policy_details = []
    group_details = []
    while response is None or response.get('IsTruncated'):
        try:
            if marker is None:
                response = iam_client.get_account_authorization_details()
            else:
                response = iam_client.get_account_authorization_details(Marker=marker)

            users = response.get('UserDetailList')
            roles = response.get('RoleDetailList')
            groups = response.get('GroupDetailList')
            policies = response.get('Policies')

            if roles:
                role_details.append(roles)
            if users:
                user_details.append(users)
            if groups:
                group_details.append(groups)
            if policies:
                policy_details.append(policies)
            if response['IsTruncated']:
                marker = response['Marker']
        except awsClientError as error:
            if error.response['Error']['Code'] in [ "RequestTimeout",
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
            else:
                logger.error("Encountered Error: {} !! Exiting .. ".format(error.response['Error']['Code']))
                logger.info(traceback.format_exc())
                logger.error("Omitted the processing for profile :{}".format(profile))
        logger.info("IAM role query for profile {} done!!".format(profile))
    return {"roles": role_details, "groups" : group_details, "users": user_details, "policies": policy_details}

def principal_parser(account_type=None, profile=None, roles=None):
    for section in roles:
        for role in section:
            role_name = role["RoleName"]
            role_arn = role["Arn"]
            principals_federated = jmespath.search("AssumeRolePolicyDocument.Statement[].Principal.Federated[]", role)
            principals_service = jmespath.search('AssumeRolePolicyDocument.Statement[].Principal.Service[]', role)
            principals_account = jmespath.search('AssumeRolePolicyDocument.Statement[].Principal.AWS[]', role)
            if principals_federated:
                for principal in principals_federated:
                    print(" , ".join(["Role-Principal", profile, account_type, role_arn, role_name, principal, "Federated"]))
            if principals_service:
                for principal in principals_service:
                    print(" , ".join(["Role-Principal", profile, account_type, role_arn, role_name, principal, "Service"]))
            if principals_account:
                for principal in principals_account:
                    print(" , ".join(["Role-Principal", profile, account_type, role_arn, role_name, principal, "AWS"]))

def role_parser(account_type=None, profile=None, roles=None):
    for section in roles:
        for role in section:
            role_name = role["RoleName"]
            role_arn = role["Arn"]
            role_created_date = str(role["CreateDate"])
            role_last_used_date = str(jmespath.search('RoleLastUsed.LastUsedDate', role))
            role_last_used_region = str(jmespath.search('RoleLastUsed.Region', role))
            print(" , ".join(["Role-Unused", profile, account_type, role_arn, role_name, role_created_date,
                              role_last_used_date, role_last_used_region]))


def group_parser(account_type=None, profile=None, groups=None, users=None):
    existing_groups = []
    for section in groups:
        for group in section:
            existing_groups.append(group["GroupName"])
    membership = dict()
    for group in existing_groups:
        membership[group] = []
        for section in users:
            for user in section:
                if group in user["GroupList"]:
                    membership[group].append(user["UserName"])

    for group in membership:
        print(", ".join(["Group-Unused", profile, account_type, group, ";".join(membership[group])]))


def user_parser(account_type=None, profile=None, users=None, roles=None):

    existing_rolenames = []
    for section in roles:
        for role in section:
            existing_rolenames.append(role["RoleName"])

    for section in users:
        for user in section:
            user_name = user["UserName"]
            if user_name in existing_rolenames:
                role_exists = "Yes" # In case of k8 user, this should be Yes
            else:
                role_exists = "No"
            user_arn = user["Arn"]
            user_created_date = str(user["CreateDate"])
            user_groups = ";".join(user["GroupList"])
            user_inline_policy_count = "0"
            if user.get("UserPolicyList"):
                user_inline_policy_count = str(len(user.get("UserPolicyList")))
            user_managed_policy_count = str(len(user["AttachedManagedPolicies"]))
            print(", ".join(["User-Unused", profile, account_type, user_arn, user_name, user_created_date, user_groups,
                             role_exists, user_managed_policy_count, user_inline_policy_count]))


if __name__ == "__main__":

    with open('profiles', 'r') as file_in:
        content = file_in.readlines()

    profiles = [profile.replace("\n", "") for profile in content]
    for profile in profiles:
        if profile.lower().__contains__("staging"):
            account_type = "Non-Production"
        else:
            account_type = "Production"
        gaa_details = dump_gaa(profile=profile)
        # Role Principal Relationship
        principal_parser(account_type=account_type, profile=profile, roles=gaa_details["roles"])
        # Unused Roles
        role_parser(account_type=account_type, profile=profile, roles=gaa_details["roles"])
        # Unused Groups
        group_parser(account_type=account_type, profile=profile, groups=gaa_details["groups"],
                     users=gaa_details["users"])
        # Unused Users
        user_parser(account_type=account_type, profile=profile, users=gaa_details["users"], roles=gaa_details["roles"])