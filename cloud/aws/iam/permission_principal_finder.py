import policyuniverse
import time
import boto3
import csv
from botocore.config import Config
from botocore.exceptions import ClientError as awsClientError
import traceback

risky_permission = [	
					'cloudformation:CreateStack',
					'codestar:AssociateTeamMember',
					'codestar:CreateProjectFromTemplate',
					'codestar:CreateProject',
					'datapipeline:CreatePipeline',
					'datapipeline:PutPipelineDefinition',
					'dynamodb:CreateTable',
					'dynamodb:PutItem',
					'ec2:RunInstances',
					'glue:CreateDevEndpoint',
					'glue:GetDevEndpoint',
					'glue:UpdateDevEndpoint',
					'iam:AddUserToGroup',
					'iam:AttachGroupPolicy',
					'iam:AttachRolePolicy',
					'iam:AttachUserPolicy',
					'iam:CreateAccessKey',
					'iam:CreateLoginProfile',
					'iam:CreatePolicyVersion',
					'iam:PassRole',
					'iam:PutGroupPolicy',
					'iam:PutRolePolicy',
					'iam:PutUserPolicy',
					'iam:SetDefaultPolicyVersion',
					'iam:UpdateAssumeRolePolicy',
					'iam:UpdateLoginProfile',
					'lambda:CreateEventSourceMapping',
					'lambda:CreateFunction',
					'lambda:InvokeFunction',
					'lambda:UpdateFunctionCode',
					'sts:AssumeRole',
					'iam:DeleteUserPermissionBoundary',
					'iam:DeleteRolePermissionBoundary'
					]

def get_account_authorization_details(profile=None):
	session = boto3.Session(profile_name=profile)
	# aws Configuration to escape throttling
	config = Config(
		retries={
			'max_attempts': 10,
			'mode': 'adaptive'
		}
	)

	iam_client = session.client('iam', config=config)

	response = None
	marker = None
	while response is None or response.get('IsTruncated'):
		try:
			if marker is None:
				response = iam_client.get_account_authorization_details()
			else:
				response = iam_client.get_account_authorization_details(Marker=marker)

			if response['IsTruncated']:
				marker = response['Marker']
		except awsClientError as error:
			if error.response['Error']['Code'] in [
												"RequestTimeout",
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
				time.sleep(20)
		else:
			print(traceback.format_exc())
	return response

def permission_exists(policy=None, risky_permission=None):
	permission_list=dict()
	expanded_policy = policyuniverse.expand_policy(policy=policy)
	for statement in expanded_policy['Statement']:
		if statement.get('Action'):
			for perm in risky_permission:
				if perm.lower() in statement['Action']:
					if not permission_list.get(perm):
						permission_list[perm]=[]
					permission_list[perm].append({'ActionType':'Action','Sid':statement.get('Sid') ,'Effect':statement['Effect'],'Resource' :statement.get('Resource'),'NotResource':statement.get('NotResource'), 'Condition' :statement.get('Condition')})
		elif statement.get('NotAction'):
			for perm in risky_permission:
				if perm.lower() in policyuniverse.expander_minimizer.get_actions_from_statement(statement):
					if not permission_list.get(perm):
						permission_list[perm]=[]
					permission_list[perm].append({'ActionType':'NotAction','Sid':statement.get('Sid') ,'Effect':statement['Effect'],'Resource' :statement.get('Resource'),'NotResource':statement.get('NotResource'), 'Condition' :statement.get('Condition')})
	return permission_list


def managed_policy_with_risky_permissions(risky_permission=None, ga=None):
	policies = dict()
	for policy in ga['Policies']:
		for version in policy['PolicyVersionList']:
			if version['IsDefaultVersion']:
				permission_check=permission_exists(policy=version['Document'], risky_permission=risky_permission)
				if permission_check:
					for perm in permission_check:
						if not policies.get(perm):
							policies[perm] =[]
						policies[perm].append({policy['Arn']:permission_check[perm]})
						
	return policies

def groups_with_risky_permissions(risky_permission=None,managed_policies_with_risky_permissions=None,ga=None):
	groups=dict()
	for group in ga['GroupDetailList']:
		# Inline Policy
		if group.get('GroupPolicyList'):
			for policy in group['GroupPolicyList']:
				permission_check=permission_exists(policy=policy['PolicyDocument'], risky_permission=risky_permission)
				if permission_check:
					for perm in permission_check:
						
						if not groups.get(perm):
							groups[perm]=dict()
						
						if not groups[perm].get(group['Arn']):
							groups[perm][group['Arn']]=dict()

						groups[perm][group['Arn']][policy['PolicyName']]=permission_check[perm]

		# Managed Policy
		if group.get('AttachedManagedPolicies'):
			for policy in group['AttachedManagedPolicies']:
				policy_arn = policy['PolicyArn']
				for perm in managed_policies_with_risky_permissions:
					for policy in managed_policies_with_risky_permissions[perm]:
						if policy_arn in policy:
							if not groups.get(perm):
									groups[perm]=dict()
							if not groups[perm].get(group['Arn']):
								groups[perm][group['Arn']]=dict()
							groups[perm][group['Arn']][policy_arn]=policy[policy_arn]

	return groups

def users_with_risky_permissions(risky_permission=None, managed_policies_with_risky_permissions=None,groups_with_risky_permissions=None, ga=None):
	users=dict()
	for user in ga['UserDetailList']:
		# Inline Policy
		if user.get('UserPolicyList'):
			for policy in user['UserPolicyList']:
				permission_check=permission_exists(policy=policy['PolicyDocument'], risky_permission=risky_permission)
				if permission_check:
					for perm in permission_check:
						if not users.get(user['Arn']):
							users[user['Arn']]=dict()
						if not users[user['Arn']].get(perm):
							users[user['Arn']][perm]=[]
						users[user['Arn']][perm].append({policy['PolicyName']:permission_check[perm]})

		# Managed Policy
		if user.get('AttachedManagedPolicies'):
			for policy in user['AttachedManagedPolicies']:
				policy_arn = policy['PolicyArn']
				for perm in managed_policies_with_risky_permissions:
					for policy in managed_policies_with_risky_permissions[perm]:
						if policy_arn in policy:
							if not users.get(user['Arn']):
								users[user['Arn']]=dict()
							if not users[user['Arn']].get(perm):
								users[user['Arn']][perm]=[]
							users[user['Arn']][perm].append({policy_arn:policy[policy_arn]})
	
		# Member of Groups with risky permissions
		if user.get('GroupList'):
			for group in user['GroupList']:
				for perm in groups_with_risky_permissions:
					group_arn = user['Arn'].replace("user/"+user['UserName'],"group/"+group)
					if group_arn in groups_with_risky_permissions[perm]:
						if not users.get(user['Arn']):
								users[user['Arn']]=dict()
						if not users[user['Arn']].get(perm):
							users[user['Arn']][perm]=[]
						users[user['Arn']][perm].append({group_arn : groups_with_risky_permissions[perm][group_arn]})
	return users

def roles_with_risky_permissions(risky_permission=None,managed_policies_with_risky_permissions=None,ga=None):
	roles=dict()
	for role in ga['RoleDetailList']:
		# Inline Policy
		if role.get('RolePolicyList'):
			for policy in role['RolePolicyList']:
				permission_check=permission_exists(policy=policy['PolicyDocument'], risky_permission=risky_permission)
				if permission_check:
					for perm in permission_check:	
						if not roles.get(role['Arn']):
							roles[role['Arn']]=dict()
						if not roles[role['Arn']].get(perm):
							roles[role['Arn']][perm]=[]
						roles[role['Arn']][perm].append({policy['PolicyName']:permission_check[perm]})
		# Managed Policy
		if role.get('AttachedManagedPolicies'):
			for policy in role['AttachedManagedPolicies']:
				policy_arn = policy['PolicyArn']
				for perm in managed_policies_with_risky_permissions:
					for policy in managed_policies_with_risky_permissions[perm]:
						if policy_arn in policy:
							if not roles.get(role['Arn']):
								roles[role['Arn']]=dict()
							if not roles[role['Arn']].get(perm):
								roles[role['Arn']][perm]=[]
							roles[role['Arn']][perm].append({policy_arn:policy[policy_arn]})

	return roles


def get_iam_entities_with_risky_permissions(risky_permission=None, ga=None):
	managed_polices = managed_policy_with_risky_permissions(risky_permission=risky_permission,ga=ga)
	groups = groups_with_risky_permissions(risky_permission=risky_permission,managed_policies_with_risky_permissions=managed_polices,ga=ga)
	users=users_with_risky_permissions(risky_permission=risky_permission,
								managed_policies_with_risky_permissions=managed_polices,
								groups_with_risky_permissions=groups,
								ga=ga)
	roles = roles_with_risky_permissions(risky_permission=risky_permission,managed_policies_with_risky_permissions=managed_polices,ga=ga)
	
	return {'roles':roles, 'users':users}

def normalize_policy_record(record=None):
	normalized_records =[]
	for entry in record:
		policy_id = list(entry.keys())[0]
		for permission in entry[policy_id]:
			temp=dict()
			if policy_id.startswith("arn:"):
				temp['ManagedPolicyArn'] = policy_id
				temp['InlinePolicyName'] = None
			else:
				temp['ManagedPolicyArn'] = None
				temp['InlinePolicyName'] = policy_id

			for field in permission:
				temp[field]=permission[field]
			normalized_records.append(temp)
	return normalized_records



def export_csv(iam_entities_with_risky_permissions=None, output=None, profile=None):

	out = open(output, 'a')
	csv_columns = ['Account',
				   'AccountType',
				   'Arn',
				   'EntityType',
				   'MemberOfGroup',
				   'ManagedPolicyArn',
				   'InlinePolicyName',
				   'Action',
				   'ActionType',
				   'Sid',
				   'Effect',
				   'Resource',
				   'NotResource',
				   'Condition'
				   ]
	writer = csv.DictWriter(out, fieldnames=csv_columns)
	writer.writeheader()

	for entity_type in iam_entities_with_risky_permissions:
		for entity_arn in iam_entities_with_risky_permissions[entity_type]:
			for action in iam_entities_with_risky_permissions[entity_type][entity_arn]:
				for record in iam_entities_with_risky_permissions[entity_type][entity_arn][action]:
					for housing_entity in record:
						member_group = None
						if housing_entity.__contains__("group/"):
							member_group = housing_entity
							records=normalize_policy_record(record=[record[housing_entity]])
						else:
							records=normalize_policy_record(record=[record])
						
						for r in records:
							r['Account'] = profile
							if profile.__contains__("staging"):
								r['AccountType'] = 'Non-Production'
							else:
								r['AccountType'] = 'Production'
							r['Arn'] = entity_arn
							r['EntityType'] = entity_type.title()
							r['MemberOfGroup'] = member_group
							r['Action'] =action
							writer.writerow(r)
	out.close()

with open('profiles', 'r') as file_in:
	content = file_in.readlines()

profiles = [profile.replace("\n", "") for profile in content]

for profile in profiles:
	ga = get_account_authorization_details(profile=profile)
	export_csv(iam_entities_with_risky_permissions=get_iam_entities_with_risky_permissions(risky_permission=risky_permission,
																						   ga=ga), output="out.csv", profile=profile)
	print("Completed for Profile :{}".format(profile))

