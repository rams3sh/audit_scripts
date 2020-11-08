# Coded by rams3sh

# Script runs only in non-windows machine due to dependency on jq. Run the following commands before using it
# pip install boto3
# Install jq . Check the following artcle https://stedolan.github.io/jq/download/
# pip install pyjq 
# Usage :-
# python <this_script.py> <profile of the aws account>

import boto3
import pyjq
import json
import sys


def get_iam_entities_arns(session=None):
	iam_client=session.client('iam')
	response = None
	arns = []
	marker = None
	while (response is None or response.get('IsTruncated')):
		if marker is None:
			response = iam_client.get_account_authorization_details()
		else:
			response = iam_client.get_account_authorization_details(Marker=marker)

		users = response.get('UserDetailList')
		roles = response.get('RoleDetailList')
		groups = response.get('GroupDetailList')
		policies = response.get('Policies')

		if users:
			for user in users:
				arns.append(user['Arn'])

		if roles:
			for role in roles:
				arns.append(role['Arn'])

		if groups:
			for group in groups:
				arns.append(group['Arn'])

		if policies:
			for policy in policies:
				arns.append(policy['Arn'])

		if response['IsTruncated']:
			marker = response['Marker']
	return arns

def generate_access_advisor_report(session=None, arn=None):
	iam_client=session.client('iam')
	job_id = iam_client.generate_service_last_accessed_details(Arn=arn).get('JobId')
	return job_id

def get_access_advisor_report(session=None, job_id=None):
	iam_client=session.client('iam')
	marker = None
	output=dict()
	output['ServicesLastAccessed'] =[]
	while True:
		try:
			if marker is None:
				report=iam_client.get_service_last_accessed_details(JobId=job_id)
			else:
				report=iam_client.get_service_last_accessed_details(JobId=job_id,Marker=marker)

			if report.get('JobStatus') in ["COMPLETED","FAILED"]:
				if report.get('IsTruncated'):
					marker = report.get('Marker')
					output['ServicesLastAccessed'] += report['ServicesLastAccessed']
					continue
				else:
					output['ServicesLastAccessed'] += report['ServicesLastAccessed']

					# The following hack is to overcome this issue 
					# https://github.com/doloopwhile/pyjq/issues/28

					output = json.dumps(output, default=str)
					output = json.loads(output)
					return output

			time.sleep(5)
		
		except Exception as e:
			return None


profile_name=sys.argv[1]
session = boto3.Session(profile_name=profile_name)
arns=get_iam_entities_arns(session=session)

job_dict=dict()

# Generate the Job 
for arn in arns:
	job_dict[arn]=generate_access_advisor_report(session=session, arn=arn)


print("Profile,","Arn,","AccountId,","Name,","Type,","Services_Available,","Services_Used,","Services_Unused,","Unused_Percentage")

account_level_services_permissions_provided = set()
account_level_services_used = set()
account_level_services_unused = set()
account_level_services_unused_percent = None

# Get the Job Report
for job_arn in job_dict:
	report = get_access_advisor_report(session=session, job_id=job_dict[job_arn])
	arn=job_arn
	account_id = job_arn.split(":")[4]
	name=job_arn.split("/")[-1] 
	iam_type = job_arn.split(":")[-1].split("/")[0]
	services_available = set(pyjq.all(".ServicesLastAccessed[] | .ServiceNamespace", report))
	account_level_services_permissions_provided = account_level_services_permissions_provided.union(services_available)
	services_used = set(pyjq.all('.ServicesLastAccessed[] | select(.LastAuthenticated != null) | .ServiceNamespace', report))
	account_level_services_used = account_level_services_used.union(services_used)
	services_unused = services_available - services_used
	try:
		unused_percent=(len(services_unused)/len(services_available))*100
	except ZeroDivisionError:
		unused_percent=100
	print(profile_name,",",arn,",",account_id,",",name,",",iam_type,",\"",services_available,"\",\"",services_used,"\",\"",services_unused,"\",",str(unused_percent))

account_level_services_unused = account_level_services_permissions_provided - account_level_services_used

try:
	account_level_services_unused_percent =(len(account_level_services_unused)/len(account_level_services_permissions_provided))*100
except ZeroDivisionError:
	account_level_services_unused_percent=100

print(profile_name,",",account_id,",",profile_name,",","Account",",\"",account_level_services_permissions_provided,"\",\"",account_level_services_used,"\",\"",account_level_services_unused,"\",",str(account_level_services_unused_percent))
