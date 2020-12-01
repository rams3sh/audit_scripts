
# Analysing Access Advisor Report

Load the generated csv from the execution of script in this folder and execute the following sqlite query.

This exercise would be useful for organizations in establishing a service level guardrail at AWS Org Level.

### List of Services being utilised across all AWS Accounts
```sqlite3
select ServiceName, ServiceNamespace, MAX(LastAuthenticated) as LatestAccessDate from access_advisor_report where LastAuthenticated not NULL group by ServiceNamespace
```
### List of Services being utilised across all AWS accounts ordered by count of IAM entities using it 
```sqlite3
select ServiceName, ServiceNamespace, MAX(LastAuthenticated) as LatestAccessDate, count(*) as UsingEntitiesCount from access_advisor_report where LastAuthenticated not NULL GROUP by ServiceNamespace order by LastAuthenticated DESC , UsingEntitiesCount DESC
```
Note : Access Advisor report is known to capture even the read only actions.
Hence even visiting an AWS Service through the console can result in it being flagged as being used in access advisor report.
The UsageCount stats would help one to further narrow down the false positives.

### List of Services utilised per account ordered by count of IAM entities using it
```sqlite3
select Account, ServiceName, ServiceNamespace, MAX(LastAuthenticated) as LatestAccessDate, count(*) as UsingEntitiesCount from access_advisor_report where LastAuthenticated not NULL GROUP by Account, ServiceNamespace order by Account ASC, LastAuthenticated DESC , UsingEntitiesCount DESC
``` 
### List of Services utilised per account type (Production of Non-Production) ordered by count of IAM entities using it
```sqlite3
select AccountType, ServiceName, ServiceNamespace, MAX(LastAuthenticated) as LatestAccessDate, count(*) as UsingEntitiesCount from access_advisor_report where LastAuthenticated not NULL GROUP by AccountType, ServiceNamespace order by AccountType ASC, LastAuthenticated DESC , UsingEntitiesCount DESC
```
### List of Services not being utilised across any AWS Accounts
```sqlite3
select DISTINCT ServiceName, ServiceNamespace from access_advisor_report where ServiceNamespace in (select DISTINCT ServiceNamespace from access_advisor_report where LastAuthenticated is NULL
EXCEPT
select DISTINCT ServiceNamespace from access_advisor_report where LastAuthenticated not NULL) 
```
### List of users with permissions 
```sqlite3
select DISTINCT Account, AccountType,Arn, max(LastAuthenticated) as RecentActivity from access_advisor_report where EntityType="User" and ServiceName not NULL GROUP by Arn;
```
### List of users with unused service permissions
```sqlite3
select Account, AccountType, Arn, EntityType, group_concat(ServiceNamespace, ", ") as UnusedServicePermissions from access_advisor_report where EntityType="User" and ServiceName not NULL and LastAuthenticated is NULL group by Arn;
```
### List of users with unused service permissions
```sqlite3
select Account, AccountType, Arn, EntityType, group_concat(ServiceNamespace, ", ") as UnusedServicePermissions from access_advisor_report where EntityType="Role" and ServiceName not NULL and LastAuthenticated is NULL group by Arn;
```