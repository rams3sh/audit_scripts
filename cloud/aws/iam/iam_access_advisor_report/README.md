
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
### List of users, roles along with total service permissions , used service permissions and unused service permissions
```sqlite3
WITH total_service_permissions as (
select Arn, EntityType, group_concat(ServiceNamespace, ", ") as TotalServicePermissions 
from access_advisor_report group by Arn
),
used_service_permissions as (
select Arn, EntityType, group_concat(ServiceNamespace, ", ") as UsedServicePermissions 
from access_advisor_report where LastAuthenticated is not NULL group by Arn
),
 unused_service_permissions as (
select Arn, EntityType, group_concat(ServiceNamespace, ", ") as UnusedServicePermissions 
from access_advisor_report where LastAuthenticated is NULL group by Arn
)

select distinct Arn, EntityType, TotalServicePermissions, UsedServicePermissions, UnusedServicePermissions, 
	IIF( TotalServicePermissions='',0,(LENGTH(TotalServicePermissions) - LENGTH(REPLACE(TotalServicePermissions, ',', '')))+1) as TotalServicePermissionsCount, 
	IIF( UsedServicePermissions='',0,(LENGTH(UsedServicePermissions) - LENGTH(REPLACE(UsedServicePermissions, ',', '')))+1) as UsedServicePermissionsCount, 
	IIF( UnusedServicePermissions='',0,(LENGTH(UnusedServicePermissions) - LENGTH(REPLACE(UnusedServicePermissions, ',', '')))+1) as UnusedServicePermissionsCount
	from (SELECT 
    COALESCE(t.Arn, u.Arn, un.Arn) AS Arn,
    COALESCE(t.EntityType, u.EntityType, un.EntityType) AS EntityType,
    COALESCE(TotalServicePermissions, '') AS TotalServicePermissions,
    COALESCE(UsedServicePermissions, '') AS UsedServicePermissions,
    COALESCE(UnusedServicePermissions, '') AS UnusedServicePermissions
FROM total_service_permissions t
LEFT JOIN used_service_permissions u ON t.Arn = u.Arn
LEFT JOIN unused_service_permissions un ON t.Arn = un.Arn
UNION
SELECT 
    COALESCE(t.Arn, u.Arn, un.Arn) AS Arn,
    COALESCE(t.EntityType, u.EntityType, un.EntityType) AS EntityType,
    COALESCE(TotalServicePermissions, '') AS TotalServicePermissions,
    COALESCE(UsedServicePermissions, '') AS UsedServicePermissions,
    COALESCE(UnusedServicePermissions, '') AS UnusedServicePermissions
FROM used_service_permissions u
LEFT JOIN total_service_permissions t ON u.Arn = t.Arn
LEFT JOIN unused_service_permissions un ON u.Arn = un.Arn
UNION
SELECT 
    COALESCE(t.Arn, u.Arn, un.Arn) AS Arn,
    COALESCE(t.EntityType, u.EntityType, un.EntityType) AS EntityType,
    COALESCE(TotalServicePermissions, '') AS TotalServicePermissions,
    COALESCE(UsedServicePermissions, '') AS UsedServicePermissions,
    COALESCE(UnusedServicePermissions, '') AS UnusedServicePermissions
FROM unused_service_permissions un
LEFT JOIN total_service_permissions t ON un.Arn = t.Arn
LEFT JOIN used_service_permissions u ON un.Arn = u.Arn)
```
