Function Export-WMIfilters

{

$ExportWMI=@{}

$WMIFilters=Get-ADObject -Filter 'objectClass -eq "msWMI-Som"' -Properties *
$schemaIDGUID = @{}
$ErrorActionPreference = 'SilentlyContinue'
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID |
 ForEach-Object {$schemaIDGUID.add([System.GUID]$_.schemaIDGUID,$_.name)}
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID |
 ForEach-Object {$schemaIDGUID.add([System.GUID]$_.rightsGUID,$_.name)}
$ErrorActionPreference = 'Continue'

        ForEach ($set in $WMIFIlters) 
        {

                New-Object -TypeName PSObject -Property @{ 

                    'CanonicalName'                   = $Set.CanonicalName
                    'CN'                              = $Set.CN
                    'Created'                         = $Set.Created
                    'createTimeStamp'                 = $Set.createTimeStamp
                    'Deleted'                         = $Set.Deleted
                    'Description'                     = $Set.Description
                    'DisplayName'                     = $Set.DisplayName
                    'DistinguishedName'               = $Set.DistinguishedName
                    'dSCorePropagationData'           = $Set.dSCorePropagationData | Out-String
                    'instanceType'                    = $Set.instanceType
                    'isDeleted'                       = $Set.isDeleted
                    'LastKnownParent'                 = $Set.LastKnownParent
                    'Modified'                        = $Set.Modified
                    'modifyTimeStamp'                 = $Set.modifyTimeStamp
                    'msWMI-Author'                    = $Set.'msWMI-Author'
                    'msWMI-ChangeDate'                = $Set.'msWMI-ChangeDate'
                    'msWMI-CreationDate'              = $Set.'msWMI-CreationDate'
                    'msWMI-ID'                        = $Set.'msWMI-ID'
                    'msWMI-Name'                      = $Set.'msWMI-Name'
                    'msWMI-Parm2'                     = $Set.'msWMI-Parm2'
                    'Name'                            = $Set.Name
                    'ObjectCategory'                  = $Set.ObjectCategory
                    'ObjectClass'                     = $Set.ObjectClass
                    'ObjectGUID'                      = $Set.ObjectGUID
                    'ProtectedFromAccidentalDeletion' = $Set.ProtectedFromAccidentalDeletion
                    'sDRightsEffective'               = $Set.sDRightsEffective
                    'showInAdvancedViewOnly'          = $Set.showInAdvancedViewOnly
                    'uSNChanged'                      = $Set.uSNChanged
                    'uSNCreated'                      = $Set.uSNCreated
                    'whenChanged'                     = $Set.whenChanged
                    'whenCreated'                     = $Set.whenCreated
                    'WriteDebugStream'                = $Set.WriteDebugStream | Out-String
                    'WriteErrorStream'                = $Set.WriteErrorStream | Out-String
                    'WriteInformationStream'          = $Set.WriteInformationStream | Out-String
                    'WriteVerboseStream'              = $Set.WriteVerboseStream | Out-String
                    'WriteWarningStream'              = $Set.WriteWarningStream | Out-String
                    'Owner'                  = $Set.nTSecurityDescriptor.Owner
                    'Permissions'            = $Set.nTSecurityDescriptor.Access | ForEach-Object -Process { 
                                                New-Object -TypeName PSObject -Property @{ 
                                                'ActiveDirectoryRights'  = $_.ActiveDirectoryRights
                                                'InheritanceType'        = $_.InheritanceType
                                                'ObjectType'             = $_.ObjectType
                                                'InheritedObjectType'    = $_.InheritedObjectType
                                                'ObjectFlags'            = $_.ObjectFlags
                                                'AuditFlags'             = $_.AuditFlag
                                                'AccessControlType'     = $_.AccessControlType
                                                'IdentityReference'      = $_.Identityreference
                                                'Is Inherited'            = $_.Isinherited
                                                'Inheritance Flags'       = $_.InheritanceFlags
                                                'Propogation Flags'       = $_.Propogationflags
                                                }   
                   } | Select-Object  `
                   @{name='objectTypeName';expression={if ($_.objectType.ToString() -eq '00000000-0000-0000-0000-000000000000') {'All'} Else {$schemaIDGUID.Item($_.objectType)}}}, `
                   @{name='inheritedObjectTypeName';expression={$schemaIDGUID.Item($_.inheritedObjectType)}}, `
                   * | Out-String

        }
}

}

Export-WMIfilters | Select-Object CanonicalName,CN,Created,createTimeStamp,Deleted,Description,DisplayName,DistinguishedName,dSCorePropagationData,instanceType,isDeleted,LastKnownParent,Modified,modifyTimeStamp,msWMI-Author,msWMI-ChangeDate,msWMI-CreationDate,msWMI-ID,msWMI-Name,msWMI-Parm2,Name,ObjectCategory,ObjectClass,ObjectGUID,ProtectedFromAccidentalDeletion,sDRightsEffective,showInAdvancedViewOnly,uSNChanged,uSNCreated,whenChanged,whenCreated,WriteDebugStream,WriteErrorStream,WriteInformationStream,WriteVerboseStream,WriteWarningStream,Owner | Sort-Object whencreated | Export-Csv ExportWmiFilters.csv
