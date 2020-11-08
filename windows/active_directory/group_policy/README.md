This folder consists of scripts that are used by me to audit Active Directory related controls.

Check out my 2 part series blog on auditing Active Directory Group Policy at

https://rams3sh.blogspot.com/2018/04/learning-from-field-understanding-and.html


Disclaimer : 
------------

Most of the scripts here are not written by me and has been collated and uploaded here from various online sources for easy reference and use. Original source links has been given wherever applicable.

The scripts are very dirty, code wise and have not been optimized and has been compiled just to get the work done. Hence expect some delay times during execution.

Get-FullGPOInfo 
---------------
This script extracts all the Metadata of all existing GPOs in a domain controller.

This script consists of codes from various online sources with little bit of customizations from my side for personal use. The original source of the scripts utilised in this , has been given below.

Big thanks to AshleyMcGlone. This script is a major rip-off from his scripts related to GPOs. 

Source : 
1. https://gallery.technet.microsoft.com/scriptcenter/Get-GPO-informations-b02e0fdf
2. https://gallery.technet.microsoft.com/PowerShell-Script-to-eed7188a
3. https://gallery.technet.microsoft.com/Forensics-Audit-Group-f9c57a1d
4. https://gallery.technet.microsoft.com/Active-Directory-OU-1d09f989t

The script exports the complete GPO details to the file "ExportGPO.csv" in the same path from where the script is being run.
The details that are required to be exported can be edited in the last line of the script.

A sample report "Get-FullGPOInfo_SampleReport.csv" of the output of this comman has been uploaded for reference. Some cells might appear blank,but might have information inside it. One might have to expand the cell in some case to find the details inside. Hence do not go at the face value.

Note: The script execution might prove to be heavy on server depending on the number of GPOs whose details to be queried and extracted.

Get-AllWmiFiltersInfo
---------------------

The script exports the complete GPO details to the file "ExportWMIFilters.csv" in the same path from where the script is being run.
The details that are required to be exported can be edited in the last line of the script.

A sample report "Get-AllWmiFIltersInfo_SampleReport.csv" of the output of this comman has been uploaded for reference. Some cells might appear blank,but might have information inside it. One might have to expand the cell in some case to find the details inside. Hence do not go at the face value.
