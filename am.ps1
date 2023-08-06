<#
PowerShell File: am.ps1
Author: Zimny65
This module includes the following functions:
- Get-GroupMembers -GroupIdentity 'Domain Admins' (LINE 15)
- Get-AllGroupMembers (LINE 72)
- Get-ObjectRightsWithNames -Identity "Management Department" (LINE 117)
- Get-UserGenericPermissions (LINE 161)
- Get-WritePermissions -Path "C:\Users\Example" (LINE 216)

Import this module to use these functions in your PowerShell session.
USAGE: Import-Module .\am.ps1
#>

function Get-GroupMembers {
<#
.SYNOPSIS
Retrieves members of a specific Active Directory (AD) group.

.DESCRIPTION
The Get-GroupMembers function relies on the PowerView module and uses the Get-NetGroupMember cmdlet to retrieve the list of members for a specific AD group, identified by the GroupIdentity parameter. It checks if the provided GroupIdentity is null or empty and stops the execution if it is. If GroupIdentity is valid, it tries to retrieve the members of the group. If the group has members, it outputs the name of the group and its members. If no members are found, it informs about this. If any error occurs during the retrieval, it catches the error and outputs an error message along with the exception message.

Note: This function requires the PowerView module to be installed and imported in the PowerShell session. Failure to do so will result in cmdlet not found errors.

.PARAMETER GroupIdentity
The identity of the AD group. This should be the distinguished name, a GUID, a security identifier (SID), or a Security Account Manager (SAM) account name.

.EXAMPLE
Get-GroupMembers -GroupIdentity 'Domain Admins'

This command retrieves the members of the AD group named "Domain Admins" 
and outputs the group name followed by the names of its members.
If no members are found, it informs about this. 
If any error occurs during the retrieval, it outputs an error message along with the exception message.
#>

    Param (
        [Parameter(Mandatory=$true)]
        [string]$GroupIdentity
    )

    if([string]::IsNullOrEmpty($GroupIdentity)) {
        Write-Error "GroupIdentity parameter is null or empty."
        return
    }

    # Try to get the group members
    try {
        $members = Get-NetGroupMember $GroupIdentity -ErrorAction Stop | Select-Object -ExpandProperty MemberName

        # If the group has members
        if ($members) {
            # Display the group name
            Write-Output "Group: $GroupIdentity"

            # Display the group members
            foreach ($member in $members) {
                Write-Output "    Member: $member"
            }
        }
        else {
            Write-Output "No members found for group: $GroupIdentity"
        }
    }
    # Catch the error and continue with the next group
    catch {
        Write-Output "Error retrieving members for group: $GroupIdentity"
        Write-Output $_.Exception.Message
    }
}

function Get-AllGroupMembers {
<#
.SYNOPSIS
Retrieves members of all Active Directory (AD) groups using PowerView cmdlets.

.DESCRIPTION
The Get-AllGroupMembers function relies on the PowerView toolkit and uses the Get-NetGroup cmdlet to retrieve all AD groups. For each group, it uses the Get-NetGroupMember cmdlet to retrieve the members of the group.
It attempts to retrieve the members of each group. If a group has members, it outputs the name of the group and its members.
If any error occurs during the retrieval, it catches the error and outputs an error message.

Note: This function requires the PowerView module to be installed and imported in the PowerShell session. Failure to do so will result in cmdlet not found errors.

.EXAMPLE
Get-AllGroupMembers

This command retrieves all the AD groups and their members using PowerView, and outputs the group names followed by their members' names. If any error occurs during the retrieval, it outputs an error message.
#>

    # Getting all the groups
    $groups = Get-NetGroup | Select-Object -ExpandProperty samaccountname

    # For each group
    foreach ($group in $groups) {
        # Try to get the group members
        try {
            $members = Get-NetGroupMember $group -ErrorAction Stop | Select-Object -ExpandProperty MemberName

            # If the group has members
            if ($members) {
                # Display the group name
                Write-Output "Group: $group"
                
                # Display the group members
                foreach ($member in $members) {
                    Write-Output "    Member: $member"
                }
            }
        }
        # Catch the error and continue with the next group
        catch {
            Write-Output "Error retrieving members for group: $group"
        }
    }
}

function Get-ObjectRightsWithNames {
<#
.SYNOPSIS
    Retrieves the list of ACL entries for an AD object, selects those with "GenericAll" rights,
    converts the security identifiers (SIDs) to usernames, and outputs this information.

.DESCRIPTION
    The Get-ObjectRightsWithNames function relies on the PowerView module and uses the Get-ObjectAcl cmdlet to retrieve the list of ACL entries 
    for an Active Directory (AD) object. It selects entries where the ActiveDirectoryRights property equals "GenericAll". 
    For each of these entries, it creates a new PSObject that includes the SecurityIdentifier, 
    the UserName (obtained by converting the SID to a name using Convert-SidToName), 
    and the ActiveDirectoryRights. The function outputs this list of PSObjects.

    Note: This function requires the PowerView module to be installed and imported in the PowerShell session. Failure to do so will result in cmdlet not found errors.

.PARAMETER Identity
    The identity of the AD object. This can be a distinguished name, a GUID, a security identifier (SID), 
    or a Security Account Manager (SAM) account name.

.EXAMPLE
    Get-ObjectRightsWithNames -Identity "Management Department"

    This command retrieves the ACL entries for the AD object named "Management Department", 
    selects those with "GenericAll" rights, converts the SIDs to usernames, 
    and outputs the SecurityIdentifier, UserName, and ActiveDirectoryRights for these entries.
#>


    param (
        [Parameter(Mandatory=$true)]
        [string]$Identity
    )

    Get-ObjectAcl -Identity $Identity | 
    Where-Object {$_.ActiveDirectoryRights -eq "GenericAll"} | 
    ForEach-Object { 
        New-Object PSObject -Property @{
            'SecurityIdentifier' = $_.SecurityIdentifier;
            'UserName' = ($_.SecurityIdentifier | Convert-SidToName);
            'ActiveDirectoryRights' = $_.ActiveDirectoryRights 
        }
    }
}

function Get-UserGenericPermissions {
<#
.SYNOPSIS
Checks the types of generic permissions (GenericAll, GenericWrite, GenericRead, GenericExecute) that the currently logged-in user has for each user in the domain.

.DESCRIPTION
The Get-UserGenericPermissions function retrieves the currently logged-in user with the 'whoami' command and all users in the domain with the Get-NetUser cmdlet.
For each user in the domain, it executes the Get-ObjectAcl cmdlet to retrieve the ACL entries for the user.
It selects entries where the ActiveDirectoryRights property equals one of the four generic rights (GenericAll, GenericWrite, GenericRead, GenericExecute).
For each of these entries, it checks if the logged-in user has that permission for the current user and outputs the result if it does.

.EXAMPLE
Get-UserGenericPermissions

This command retrieves the currently logged-in user and all users in the domain. 
For each user in the domain, it checks the types of generic permissions that the logged-in user has for that user 
and outputs the permissions if any exist.
#>

    # Get current logged-in user
    $LoggedInUser = whoami

    # Get all users in the domain
    $Users = Get-NetUser

    # For each user in the domain
    foreach($User in $Users){
        # Execute the Get-ObjectAcl command for the current user
        $AclResultAll = Get-ObjectAcl -Identity $User.samaccountname | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select @{Name="User"; Expression={(Convert-SidToName $_.SecurityIdentifier)}}, ActiveDirectoryRights
        $AclResultWrite = Get-ObjectAcl -Identity $User.samaccountname | ? {$_.ActiveDirectoryRights -eq "GenericWrite"} | select @{Name="User"; Expression={(Convert-SidToName $_.SecurityIdentifier)}}, ActiveDirectoryRights
        $AclResultRead = Get-ObjectAcl -Identity $User.samaccountname | ? {$_.ActiveDirectoryRights -eq "GenericRead"} | select @{Name="User"; Expression={(Convert-SidToName $_.SecurityIdentifier)}}, ActiveDirectoryRights
        $AclResultExecute = Get-ObjectAcl -Identity $User.samaccountname | ? {$_.ActiveDirectoryRights -eq "GenericExecute"} | select @{Name="User"; Expression={(Convert-SidToName $_.SecurityIdentifier)}}, ActiveDirectoryRights

        # Check if the logged-in user has 'GenericAll' permissions for the current user
        if ($AclResultAll.User -eq $LoggedInUser) {
            Write-Host "$LoggedInUser has GenericAll -> USER: $($User.samaccountname)"
        }

        # Check if the logged-in user has 'GenericWrite' permissions for the current user
        if ($AclResultWrite.User -eq $LoggedInUser) {
            Write-Host "$LoggedInUser has GenericWrite -> USER: $($User.samaccountname)"
        }

        # Check if the logged-in user has 'GenericRead' permissions for the current user
        if ($AclResultRead.User -eq $LoggedInUser) {
            Write-Host "$LoggedInUser has GenericRead -> USER: $($User.samaccountname)"
        }

        # Check if the logged-in user has 'GenericExecute' permissions for the current user
        if ($AclResultExecute.User -eq $LoggedInUser) {
            Write-Host "$LoggedInUser has GenericExecute -> USER: $($User.samaccountname)"
        }
    }
}

function Get-WritePermissions {
<#
.SYNOPSIS
Checks the write permissions for the current user in the specified directory.

.DESCRIPTION
The Get-WritePermissions function iterates through the files and directories within the specified path (or the current directory if no path is provided). It checks whether the current user has write permissions for each file or directory and outputs the full path for those with write permissions.

This function allows system administrators and users to quickly identify the files and directories that they can modify, making it a valuable tool for security and permissions management.

.PARAMETER Path
The directory path where the permissions check is to be performed. The default value is the current directory (".").

.EXAMPLE
Get-WritePermissions

This command checks the write permissions for the current user in the current directory and subdirectories, and outputs the full paths of files and directories with write permissions.

.EXAMPLE
Get-WritePermissions -Path "C:\Users\Example"

This command checks the write permissions for the current user in the specified directory "C:\Users\Example" and its subdirectories, and outputs the full paths of files and directories with write permissions.
#>

    param (
        [string]$path = "."
    )
    Get-ChildItem -Path $path -Recurse -File | ForEach-Object {
        $acl = Get-Acl -Path $_.FullName

        $isCurrentUser = $acl.Access | Where-Object {
            $_.IdentityReference.Value -eq "$($env:USERDOMAIN)\$($env:USERNAME)"
        }

        $hasWritePermission = $acl.Access | Where-Object {
            $_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write
        }

        $isAccessAllowed = $acl.Access | Where-Object {
            $_.AccessControlType -eq 'Allow'
        }

        if ($isCurrentUser -and $hasWritePermission -and $isAccessAllowed) {
            Write-Host $_.FullName
        }
    }
}
