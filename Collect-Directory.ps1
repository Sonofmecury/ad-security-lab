[CmdletBinding(DefaultParameterSetName='Directory')]
param(
    [Parameter(Mandatory, ParameterSetName='Directory')][string]$AdminGroup,
    [Parameter(Mandatory, ParameterSetName='Directory')][string[]]$ApprovedAdmin,
    [Parameter(ParameterSetName='Directory')][string[]]$ServiceAccount = @(),
    [Parameter(ParameterSetName='Directory')][string[]]$ManagedServiceAccount = @(),
    [Parameter(Mandatory, ParameterSetName='Share')][string[]]$ShareName
)

$ErrorActionPreference = 'Stop'

if ($PSCmdlet.ParameterSetName -eq 'Share') {
    $shares = foreach ($name in $ShareName) {
        $access = foreach ($entry in Get-SmbShareAccess -Name $name) {
            $identity = [System.Security.Principal.NTAccount]::new($entry.AccountName)
            $sid = $identity.Translate([System.Security.Principal.SecurityIdentifier]).Value
            @{ principal_sid = $sid; type = [string]$entry.AccessControlType; right = [string]$entry.AccessRight }
        }
        @{ name = $name; access = @($access | Where-Object { $null -ne $_ }) }
    }
    @{ shares = @($shares) } | ConvertTo-Json -Depth 8
    return
}

Import-Module ActiveDirectory
$members = Get-ADGroupMember -Identity $AdminGroup -Recursive
$accounts = foreach ($name in $ServiceAccount) {
    $account = Get-ADUser -Identity $name -Properties PasswordNeverExpires
    @{ name = $account.SamAccountName; enabled = $account.Enabled; password_never_expires = $account.PasswordNeverExpires; managed = $false }
}
$managedAccounts = foreach ($name in $ManagedServiceAccount) {
    $account = Get-ADServiceAccount -Identity $name -Properties Enabled
    @{ name = $account.SamAccountName; enabled = $account.Enabled; password_never_expires = $false; managed = $true }
}
@{
    domain_admins = @($members | ForEach-Object { $_.SamAccountName })
    approved_domain_admins = @($ApprovedAdmin)
    service_accounts = @((@($accounts) + @($managedAccounts)) | Where-Object { $null -ne $_ })
} | ConvertTo-Json -Depth 8
