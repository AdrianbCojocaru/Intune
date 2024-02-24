<#PSScriptInfo

.VERSION 1.0

.DATE 02-Oct-2023

.AUTHOR adrian.cojocaru

#>

<#

  .DESCRIPTION
  Creates a csv reports of all existing Intune apps, inluding the assignment groups for each one.
  
  .OUTPUTS
  CSV report

  .EXAMPLE
  .\Get-IntuneApps.ps1

#>

#Region ----------------------------------------------------- [AzureAD Variables] ----------------------------------------------
[string]$TenantId = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "TenantId" }
[string]$ApplicationId = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "AppId" }
[string]$ApplicationSecret = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "AppSecret" }
[string]$Thumbprint = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "CertThumbprint" }

#EndRegion -------------------------------------------------- [AzureAD Variables] ----------------------------------------------
#Region ----------------------------------------------------- [Script Variables] ----------------------------------------------
[version]$Global:ScriptVersion = [version]'1.0.0'
[int]$Global:ExitCode = 0
[int]$Global:GraphTokenRefreshLimit = 24
[int]$Global:GraphTokenRefreshCount = 0
[int]$Global:GatewayTimeoutCountLimit = 128
[int]$Global:GatewayTimeoutCount = 0
[int]$Global:CheckCountLimit = 128
[int]$Global:CheckCount = 0
[System.Management.Automation.ActionPreference]$Global:VerbosePreference = "SilentlyContinue"
#$DateTime = Get-Date -Format yyyy-MM-dd
#EndRegion -------------------------------------------------- [Script Variables] ----------------------------------------------

#Region ----------------------------------------------------- [Classes] ----------------------------------------------
class CustomException : Exception {
    <#

    .DESCRIPTION
    Used to throw exceptions.
    .EXAMPLE
    throw [CustomException]::new( "Get-ErrorOne", "This will cause the script to end with ExitCode 101")

#>
    [string] $additionalData

    CustomException($Message, $additionalData) : base($Message) {
        $this.additionalData = $additionalData
    }
}
#EndRegion -------------------------------------------------- [Classes] ----------------------------------------------
#Region ----------------------------------------------------- [Functions] ----------------------------------------------
Function Write-LogRunbook {
    <#

    .DESCRIPTION
    Write messages to a log file defined by $LogPath and also display them in the console.
    Message format: [Date & Time] [CallerInfo] :: Message Text

#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$Message,
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        # Optional. Specifies the name of the message writter. Function, command or custom name. Defaults to FunctioName or unknown
        [string]$Caller = 'Unknown'
    )
    Begin {
        [string]$LogDateTime = (Get-Date -Format 'MM-dd-yyyy HH\:mm\:ss.fff').ToString()
    }
    Process {
        "[$LogDateTime] [${Caller}] :: $Message" | Write-Verbose -Verbose  
    }
    End {}
}

function Write-ErrorRunbook {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false, Position = 0)]
        [AllowEmptyCollection()]
        # Optional. The errorr collection.
        [array]$ErrorRecord
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        If (-not $ErrorRecord) {
            If ($global:Error.Count -eq 0) {
                Return
            }
            Else {
                [array]$ErrorRecord = $global:Error[0]
            }
        }
    }
    Process {
        [string]$LogDateTime = (Get-Date -Format 'MM-dd-yyyy HH\:mm\:ss.fff').ToString()
        $ErrorRecord | ForEach-Object {
            $errNumber = $ErrorRecord.count - $( $ErrorRecord.IndexOf($_))
            if ($_.Exception.GetType().Name -eq 'CustomException') {
                $ErrorText = "[$LogDateTime] [${CmdletName} Nr. $errNumber] " + `
                    "Line: $($($_.InvocationInfo).ScriptLineNumber) Char: $($($_.InvocationInfo).OffsetInLine) " + `
                    "[$($($_.Exception).Message)] $($($_.Exception).additionalData)" 
            }
            else {
                $ErrorText = "[$LogDateTime] [${CmdletName} Nr. $errNumber] :: $($($_.Exception).Message)`n" + `
                    ">>> Line: $($($_.InvocationInfo).ScriptLineNumber) Char: $($($_.InvocationInfo).OffsetInLine) <<<`n" + `
                    "$($($_.InvocationInfo).Line)"
                if ($ErrorRecord.ErrorDetails.Message) {
                    $ErrorText += $ErrorRecord.ErrorDetails.Message
                }
            }
            $ErrorText | Write-Error
        }
    }
    End {}
}
function Get-Token {
    <#
  .DESCRIPTION
  Get Authentication token from Microsoft Graph (default) or Threat Protection.
  Authentication can be done with a Certificate  Thumbprint (default) or ApplicationId Id & ApplicationSecret.
  $Thumbprint variable needs to be initialized before calling the function
  For ApplicationId & ApplicationSecret the $ApplicationId & $ApplicationSecret variables need to be initialized before calling the function.
 .Example
   Get a token for Graph using certificate thumbprint (default behaviour)
   Get-Token
 .Example
   Get a token for Defender's ThreatProtection using certificate thumbprint
   Get-Token -ThreatProtection
 .Example
   Get a token for Defender's ThreatProtection using ApplicationId & ApplicationSecret
   For ApplicationId & ApplicationSecret the variables need to be defined before calling the function: $ApplicationId & $ApplicationSecret
   Get-Token -TenantId 'abc' -AppId 'xxxxxxxx' -AppSecret 'yyyyyyyyy' -ThreatProtection
#>
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$TenantId = $Global:TenantId,
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$AppId = $Global:ApplicationId,
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$AppSecret = $Global:ApplicationSecret,
        [Parameter(Mandatory = $false, Position = 3)]
        [string]$Storage,
        [Parameter(Mandatory = $false, Position = 4)]
        [string]$AccountUser,
        [Parameter(Mandatory = $false, Position = 5)]
        [string]$AccountPass,
        [Parameter(Mandatory = $false, Position = 6)]
        [switch]$ThreatProtection
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        #$PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
    }
    End {
        try {
            $url = if ($ThreatProtection) { 'https://api.security.microsoft.com' } else { 'https://graph.microsoft.com' }
            Write-LogRunbook "url = $url" -Caller $CmdletName
            if ($AppId) {
                if ($AccountUser) {
                    Write-LogRunbook "AccountUser = $AccountUser; AccountPassLength = $($AccountPass.Length) TenantId = $TenantId" -Caller $CmdletName
                    $body = [Ordered] @{
                        Grant_Type    = "Password"
                        client_Id     = $AppId
                        Client_Secret = $AppSecret
                        Username      = $AccountUser
                        Password      = $AccountPass
                    }
                }
                else {
                    $body = [Ordered] @{
                        grant_type    = 'client_credentials'
                        client_id     = $AppId
                        client_secret = $AppSecret  
                    }
                }
                if ($ThreatProtection) {
                    $oAuthUrl = "https://login.windows.net/$TenantId/oauth2/token"
                    $body.Add('resource', $url)
                }
                else {
                    $oAuthUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" 
                    $body.Add('scope', $url + '/.default')
                }
                Write-LogRunbook "oAuthUrl = $oAuthUrl" -Caller $CmdletName
                Write-LogRunbook "ApplicationId = $AppId; TenantId = $TenantId" -Caller $CmdletName
                #$body | ConvertTo-Json -Compress | Write-LogRunbook
                [string]$Token = (Invoke-RestMethod -Method Post -Uri $oAuthUrl -Body $body -ErrorAction Stop).access_token
            }
            else {
                # certificate auth
                if (-not (Get-AzContext)) {
                    Write-LogRunbook "No AzContext. Running Connect-AzAccount" -Caller $CmdletName
                    Connect-AzAccount -CertificateThumbprint $Thumbprint -ApplicationId $ApplicationId -Tenant $TenantId -ServicePrincipal
                }
                [string]$Token = (Get-AzAccessToken -ResourceUrl $url).Token
            }
            $Token
        }
        catch {
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "Error calling $oAuthUrl")
        }
    }
}
#EndRegion -------------------------------------------------- [Functions] ----------------------------------------------

#Region -------------------------------------------------------- [Main] ----------------------------------------------

[System.Collections.Generic.List[PSCustomObject]]$AppList = @()
$Global:Token = Get-Token -TenantId $TenantId -AppId $ApplicationId -AppSecret $ApplicationSecret
$headers = @{
    Authorization  = "Bearer $Token"
    "Content-type" = "application/json"
}
$url = "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps/"
$response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
if ($response.value) {
    $response.value | ForEach-Object {
        $AppList.Add($_) 
        $_ | Add-Member -NotePropertyName '0_0' -NotePropertyValue $null #Available Included
        $_ | Add-Member -NotePropertyName '0_1' -NotePropertyValue $null #Available Excluded
        $_ | Add-Member -NotePropertyName '1_0' -NotePropertyValue $null #Required Included
        $_ | Add-Member -NotePropertyName '1_1' -NotePropertyValue $null #Required Excluded
        $_ | Add-Member -NotePropertyName '2_0' -NotePropertyValue $null #Uninstall Included
        $_ | Add-Member -NotePropertyName '2_1' -NotePropertyValue $null #Uninstall Excluded
        $_ | Add-Member -NotePropertyName '3_0' -NotePropertyValue $null #availableWithoutEnrollment
    }
}
while ($response.'@odata.nextLink') {
    #Start-Sleep -Seconds 1
    $url = $response.'@odata.nextLink'
    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
    if ($response.value) {
        $response.value | ForEach-Object {
            $_ | Add-Member -NotePropertyName '0_0' -NotePropertyValue $null #Available Included
            $_ | Add-Member -NotePropertyName '0_1' -NotePropertyValue $null #Available Excluded
            $_ | Add-Member -NotePropertyName '1_0' -NotePropertyValue $null #Required Included
            $_ | Add-Member -NotePropertyName '1_1' -NotePropertyValue $null #Required Excluded
            $_ | Add-Member -NotePropertyName '2_0' -NotePropertyValue $null #Uninstall Included
            $_ | Add-Member -NotePropertyName '2_1' -NotePropertyValue $null #Uninstall Excluded
            $_ | Add-Member -NotePropertyName '3_0' -NotePropertyValue $null #availableWithoutEnrollment
            $AppList.Add($_) 
        }
    }
}

$AppList | ForEach-Object {
    $App = $_
    Write-LogRunbook $_.displayName -Caller 'displayname'
    $url = "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps/$($_.id)/assignments"
    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
    if ($response.value) {
        $response.value | ForEach-Object {
            #0_ available   #_0 included
            #1_ required    #_1 excluded
            #2_uninstall
            $Split = $_.id.split('_')[-2] + '_' + $_.id.split('_')[-1]
            $str = $_.id.split('_')[0]
            try {
                $url = "https://graph.microsoft.com/v1.0/groups/$str"
                $response = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -UseBasicParsing -ErrorAction Stop
                $Info = $response.Content | ConvertFrom-Json
                #check this when the group will have a few members..
                if ($Info.displayName) {
                    $displayName = $info.displayName
                    Write-LogRunbook "'$($info.displayName)' group found for '$str'" -Caller $CmdletName
                }
            }
            catch {
                $displayName = $str
                switch ($_.Exception.Response.StatusCode) {
                    'NotFound' { 
                        Write-LogRunbook "AzureAD object '$str' not found." -Caller $CmdletName
                    }
                    Default { 
                        $response.value
                        Write-ErrorRunbook $_
                    }
                }
            } 
            finally {
                $App.$Split += "$displayName;"
            }
        }
    }
}

$AppList | Select-Object -Property displayName, isFeatured, installCommandLine, uninstallCommandLine, 0_0, 0_1, 1_0, 1_1, 2_0, 2_1, 3_0 | Export-Csv -Path "Get-IntuneApps.csv"