<#PSScriptInfo

.VERSION 1.0

.DATE 04-Dec-2023

.AUTHOR adrian.cojocaru

#>

<#
  .SYNOPSIS
  Store info for non-compliant devices in Azure Tables for one or more Compliance Policies.
  It also retrieves the device primary user and user's manager.

  .DESCRIPTION
  Concatenates the results from Microsoft Graph, DeviceManagement and Compliance Policies APIs to create a comprehensive report of noncompliant devices that is stored in Azure Tables.
  It uses a Config.json file. This file contains the Compliance Policy Id and the coresponding Azure Table Name.
  Builds a list of devcies that are not compliant from each Compliance Policy report.
  For each of these devices it gets the device Primary User and their Manager.
  This data is stored in an Azure Table for each Compliance Policy defined in the json file.

  .INPUTS
  N/A. Designed to run inside an azure runbook

  .OUTPUTS
  Verbose output stream logfile

  .EXAMPLE
  .\NeStore-ComplianceStatus.ps1

#>

#Region ----------------------------------------------------- [AzureAD Variables] ----------------------------------------------
[string]$Global:TenantId = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "TenantId" }
[string]$Global:ApplicationId = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "DWC-AppId" }
[string]$Global:Thumbprint = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "DWC-CertThumbprint" }
[string]$SASToken = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "AzTablesSASToken" }
[string]$StorageAccountName = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "StorageAccountName" }
if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { 
    [string]$JsonPath = { Get-AutomationVariable -Name "JsonPath" }
}
else {
    [string]$JsonPath = "Store-ComplianceStatus.json"
}
#EndRegion -------------------------------------------------- [AzureAD Variables] ----------------------------------------------
#Region ----------------------------------------------------- [Script Variables] ----------------------------------------------
[version]$ScriptVersion = [version]'1.0.0'
$Global:ExitCode = 0
$Global:GraphTokenRefreshLimit = 24
$Global:GraphTokenRefreshCount = 0
$Global:GatewayTimeoutCountLimit = 128
$Global:GatewayTimeoutCount = 0
$VerbosePreference = "SilentlyContinue"
$DateTime = Get-Date -Format yyyy-MM-dd
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
        [string]$CertThumbprint = $Global:Thumbprint,
        [Parameter(Mandatory = $false, Position = 7)]
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
            if ($AppSecret) {
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
                    Connect-AzAccount -CertificateThumbprint $CertThumbprint -ApplicationId $AppId -Tenant $TenantId -ServicePrincipal
                }
                Write-Host "Connect-AzAccount -CertificateThumbprint $CertThumbprint -ApplicationId $AppId -Tenant $TenantId -ServicePrincipal"
                Write-Host "Get-AzAccessToken -ResourceUrl $url"
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
function Get-JsonContent {
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$JsonFilePath,
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [switch]$Web
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
    }
    End {
        try {
            if ($Web) {
                #Invoke-RestMethod 'https://stfnemeamemtransfer.blob.core.windows.net/testac/AdvancedHuntingTestQueries.json?sp=r&st=2023-08-06T19:49:39Z&se=2024-08-07T03:49:39Z&spr=https&sv=2022-11-02&sr=b&sig=3RlsQZ6vTbur%2F6T4YPDK7izF525uobv4zCJbZypjp4M%3D' -ErrorAction Stop
                Invoke-RestMethod $JsonFilePath -ErrorAction Stop
            }
            else {
                if (Test-Path $JsonPath) {
                    Get-Content $JsonPath -Raw | ConvertFrom-Json 
                }
                else { throw "File not found: $JsonPath" }
            }
        }
        catch {
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "Error calling json url")
        }
    }
    
}

function  Get-UserManager {
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$Token,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$UserPrincipalName,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$ObjectId
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        if (-not $HideParams) { $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { if ($_.Key -notlike "*token*") { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName } } }
    }
    End {
        try {
            $headers = @{ 'Authorization' = "Bearer $Tokenh" }
            if ($UserPrincipalName) {
                $url = "https://graph.microsoft.com/v1.0/users/$UserPrincipalName/manager"
            }
            elseif ($ObjectId) {
                $url = "https://graph.microsoft.com/v1.0/users/$ObjectId/manager"
            }
            else { 
                throw 'UserPrincipalName & ObjectId cannot be both empty!' 
            }
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -UseBasicParsing -ErrorAction Stop
            $response.Content | ConvertFrom-Json
            #check this when the group will have a few members..
            #($response.Content | ConvertFrom-Json).value | Select-Object -Property 'id', 'displayName', 'givenName', 'surname' , 'mail' | Out-String | Write-LogRunbook -Caller $CmdletName
        }
        catch {
            $CurrentError = $_
            switch ($_.Exception.Response.StatusCode) {
                'NotFound' {
                    "StatusCode: '$($($($CurrentError.Exception).Response).StatusCode)'; StatusDescription: '$($($CurrentError.Exception).Message)'; url: '$url'" | Write-LogRunbook -Caller $CmdletName
                }
                'Unauthorized' {
                    if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                        "StatusCode: '$($($($CurrentError.Exception).Response).StatusCode)'; StatusDescription: '$($($CurrentError.Exception).Message)'; GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'; url: '$url'" | Write-LogRunbook -Caller $CmdletName
                        $Global:Token = Get-Token -TenantId $Global:TenantId -AppId $Global:ApplicationId -CertThumbprint $Global:Thumbprint
                        $PSBoundParameters.Token = $Global:Token
                        $Global:GraphTokenRefreshCount++
                        Get-IntuneDevcieInfo @PSBoundParameters
                    }
                    else {
                        Write-ErrorRunbook
                        throw [CustomException]::new( $CmdletName, "GraphTokenRefreshLimit '$Global:GraphTokenRefreshCount' reached! ")
                    }
                }
                Default {
                    Write-ErrorRunbook
                    throw [CustomException]::new( $CmdletName, "StatusCode: '$($($($CurrentError.Exception).Response).StatusCode)'; StatusDescription: '$($($CurrentError.Exception).Message)'; url: '$url'")
                }
            } 
        }
    }
} 


function Get-IntuneDevcieInfo {
    <#
  .DESCRIPTION
  Gets the Intune information about a device

 .Example
   Get-IntuneDevcieInfo -Token $Token -DeviceName 'us-467995179101'
   Get-IntuneDevcieInfo -Token $Token -IntuneDeviceId '066b2ce2-f103-4522-882f-55c19fffb6e5'
#>
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$Token,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$IntuneDeviceId,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$AzureADDeviceId,
        [Parameter(Mandatory = $false, Position = 3, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$DeviceName,
        [Parameter(Mandatory = $false, Position = 4, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$ComplianceForPolicyId,
        [Parameter(Mandatory = $false, Position = 5, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [switch]$HideParams
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        if (-not $HideParams) { $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { if ($_.Key -notlike "*token*") { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName } } }
    }
    End {
        $headers = @{
            Authorization  = "Bearer $Token"
            "Content-type" = "application/json"
        }
        try {
            #New-DWLicMNGTLogAnalyticsEvent -Log_Message "Uploading hardware hash to Myizhora tenant for $($ComputerName)" -Severity "Information" -Computer "$($ComputerName)" -Operation "Import"
            if ($IntuneDeviceId) {
                $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$IntuneDeviceId"
            }
            elseif ($AzureADDeviceId) {
                $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/?`$filter=azureADDeviceId%20eq%20'$AzureADDeviceId'"
            }
            else {
                $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/?`$filter=deviceName%20eq%20'$DeviceName'"
            }
            try {
                $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
                if ($ComplianceForPolicyId) {
                    if ($response) {
                        $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$IntuneDeviceId/deviceCompliancePolicyStates"
                        $ComplianceResponse = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
                        $MatchingCompliancePolicies = $ComplianceResponse.value | Where-Object { $_.id -eq $ComplianceForPolicyId }                  
                    }
                    # not done yet!!!
                }
                # $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/a0e970e1-c6b6-4579-aaa3-00598a11e916/deviceCompliancePolicyStates" also works
            }
            catch {
                $CurrentError = $_
                switch ($_.Exception.Response.StatusCode) {
                    'NotFound' {
                        "StatusCode: '$($($($CurrentError.Exception).Response).StatusCode)'; StatusDescription: '$($($CurrentError.Exception).Message)'; url: '$url'" | Write-LogRunbook -Caller $CmdletName
                    }
                    'Unauthorized' {
                        if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                            "StatusCode: '$($($($CurrentError.Exception).Response).StatusCode)'; StatusDescription: '$($($CurrentError.Exception).Message)'; GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'; url: '$url'" | Write-LogRunbook -Caller $CmdletName
                            $Global:Token = Get-Token -TenantId $Global:TenantId -AppId $Global:ApplicationId -CertThumbprint $Global:Thumbprint
                            $PSBoundParameters.Token = $Global:Token
                            $Global:GraphTokenRefreshCount++
                            Get-IntuneDevcieInfo @PSBoundParameters
                        }
                        else {
                            Write-ErrorRunbook
                            throw [CustomException]::new( $CmdletName, "GraphTokenRefreshLimit '$Global:GraphTokenRefreshCount' reached! ")
                        }
                    }
                    Default {
                        Write-ErrorRunbook
                        throw [CustomException]::new( $CmdletName, "StatusCode: '$($($($CurrentError.Exception).Response).StatusCode)'; StatusDescription: '$($($CurrentError.Exception).Message)'; url: '$url'")
                    }
                } 
            }
            if ($IntuneDeviceId) {
                if (-not $HideParams) { $response | ConvertTo-Json -Compress | Write-LogRunbook -Caller $CmdletName }
                $response
            }
            else {
                "The request returned $($response.'@odata.count') device(s)." | Write-LogRunbook -Caller $CmdletName
                if (-not $HideParams) { $response.value | ConvertTo-Json -Compress | Write-LogRunbook -Caller $CmdletName }
                $response.value
            }
        }
        catch {
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "Check the above error calling '$url'")
        } 
    }      
}

function Get-deviceComplianceDeviceStatus {
    #https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/1559f885-4ca8-4d2f-8927-7450634a123f/deviceRunStates/?$expand=*
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Optional. Powershell Health scripts (remediation + detection)
        [string]$deviceCompliancePolicyId
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
        $StatusesList = @()
        $count = 0
    }
    End {
        try {
            $headers = @{ 'Authorization' = "Bearer $Token" }
            $url = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/{$deviceCompliancePolicyId}/deviceStatuses"
            #$ComplianceFilter = "?`$filter=userPrincipalName ne 'nonCompliant'"
            #or
            ##$ComplianceFilter = "?`$filter=userPrincipalName ne 'System account'"
            #$NewUrl = $url + $ComplianceFilter
            #https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/{ffae1e8a-1102-4fb4-a546-cb2a52a41a1f}/deviceStatuses?$filter=status eq 'nonCompliant'
            #Invoke-RestMethod : The remote server returned an error: (501) Not Implemented.1"
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
            #($response.Content | ConvertFrom-Json).value
            if ($response.value) { $StatusesList += $response.value }
            while ($response.'@odata.nextLink') {
                $count++
                Write-LogRunbook "nextLink nr $count" -Caller $CmdletName
                #Start-Sleep -Seconds 1
                $response = Invoke-RestMethod -Headers $headers -Uri $response.'@odata.nextLink' -Method Get -ErrorAction Stop
                if ($response.value) { $StatusesList += $response.value }
            }
            $StatusesList
        }
        catch {
            switch ($_.Exception.Response.StatusCode) {
                'Unauthorized' {
                    if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                        Write-LogRunbook "Token expired. Getting a new one. GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'" -Caller $CmdletName
                        $Global:Token = Get-Token -TenantId $Global:TenantId -AppId $Global:ApplicationId -CertThumbprint $Global:Thumbprint
                        $Global:GraphTokenRefreshCount++
                        Get-deviceComplianceDeviceStatus @PSBoundParameters
                    }
                    else {
                        Write-ErrorRunbook
                        throw [CustomException]::new( $CmdletName, "GraphTokenRefreshLimit '$Global:GraphTokenRefreshCount' reached! ")
                    }
                }
                'NotFound' { 
                    Write-LogRunbook "AzureAD object not found." -Caller $CmdletName
                }
                'GatewayTimeout' {
                    if ($Global:GatewayTimeoutCount -lt $Global:GatewayTimeoutCountLimit) {
                        Write-LogRunbook "(504) Gateway Timeout counter: $Global:GatewayTimeoutCount. Retrying." -Caller $CmdletName
                        Start-Sleep -Seconds 2
                        $Global:GatewayTimeoutCount++
                        Get-deviceComplianceDeviceStatus @PSBoundParameters
                    }
                    else {
                        Write-ErrorRunbook
                        throw [CustomException]::new( $CmdletName, "GatewayTimeoutCountLimit '$Global:GatewayTimeoutCountLimit' reached! ")
                    }
                }
                Default {
                    Write-ErrorRunbook
                    throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling '$url'")
                }
            }
        }
    } 
}
function Get-IntuneDevcieInfo {
    <#
  .DESCRIPTION
  Gets the Intune information about a device

 .Example
   Get-IntuneDevcieInfo -Token $Token -DeviceName 'us-467995179101'
   Get-IntuneDevcieInfo -Token $Token -IntuneDeviceId '066b2ce2-f103-4522-882f-55c19fffb6e5'
#>
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$Token,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$IntuneDeviceId,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$AzureADDeviceId,
        [Parameter(Mandatory = $false, Position = 3, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$DeviceName,
        [Parameter(Mandatory = $false, Position = 4, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$ComplianceForPolicyId,
        [Parameter(Mandatory = $false, Position = 5, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [switch]$HideParams
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        if (-not $HideParams) { $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { if ($_.Key -notlike "*token*") { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName } } }
    }
    End {
        $headers = @{
            Authorization  = "Bearer $Token"
            "Content-type" = "application/json"
        }
        try {
            #New-DWLicMNGTLogAnalyticsEvent -Log_Message "Uploading hardware hash to Myizhora tenant for $($ComputerName)" -Severity "Information" -Computer "$($ComputerName)" -Operation "Import"
            if ($IntuneDeviceId) {
                $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$IntuneDeviceId"
            }
            elseif ($AzureADDeviceId) {
                $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/?`$filter=azureADDeviceId%20eq%20'$AzureADDeviceId'"
            }
            else {
                $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/?`$filter=deviceName%20eq%20'$DeviceName'"
            }
            try {
                $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
                if ($ComplianceForPolicyId) {
                    if ($response) {
                        $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$IntuneDeviceId/deviceCompliancePolicyStates"
                        $ComplianceResponse = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
                        $MatchingCompliancePolicies = $ComplianceResponse.value | Where-Object { $_.id -eq $ComplianceForPolicyId }                  
                    }
                    # not done yet!!!
                }
                # $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/a0e970e1-c6b6-4579-aaa3-00598a11e916/deviceCompliancePolicyStates" also works
            }
            catch {
                $CurrentError = $_
                switch ($_.Exception.Response.StatusCode) {
                    'NotFound' {
                        "StatusCode: '$($($($CurrentError.Exception).Response).StatusCode)'; StatusDescription: '$($($CurrentError.Exception).Message)'; url: '$url'" | Write-LogRunbook -Caller $CmdletName
                    }
                    'Unauthorized' {
                        if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                            "StatusCode: '$($($($CurrentError.Exception).Response).StatusCode)'; StatusDescription: '$($($CurrentError.Exception).Message)'; GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'; url: '$url'" | Write-LogRunbook -Caller $CmdletName
                            $Global:Token = Get-Token -TenantId $Global:TenantId -AppId $Global:ApplicationId -CertThumbprint $Global:Thumbprint
                            $PSBoundParameters.Token = $Global:Token
                            $Global:GraphTokenRefreshCount++
                            Get-IntuneDevcieInfo @PSBoundParameters
                        }
                        else {
                            Write-ErrorRunbook
                            throw [CustomException]::new( $CmdletName, "GraphTokenRefreshLimit '$Global:GraphTokenRefreshCount' reached! ")
                        }
                    }
                    Default {
                        Write-ErrorRunbook
                        throw [CustomException]::new( $CmdletName, "StatusCode: '$($($($CurrentError.Exception).Response).StatusCode)'; StatusDescription: '$($($CurrentError.Exception).Message)'; url: '$url'")
                    }
                } 
            }
            if ($IntuneDeviceId) {
                if (-not $HideParams) { $response | ConvertTo-Json -Compress | Write-LogRunbook -Caller $CmdletName }
                $response
            }
            else {
                "The request returned $($response.'@odata.count') device(s)." | Write-LogRunbook -Caller $CmdletName
                if (-not $HideParams) { $response.value | ConvertTo-Json -Compress | Write-LogRunbook -Caller $CmdletName }
                $response.value
            }
        }
        catch {
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "Check the above error calling '$url'")
        } 
    }      
}
function  Get-AzureTableEntities {
    <#
  .DESCRIPTION
  Returns all entries in an Azure Table.

 .Example
   Get-AzureTableEntities -StorageAccountName $StorageAccountName -TableName q2q -filter "PartitionKey%20gt%20'2023-12-01'"
#>
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$StorageAccountName,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$TableName,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$filter
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
        $TableData = New-Object System.Collections.Generic.List[System.Object]
    }
    End {

        try {
            $GMTTime = (Get-Date).ToUniversalTime().toString('R')
            $headers = @{
                'x-ms-date' = $GMTTime;
                Accept      = 'application/json;odata=nometadata'
            }
            $url = "https://$StorageAccountName.table.core.windows.net/${TableName}${SASToken}"
            if ($filter) { 
                $url += "&`$filter=$filter"
            }
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -UseBasicParsing -ErrorAction Stop
            ($response.Content | ConvertFrom-Json).value | ForEach-Object { $TableData.Add($_) } # 26 Milliseconds
            while ($response.Headers.'x-ms-continuation-NextPartitionKey') {
                $NextRowKey = $response.Headers.'x-ms-continuation-NextRowKey'
                $NextPartitionKey = $response.Headers.'x-ms-continuation-NextPartitionKey'
                Write-LogRunbook "NextPartitionKey = '$NextPartitionKey' NextRowKey = '$NextRowKey'" -Caller $CmdletName
                #https://myaccount.table.core.windows.net/Customers?NextPartitionKey=1!8!U21pdGg-&NextRowKey=1!12!QmVuMTg5OA--
                $url = "https://$StorageAccountName.table.core.windows.net/${TableName}${SASToken}&NextPartitionKey=$NextPartitionKey&NextRowKey=$NextRowKey"
                if ($filter) { 
                    $url += "&`$filter=$filter"
                }
                $response = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -UseBasicParsing -ErrorAction Stop
                ($response.Content | ConvertFrom-Json).value |  ForEach-Object { $TableData.Add($_) }
            }
            Write-LogRunbook "$($TableData.count) entities found." -Caller $CmdletName
            $TableData
        }
        catch {
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling '$url'")
        }
    }
}
function  Add-AzureTableEntities {
    <#
  .DESCRIPTION
  Adds one or more AzureTableEntities.
  https://learn.microsoft.com/en-us/rest/api/storageservices/performing-entity-group-transactions
  https://stackoverflow.com/questions/36268925/powershell-invoke-restmethod-multipart-form-data

 .Example
   $devicesComplianceDeviceStatusFiltered | Add-AzureTableEntities -StorageAccountName $StorageAccountName -TableName $TableName
#>
    #https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/1559f885-4ca8-4d2f-8927-7450634a123f/deviceRunStates/?$expand=*
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$StorageAccountName,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$TableName,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [pscustomobject]$Entity
        
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
        $GMTTime = (Get-Date).ToUniversalTime().toString('R')
        $headers = @{
            'x-ms-date'    = $GMTTime;
            Accept         = 'application/json;odata=nometadata';
            'Content-Type' = 'application/json'
        }
        $url = "https://$StorageAccountName.table.core.windows.net/${TableName}${SASToken}"
    }
    Process {
        try {
            $bodyJSON = $Entity | ConvertTo-Json -Compress
            Write-LogRunbook $bodyJSON -Caller $CmdletName
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Body $bodyJSON -Method Post -ErrorAction Stop
        }
        catch {
            if (($_.Exception.StatusCode -eq 'Conflict') -or ($_.Exception.Response.StatusCode -eq 'Conflict')) {
                #ps7 vs ps5
                Write-LogRunbook ($_.ErrorDetails.Message | ConvertFrom-Json).'odata.error'.code -Caller $CmdletName
                $message = ($_.ErrorDetails.Message | ConvertFrom-Json).'odata.error'.message.value.Replace("`n", "\n")
                Write-LogRunbook $message -Caller $CmdletName
            }
            else {    
                Write-ErrorRunbook
                throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling '$url'")
            }
        }
    }
    End {
    } 
}
function  Remove-AzureTableEntities {
    <#
  .DESCRIPTION
  Removes one or more AzureTableEntities.
  https://learn.microsoft.com/en-us/rest/api/storageservices/performing-entity-group-transactions
  https://stackoverflow.com/questions/36268925/powershell-invoke-restmethod-multipart-form-data

 .Example
    $b | Remove-AzureTableEntities -StorageAccountName $StorageAccountName -TableName q1q
#>
    #https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/1559f885-4ca8-4d2f-8927-7450634a123f/deviceRunStates/?$expand=*
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$StorageAccountName,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$TableName,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [pscustomobject]$Entity
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
        $GMTTime = (Get-Date).ToUniversalTime().toString('R')
        $headers = @{
            'x-ms-date' = $GMTTime;
            Accept      = 'application/json;odata=nometadata';
            'If-Match'  = "*"
        }
    }
    Process {
        try {
            #https://myaccount.table.core.windows.net/mytable(PartitionKey='myPartitionKey', RowKey='myRowKey')
            $url = "https://$StorageAccountName.table.core.windows.net/${TableName}(PartitionKey='$($Entity.PartitionKey)',RowKey='$($Entity.RowKey)')${SASToken}"
            $EntityJson = $Entity | ConvertTo-Json -Compress
            Write-LogRunbook $EntityJson -Caller $CmdletName
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method DELETE -ErrorAction Stop
        }
        catch {
            if (($_.Exception.StatusCode -eq 'NotFound') -or ($_.Exception.Response.StatusCode -eq 'NotFound')) {
                Write-LogRunbook ($_.ErrorDetails.Message | ConvertFrom-Json).'odata.error'.code -Caller $CmdletName
                $message = ($_.ErrorDetails.Message | ConvertFrom-Json).'odata.error'.message.value.Replace("`n", "\n")
                Write-LogRunbook $message -Caller $CmdletName
            }
            else {    
                Write-ErrorRunbook
                throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling '$url'")
            }
        }
    }
    End {
    } 
}
function  Update-AzureTableEntities {
    <#
  .DESCRIPTION
  Udates an existing entity, or inserts a new entity if it doesn't exist in the table

 .Example
    $b | Update-AzureTableEntities -StorageAccountName $StorageAccountName -TableName q1q
#>
    #https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/1559f885-4ca8-4d2f-8927-7450634a123f/deviceRunStates/?$expand=*
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$StorageAccountName,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$TableName,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [pscustomobject]$Entity
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
        $GMTTime = (Get-Date).ToUniversalTime().toString('R')
        $headers = @{
            'x-ms-date'    = $GMTTime;
            Accept         = "application/json;odata=nometadata";
            "Content-type" = "application/json"
        }
    }
    Process {
        try {
            #https://myaccount.table.core.windows.net/mytable(PartitionKey='myPartitionKey', RowKey='myRowKey')
            #http://127.0.0.1:10002/devstoreaccount1/mytable(PartitionKey='myPartitionKey', RowKey='myRowKey')
            $url = "https://$StorageAccountName.table.core.windows.net/${TableName}(PartitionKey='$($Entity.PartitionKey)',RowKey='$($Entity.RowKey)')${SASToken}"
            $EntityJson = $Entity | ConvertTo-Json -Compress
            Write-LogRunbook $EntityJson -Caller $CmdletName
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Body $EntityJson -Method MERGE -ErrorAction Stop
        }
        catch {   
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling '$url'")
        }
    }
    End { } 
}

#EndRegion -------------------------------------------------- [Functions] ----------------------------------------------
#Region -------------------------------------------------------- [Main] ----------------------------------------------
try {
    if (-not ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId)) {
        $ScriptName = (Get-Item $PSCommandPath).Basename
        $LogFolder = "$PSScriptRoot\Logs-$ScriptName"
        $OutputFolder = "$PSScriptRoot\Output-$ScriptName"
        $LogPath = "$LogFolder\$ScriptName-$TimeStamp.log"
        if (-not (Test-Path $LogFolder)) { New-Item -ItemType Directory $LogFolder | Out-Null }
        if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory $OutputFolder | Out-Null }
    }
    "====================================================================" | Write-LogRunbook -Caller 'Info-Start'
    "======================= ScriptVersion: $Scriptversion =======================" | Write-LogRunbook -Caller 'Info-Start'
    $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller 'Info-Start' }
    $JsonObjects = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-JsonContent -JsonFilePath $JsonPath -Web } else { Get-JsonContent -JsonFilePath $JsonPath }
    $CurrentJsonObject = 1
    $Global:Token = Get-Token -TenantId $Global:TenantId -AppId $Global:ApplicationId -CertThumbprint $Global:Thumbprint
    
    $JsonObjects | ForEach-Object {
        Write-LogRunbook "--------------------------------------------------------------------------------" -Caller "JsonEntry $CurrentJsonObject"
        $CurrentJsonObject++
        $TableName = $_.AzureTableName
        $CompliancePolicySettingId = $_.CompliancePolicySettingId
        $CompliancePolicyId = $_.CompliancePolicyId
        $DateTimeBefore = Get-Date
        $devicesComplianceDeviceStatus = [System.Collections.Generic.List[PSObject]]::new()
        $devicesComplianceDeviceStatus = Get-deviceComplianceDeviceStatus -deviceCompliancePolicyId $CompliancePolicyId
        $devicesComplianceDeviceStatusNotCompliant = $devicesComplianceDeviceStatus | Where-Object { ($_.status -eq 'nonCompliant') -and ($_.complianceGracePeriodExpirationDateTime.Year -ne "9999") }  |`
            Select-Object -Property id, deviceDisplayName, complianceGracePeriodExpirationDateTime, status, lastReportedDateTime -Unique
        <#
        $devicesComplianceDeviceStatusNew = [System.Collections.Generic.List[PSObject]]::new()
        $devicesComplianceDeviceStatusNotCompliantOnlyNew = [System.Collections.Generic.List[PSObject]]::new()
        $Differences = [System.Collections.Generic.List[PSObject]]::new()
        $ObjToBeAdded = [System.Collections.Generic.List[PSObject]]::new()
        $ObjToBeRemoved = [System.Collections.Generic.List[PSObject]]::new()
        $devicesComplianceDeviceStatusNew = Get-deviceComplianceDeviceStatusNew -PolicySettingId $CompliancePolicySettingId
        $devicesComplianceDeviceStatusNotCompliantOnlyNew = $devicesComplianceDeviceStatusNew | Where-Object {
            ($_.state -eq 'nonCompliant') -and ($_.complianceGracePeriodExpirationDateTime -notlike "*9999*")
        } | Select-Object -Property id, deviceId, deviceName, deviceModel, settingName, state -Unique
#>        
        $devicesComplianceDeviceStatusNotCompliant | ForEach-Object {
            # get device info
            $IntuneDevice = Get-IntuneDevcieInfo -Token $Token -IntuneDeviceId $_.id.split('_')[2]
            $_ | Add-Member -NotePropertyName 'IntuneDeviceId' -NotePropertyValue $IntuneDevice.id
            $_ | Add-Member -NotePropertyName 'AzureADDeviceId' -NotePropertyValue $IntuneDevice.azureADDeviceId
            $_ | Add-Member -NotePropertyName 'DeviceEnrollmentType' -NotePropertyValue $IntuneDevice.deviceEnrollmentType
            $_ | Add-Member -NotePropertyName 'DeviceRegistrationState' -NotePropertyValue $IntuneDevice.deviceRegistrationState
            $_ | Add-Member -NotePropertyName 'UserId' -NotePropertyValue $IntuneDevice.userId
            $_ | Add-Member -NotePropertyName 'EmailAddress' -NotePropertyValue $IntuneDevice.emailAddress
            $_ | Add-Member -NotePropertyName 'UserPrincipalName' -NotePropertyValue $IntuneDevice.userPrincipalName
            $_ | Add-Member -NotePropertyName 'ManagementAgent' -NotePropertyValue $IntuneDevice.managementAgent
            $_ | Add-Member -NotePropertyName 'ComplianceState' -NotePropertyValue $IntuneDevice.complianceState
            $_ | Add-Member -NotePropertyName 'ManagedDeviceOwnerType' -NotePropertyValue $IntuneDevice.managedDeviceOwnerType
            $_ | Add-Member -NotePropertyName 'EnrolledDateTime' -NotePropertyValue $IntuneDevice.enrolledDateTime
            $_ | Add-Member -NotePropertyName 'LastSyncDateTime' -NotePropertyValue $IntuneDevice.lastSyncDateTime
            $_ | Add-Member -NotePropertyName 'OperatingSystem' -NotePropertyValue $IntuneDevice.operatingSystem
            $_ | Add-Member -NotePropertyName 'OSVersion' -NotePropertyValue $IntuneDevice.osVersion
            $_ | Add-Member -NotePropertyName 'Model' -NotePropertyValue $IntuneDevice.model
            $_ | Add-Member -NotePropertyName 'Manufacturer' -NotePropertyValue $IntuneDevice.manufacturer
            $_ | Add-Member -NotePropertyName 'SerialNumber' -NotePropertyValue $IntuneDevice.serialNumber
            $_ | Add-Member -NotePropertyName PartitionKey -NotePropertyValue $CompliancePolicyId
            $_ | Add-Member -NotePropertyName RowKey -NotePropertyValue $_.status
        }
        # add/remove the delta
        $CurrentAzureTableEntities = Get-AzureTableEntities -StorageAccountName $StorageAccountName -TableName $TableName #-filter "PartitionKey%20gt%20'2023-12-01'"
        if ($CurrentAzureTableEntities -and $devicesComplianceDeviceStatusNotCompliant) {
            $Differences = Compare-Object -ReferenceObject $CurrentAzureTableEntities -DifferenceObject $devicesComplianceDeviceStatusNotCompliant -Property deviceId -PassThru
            $ObjToBeAdded = $Differences | Where-Object { $_.SideIndicator -eq '=>' }
            $ObjToBeRemoved = $Differences | Where-Object { $_.SideIndicator -eq '<=' }
        }
        elseif ($CurrentAzureTableEntities) {
            Write-LogRunbook "No non-compliant devices for policy Id '$CompliancePolicyId'. Maybe this should have a safeguard...email or something." -Caller 'Sanity-Check'
            Write-LogRunbook "All existing entries will be removed from table $TableName." -Caller 'Sanity-Check'
            $ObjToBeRemoved = $CurrentAzureTableEntities
        }
        else {
            Write-LogRunbook "Table $TableName is empty." -Caller 'Sanity-Check'
            $ObjToBeAdded = $devicesComplianceDeviceStatusNotCompliant
        }
    
        #Write-Output "Table '$TableName'. Entities to be added: $($ObjToBeAdded.count) Entities to be removed: $($ObjToBeRemoved.count)"
        if ($ObjToBeRemoved) {
            $ObjToBeRemoved | Remove-AzureTableEntities -StorageAccountName $StorageAccountName -TableName $TableName
        }
        if ($ObjToBeAdded) {
            # get objects ready to be added to the table
            #$ObjToBeAdded | Add-Member -NotePropertyName IntuneDeviceId -NotePropertyValue $null
            $ObjToBeAdded | Add-Member -NotePropertyName Manager -NotePropertyValue $null
            $ObjToBeAdded | Add-Member -NotePropertyName AddedOn -NotePropertyValue $DateTime
            $ObjToBeAdded | Add-Member -NotePropertyName EmailSent -NotePropertyValue '1999-01-01'

            $ObjToBeAdded | ForEach-Object {
                $_.PSObject.Properties.Remove('SideIndicator')
                #$_.IntuneDeviceId = $_.deviceId
                #$IntuneDeviceInfo = $_.deviceId | Get-IntuneDeviceInfo
                #$_.PrimaryUser = $IntuneDeviceInfo.PrimaryUser
                #$_.OSVersion = $IntuneDeviceInfo.OSVersion
                #$_.azureADDeviceId = $IntuneDeviceInfo.azureADDeviceId
                #$_.RowKey = if ($IntuneDeviceInfo.azureADDeviceId) { $IntuneDeviceInfo.azureADDeviceId } else { "IntuneId$($_.deviceId)" }
                #if ($_.UserId) { $_.Manager = Get-UserManager -UserPrincipalName $_.UserPrincipalName | Select-Object -ExpandProperty mail }
            }
            #$ObjToBeAdded | ForEach-Object {if ($_.RowKey.length -eq 0) {$_.RowKey = "IntuneId$($_.IntuneDeviceId)"}} 
            $ObjToBeAdded | Add-AzureTableEntities -StorageAccountName $StorageAccountName -TableName $TableName
        }
        Write-Output "Entities count before: $($CurrentAzureTableEntities.count). Entities added: $($ObjToBeAdded.count). Entities removed: $($ObjToBeRemoved.count)."
        $CurrentJsonObject++
        $ElapsedTime = New-TimeSpan -Start $DateTimeBefore -End (Get-Date)
        Write-Output "Elapsed time (seconds): $($ElapsedTime.TotalSeconds)"
        Write-Output "GatewayTimeoutCount: $GatewayTimeoutCount"
        #$b | Remove-AzureTableEntities -StorageAccountName $StorageAccountName -TableName q1q
        #######################
        #######################
        #######################
        # throw [CustomException]::new( "Get-ErrorOne", "This will cause the script to end with ExitCode 101")
        # some more code
        # throw [CustomException]::new( "Get-ErrorTwo", "This will cause the script to end with ExitCode 102")
    }
}
catch {
    switch ($_.Exception.Message) {
        'Get-ErrorOne' { $Global:ExitCode = 101 }
        'Get-ErrorTwo' { $Global:ExitCode = 102 }
        Default { $Global:ExitCode = 300 }
    }
    Write-ErrorRunbook
}
finally {
    if ($Global:ExitCode -ne 0) { throw $_ }
    Write-LogRunbook "============================ Exit code: $Global:ExitCode ==========================" -Caller 'Info-End'
    Exit $Global:ExitCode
}
#EndRegion ----------------------------------------------------- [Main] ----------------------------------------------
# to do: exit codes, json, script for removing devices from groups based on xx days (another json) (read tables), email script read tables, batch entities