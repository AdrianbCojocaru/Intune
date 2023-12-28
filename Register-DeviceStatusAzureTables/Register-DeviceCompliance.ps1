<#PSScriptInfo

.VERSION 1.0

.DATE 04-Dec-2023

.AUTHOR adrian.cojocaru

#>

<#
  .SYNOPSIS
  Register device compliance in Azure Tables for one or more Compliance Policies.
  It retrieves the device primary user and user's manager.

  .DESCRIPTION
  Detailed description.
  Purpose. Project. Dependencies. Limitations.

  .PARAMETER Param1
  Description for Param1

  .PARAMETER Param2
  Description for Param2

  .INPUTS
  If your script accepts pipeline input, describe it here

  .OUTPUTS
  A log file ($LogPath) will be created by default under the "Logs-<ScriptName>" folder next to the script.
  An output folder ($OutputFolder) "Output-<ScriptName>" will be created by default next to the script.
  *.CSVs or other output files can be generated under this folder.

  .EXAMPLE
  .\New-ScriptName.ps1 -Param1 'aa0116f4-d2d9-4191-8348-686ea15d085b' -Param2 'AadDeviceId'
   Shortly describe the usecase of running the script with these parameters.

#>

Param
(
    [Parameter (Mandatory = $false)]
    [string]$Param1 = '',
    [Parameter (Mandatory = $false)]
    [string]$Param2
)

#Region ----------------------------------------------------- [AzureAD Variables] ----------------------------------------------
[string]$tenantId = if ($env:AZUREPS_HOST_ENVIRONMENT) { Get-AutomationVariable -Name "MyTenantId" } else { $env:MyTenantId }
[string]$ApplicationId = if ($env:AZUREPS_HOST_ENVIRONMENT) { Get-AutomationVariable -Name "MyAppClientId" } else { $env:MyAppClientId }
[string]$ApplicationSecret = if ($env:AZUREPS_HOST_ENVIRONMENT) { Get-AutomationVariable-Name "MyDAppSecret" } else { $env:MyDAppSecret }
[string]$Thumbprint = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "CertThumbprint" } else { $env:AppCertThumbprint }
[string]$SASToken = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "SASToken" } else { $env:SASToken }
[string]$StorageAccountName = 'StorageAccountName'
[string]$TableName = 'CompliancePolicyXXXX'
[string]$PolicyId = 'd01256b4-ba81-4714-a5d3-8495806f4d81'
#EndRegion -------------------------------------------------- [AzureAD Variables] ----------------------------------------------
#Region ----------------------------------------------------- [Script Variables] ----------------------------------------------
[version]$ScriptVersion = [version]'1.0.0'
$Global:ExitCode = 0
$Global:GraphTokenRefreshLimit = 24
$Global:GraphTokenRefreshCount = 0
$Global:GatewayTimeoutCountLimit = 24
$Global:GatewayTimeoutCount = 0
$TimeStamp = get-date -Format yyyyMMddTHHmmss
$ScriptName = (Get-Item $PSCommandPath).Basename
$LogFolder = "$PSScriptRoot\Logs-$ScriptName"
$OutputFolder = "$PSScriptRoot\Output-$ScriptName"
$LogPath = "$LogFolder\$ScriptName-$TimeStamp.log"
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
Function Write-Log {
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
        # Optional. Specifies the message color in the powershell console White(default) Green Blue Yellow DarkYellow Red
        [string]$Color = 'White',
        [Parameter(Mandatory = $false, Position = 2)]
        # Optional. Specifies the message color in the powershell console White(default) Green Blue Yellow DarkYellow Red
        [string]$BackgroundColor = '',
        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNull()]
        # Optional. Specifies the name of the message writter. Function, command or custom name. Defaults to FunctioName or unknown
        [string]$Caller = 'Unknown'
    )
    Begin {
        [string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
        [string]$LogTime = (Get-Date -Format 'HH\:mm\:ss.fff').ToString()
        #if ([string]::IsNullOrEmpty($Message)) { return }
    }
    Process {
        If ($Message) {
            [string]$CompleteMsg = "[$LogDate $LogTime] [${Caller}] :: $Message"
            #Try {
            if ($BackgroundColor -eq '') {
                $CompleteMsg | Write-Host -ForegroundColor $Color
            }
            else {
                $CompleteMsg | Write-Host -ForegroundColor $Color -BackgroundColor $BackgroundColor 
            }
            $CompleteMsg | Out-File -FilePath $LogPath -Append -NoClobber -Force -Encoding 'UTF8' -ErrorAction 'Stop' 
        }
    }
    End {}
}
function Write-Error2 {
    <#

    .DESCRIPTION
    Uses Write-Log to write error messages to the log file and also display them in the console.

#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false, Position = 0)]
        [AllowEmptyCollection()]
        # Optional. The errorr collection.
        [array]$ErrorRecord,
        [Parameter(Mandatory = $false, Position = 1)]
        [AllowEmptyCollection()]
        # Optional.
        [switch]$Pause
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
        $ErrorRecord | ForEach-Object {
            $errNumber = $ErrorRecord.count - $( $ErrorRecord.IndexOf($_))
            $_.CategoryInfo | Write-Log -Caller "${CmdletName} Nr. $errNumber"  -Color Red
            $_ | Write-Log -Caller "${CmdletName} Nr. $errNumber" -Color Red
            $_.InvocationInfo.PositionMessage | Write-Log -Caller "${CmdletName} Nr. $errNumber" -Color Red
            if ($Pause) {
                Write-Log "Please review before continuing!" -BackgroundColor DarkMagenta -Color Yellow -Caller $CmdletName
                Pause
            }
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
   Get-Token -ThreatProtection -AppIdSecret
#>
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [switch]$ThreatProtection,
        [Parameter(Mandatory = $false, Position = 1)]
        [switch]$AppIdSecret,
        [Parameter(Mandatory = $false, Position = 2)]
        [switch]$Storage
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
    }
    End {
        try {
            $url = if ($ThreatProtection) { 'https://api.security.microsoft.com' } else { 'https://graph.microsoft.com' }
            Write-Log "url = $url" -Caller $CmdletName
            if ($AppIdSecret) {
                $body = [Ordered] @{
                    grant_type    = 'client_credentials'
                    client_id     = $ApplicationId
                    client_secret = $ApplicationSecret  
                }
                if ($ThreatProtection) {
                    $oAuthUrl = "https://login.windows.net/$TenantId/oauth2/token"
                    $body.Add('resource', $url)
                }
                else {
                    $oAuthUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" 
                    $body.Add('scope', $url + '/.default')
                }
                Write-Log "oAuthUrl = $oAuthUrl" -Caller $CmdletName
                [string]$Token = (Invoke-RestMethod -Method Post -Uri $oAuthUrl -Body $body -ErrorAction Stop).access_token
            }
            else {
                # certificate auth
                if (-not (Get-AzContext)) {
                    Write-Log "No AzContext. Running Connect-AzAccount" -Caller $CmdletName
                    Connect-AzAccount -CertificateThumbprint $Thumbprint -ApplicationId $ApplicationId -Tenant $TenantId -ServicePrincipal
                }
                [string]$Token = (Get-AzAccessToken -ResourceUrl $url).Token
            }
            $Token
        }
        catch {
            Write-Error2
            throw [CustomException]::new( $CmdletName, "Error calling https://api.security.microsoft.com")
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
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
    }
    End {
        try {
            if ($Web) {
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
            Write-Error2
            throw [CustomException]::new( $CmdletName, "Error calling json url")
        }
    }
    
}

function  Get-UserManager {
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$UserPrincipalName,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$ObjectId
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
    }
    End {
        try {
            $headers = @{ 'Authorization' = "Bearer $Token_Graph" }
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
            #($response.Content | ConvertFrom-Json).value | Select-Object -Property 'id', 'displayName', 'givenName', 'surname' , 'mail' | Out-String | Write-Log -Caller $CmdletName
        }
        catch {
            switch ($_.Exception.Response.StatusCode) {
                'Unauthorized' {
                    if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                        Write-Log "Token expired. Getting a new one. GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'" -Caller $CmdletName
                        $global:Token_Graph = Get-Token -AppIdSecret
                        $Global:GraphTokenRefreshCount++
                        Get-UserManager @PSBoundParameters
                    }
                    else {
                        Write-Error2
                        throw [CustomException]::new( $CmdletName, "GraphTokenRefreshLimit '$Global:GraphTokenRefreshCount' reached! ")
                    }
                }
                'NotFound' { 
                    Write-Log "AzureAD object not found." -Caller $CmdletName
                }
                Default {
                    Write-Error2
                    throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling '$url'")
                }
            }
        }
    } 
}

function Get-IntuneDevicePrimaryUser {
    <#
  .DESCRIPTION
  Returns the Intune Device primary user.
  If there is no primary user in intune then it will return the AzureAD device owner

 .Example
   Get-AADDeviceInfo -IntuneDeviceId $devices[3].DeviceId
#>
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$IntuneDeviceId
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        #$AlreadyAddedList = [System.Collections.ArrayList]::new()
        #$GroupList = [System.Collections.ArrayList]::new()
    }
    Process {
        try {
            $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
            $headers = @{
                Authorization  = "Bearer $Token_Graph"
                "Content-type" = "application/json"
            }
            if ($IntuneDeviceId) {
                #Write-Log "IntuneDeviceId $IntuneDeviceId" -Caller $CmdletName
                #$url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{$IntuneDeviceId}?`$select=userPrincipalName,emailAddress,azureADDeviceId,deviceName"
                $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{$IntuneDeviceId}"
                $responseIntune = Invoke-RestMethod -Headers $headers -Uri $url -Method Get -ErrorAction Stop
                if ($responseIntune) {
                    $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{$IntuneDeviceId}/users"
                    $UsersIntune = Invoke-RestMethod -Headers $headers -Uri $url -Method Get -ErrorAction Stop
                    $responseIntune | Add-Member -NotePropertyName PrimaryUser -NotePropertyValue  $UsersIntune.value[0].userPrincipalName
                    if ($UsersIntune.value.count -gt 1 ) {
                        Write-Log "Found $($($UsersIntune.value.count)) Intune users for intune device Id '$IntuneDeviceId'" -Caller $CmdletName
                    }
                    elseif (($UsersIntune.value.count -eq 0) -and $responseIntune.azureADDeviceId) {
                        Write-Log "No Primaryy user in Intune for azureADDeviceId '$($responseIntune.azureADDeviceId)'" -Caller $CmdletName
                        #$url = "https://graph.microsoft.com/v1.0/devices(deviceId='{$AzureAdDeviceId}')?`$select=id,displayName"
                        $url = "https://graph.microsoft.com/v1.0/devices(deviceId='{$($responseIntune.azureADDeviceId)}')/registeredOwners"
                        $responseAzureAd = Invoke-RestMethod -Headers $headers -Uri $url -Method Get -ErrorAction Stop
                        #$AzureAdDeviceObjectId
                        $responseIntune | Add-Member -NotePropertyName PrimaryUser -NotePropertyValue  $responseAzureAd[0].value.userPrincipalName -Force
                        if ($responseAzureAd.count -gt 1 ) {
                            Write-Log "Found $($responseAzureAd.count) AzureAD owners for AzureAD device Id '$($responseIntune.azureADDeviceId)' -Caller $CmdletName"
                        }
                    }
                }
                $responseIntune
            }
            else {
                Write-Log "IntuneDeviceId params was empty." -Caller $CmdletName
            }

        }
        catch {
            switch ($_.Exception.Response.StatusCode) {
                'Unauthorized' {
                    if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                        Write-Log "Token expired. Getting a new one. GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'" -Caller $CmdletName
                        $global:Token_Graph = Get-Token -AppIdSecret
                        $Global:GraphTokenRefreshCount++
                        Get-IntuneDevicePrimaryUser @PSBoundParameters
                    }
                    else {
                        Write-Error2
                        throw [CustomException]::new( $CmdletName, "GraphTokenRefreshLimit '$Global:GraphTokenRefreshCount' reached! ")
                    }
                }
                'NotFound' { 
                    Write-Log "AzureAD object not found." -Caller $CmdletName
                }
                Default {
                    Write-Error2
                    throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling '$url'")
                }
            }
        }
    }
    End {
        # Write-Log "Ended" -Caller $CmdletName
    }
}

function  Get-deviceComplianceDeviceStatus {
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
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
        $StatusesList = @()
        $count = 0
    }
    End {
        try {
            $headers = @{ 'Authorization' = "Bearer $Token_Graph" }
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
                write-host $count
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
                        Write-Log "Token expired. Getting a new one. GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'" -Caller $CmdletName
                        $global:Token_Graph = Get-Token -AppIdSecret
                        $Global:GraphTokenRefreshCount++
                        Get-deviceComplianceDeviceStatus @PSBoundParameters
                    }
                    else {
                        Write-Error2
                        throw [CustomException]::new( $CmdletName, "GraphTokenRefreshLimit '$Global:GraphTokenRefreshCount' reached! ")
                    }
                }
                'NotFound' { 
                    Write-Log "AzureAD object not found." -Caller $CmdletName
                }
                'GatewayTimeout' {
                    if ($Global:GatewayTimeoutCount -lt $Global:GatewayTimeoutCountLimit) {
                        Write-Log "(504) Gateway Timeout counter: $Global:GatewayTimeoutCount. Retrying." -Caller $CmdletName
                        Start-Sleep -Seconds 2
                        $Global:GatewayTimeoutCount++
                        Get-deviceComplianceDeviceStatus @PSBoundParameters
                    }
                    else {
                        Write-Error2
                        throw [CustomException]::new( $CmdletName, "GatewayTimeoutCountLimit '$Global:GatewayTimeoutCountLimit' reached! ")
                    }
                }
                Default {
                    Write-Error2
                    throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling '$url'")
                }
            }
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
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
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
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -ErrorAction Stop
            ($response.Content | ConvertFrom-Json).value | ForEach-Object { $TableData.Add($_) } # 26 Milliseconds
            while ($response.Headers.'x-ms-continuation-NextPartitionKey') {
                $NextRowKey = $response.Headers.'x-ms-continuation-NextRowKey'
                $NextPartitionKey = $response.Headers.'x-ms-continuation-NextPartitionKey'
                Write-Log "NextPartitionKey = '$NextPartitionKey' NextRowKey = '$NextRowKey'" -Caller $CmdletName
                #https://myaccount.table.core.windows.net/Customers?NextPartitionKey=1!8!U21pdGg-&NextRowKey=1!12!QmVuMTg5OA--
                $url = "https://$StorageAccountName.table.core.windows.net/${TableName}${SASToken}&NextPartitionKey=$NextPartitionKey&NextRowKey=$NextRowKey"
                if ($filter) { 
                    $url += "&`$filter=$filter"
                }
                $response = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -ErrorAction Stop
                ($response.Content | ConvertFrom-Json).value |  ForEach-Object { $TableData.Add($_) }
            }
            Write-Log "$($TableData.count) entities found." -Caller $CmdletName
            $TableData
        }
        catch {
            Write-Error2
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
    #https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/d01256b4-ba81-4714-a5d3-8495806f4d81/deviceRunStates/?$expand=*
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
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
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
            Write-Log $bodyJSON -Caller $CmdletName
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Body $bodyJSON -Method Post -ErrorAction Stop
            $response.value
        }
        catch {
            if ($_.Exception.StatusCode -eq 'Conflict') {
                Write-Log ($_.ErrorDetails.Message | ConvertFrom-Json).'odata.error'.code -Caller $CmdletName
                $message = ($_.ErrorDetails.Message | ConvertFrom-Json).'odata.error'.message.value.Replace("`n", "\n")
                Write-Log $message -Caller $CmdletName
            }
            else {    
                Write-Error2
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
    #https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/d01256b4-ba81-4714-a5d3-8495806f4d81/deviceRunStates/?$expand=*
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
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
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
            Write-Log $EntityJson -Caller $CmdletName
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Body $bodyJSON -Method DELETE -ErrorAction Stop
        }
        catch {
            if ($_.Exception.StatusCode -eq 'NotFound') {
                Write-Log ($_.ErrorDetails.Message | ConvertFrom-Json).'odata.error'.code -Caller $CmdletName
                $message = ($_.ErrorDetails.Message | ConvertFrom-Json).'odata.error'.message.value.Replace("`n", "\n")
                Write-Log $message -Caller $CmdletName
            }
            else {    
                Write-Error2
                throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling '$url'")
            }
        }
    }
    End {
    } 
}

#EndRegion -------------------------------------------------- [Functions] ----------------------------------------------
#Region -------------------------------------------------------- [Main] ----------------------------------------------
try {
    if (-not (Test-Path $LogFolder)) { New-Item -ItemType Directory $LogFolder | Out-Null }
    if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory $OutputFolder | Out-Null }
    "====================================================================" | Write-Log -Caller 'Info-Start'
    "======================= ScriptVersion: $Scriptversion =======================" | Write-Log -Caller 'Info-Start'
    $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller 'Info-Start' }
    $Token_Graph = Get-Token -AppIdSecret
    #######################
    #######################
    #######################
    #$b = Import-Csv -Path "C:\GitRepos\AzureAD\Azure Storage\AzureTables\Output-GetSet-AzureeTables\TestInsert.csv"
    #$b | Add-AzureTableEntities -StorageAccountName $StorageAccountName -TableName q1q
    #$b | Remove-AzureTableEntities -StorageAccountName $StorageAccountName -TableName q1q
    #break
    #$CurrentTable = Get-AzureTableEntities -StorageAccountName $StorageAccountName -TableName q1q #-filter "PartitionKey%20lt%20'2022-12-01'"
    $devicesComplianceDeviceStatus = [System.Collections.Generic.List[PSObject]]::new()
    $devicesComplianceDeviceStatus = Get-deviceComplianceDeviceStatus -deviceCompliancePolicyId $PolicyId
    $devicesComplianceDeviceStatusFiltered = [System.Collections.Generic.List[PSObject]]::new()
    $devicesComplianceDeviceStatusFiltered = $devicesComplianceDeviceStatus | Where-Object {
        ($_.status -eq 'nonCompliant') -and ($_.userName -ne 'System account') -and ($_.complianceGracePeriodExpirationDateTime -notlike "9999-12-31*")
        # get unique devices
        #($devicesComplianceDeviceStatusFiltered | Select-Object -Property id,deviceDisplayName,complianceGracePeriodExpirationDateTime, osversion -Unique).count
    } | Select-Object -Property id, deviceDisplayName, complianceGracePeriodExpirationDateTime -Unique
    # add/remove the delta
    $CurrentAzureTableEntities = Get-AzureTableEntities -StorageAccountName $StorageAccountName -TableName $TableName #-filter "PartitionKey%20gt%20'2023-12-01'"
    if ($CurrentAzureTableEntities -and $devicesComplianceDeviceStatusFiltered) {
        $Differences = Compare-Object -ReferenceObject $CurrentAzureTableEntities -DifferenceObject $devicesComplianceDeviceStatusFiltered -Property id -PassThru
        $ObjToBeAdded = $Differences | Where-Object { $_.SideIndicator -eq '=>' }
        $ObjToBeRemoved = $Differences | Where-Object { $_.SideIndicator -eq '<=' }
    } elseif ($CurrentAzureTableEntities) {
        Write-Log "No non-compliant devices for policy Id '$PolicyId'. Maybe this should have a safeguard...email or something." -Caller 'Sanity-Check'
        Write-Log "All existing entries will be removed from table $TableName." -Caller 'Sanity-Check'
        $ObjToBeRemoved = $CurrentAzureTableEntities
    } else {
        Write-Log "Table $TableName is empty." -Caller 'Sanity-Check'
        $ObjToBeAdded = $devicesComplianceDeviceStatusFiltered
    }
    
    if ($ObjToBeRemoved) {
        $ObjToBeRemoved | Remove-AzureTableEntities -StorageAccountName $StorageAccountName -TableName $TableName
    }
    if ($ObjToBeAdded) {
        # get objects ready to be added to the table
        $ObjToBeAdded | Add-Member -NotePropertyName PrimaryUser -NotePropertyValue $null
        $ObjToBeAdded | Add-Member -NotePropertyName OSVersion -NotePropertyValue $null
        $ObjToBeAdded | Add-Member -NotePropertyName IntuneDeviceId -NotePropertyValue $null
        $ObjToBeAdded | Add-Member -NotePropertyName Manager -NotePropertyValue $null
        $ObjToBeAdded | Add-Member -NotePropertyName AddedOn -NotePropertyValue $DateTime
        $ObjToBeAdded | Add-Member -NotePropertyName EmailSent -NotePropertyValue '1999-01-01'
        $ObjToBeAdded | Add-Member -NotePropertyName PartitionKey -NotePropertyValue $PolicyId
        $ObjToBeAdded | Add-Member -NotePropertyName RowKey -NotePropertyValue $null
        $ObjToBeAdded | ForEach-Object {
            $_.PSObject.Properties.Remove('SideIndicator')
            $_.IntuneDeviceId = $_.id.split('_')[-1]
            $IntuneDeviceInfo = $_.IntuneDeviceId | Get-IntuneDevicePrimaryUser
            $_.PrimaryUser = $IntuneDeviceInfo.PrimaryUser
            $_.OSVersion = $IntuneDeviceInfo.OSVersion
            $_.RowKey = $_.IntuneDeviceId
            if ($_.PrimaryUser) { $_.Manager = Get-UserManager -UserPrincipalName $_.PrimaryUser | Select-Object -ExpandProperty mail }
        }
        $ObjToBeAdded | Add-AzureTableEntities -StorageAccountName $StorageAccountName -TableName $TableName
    }
    Write-Output "Table '$TableName'. Entities added: $($ObjToBeAdded.count) Entities removed: $($ObjToBeRemoved.count)"
    #$b | Remove-AzureTableEntities -StorageAccountName $StorageAccountName -TableName q1q
    #######################
    #######################
    #######################
    # throw [CustomException]::new( "Get-ErrorOne", "This will cause the script to end with ExitCode 101")
    # some more code
    # throw [CustomException]::new( "Get-ErrorTwo", "This will cause the script to end with ExitCode 102")
}
catch {
    switch ($_.Exception.Message) {
        'Get-ErrorOne' { $Global:ExitCode = 101 }
        'Get-ErrorTwo' { $Global:ExitCode = 102 }
        Default { $Global:ExitCode = 300 }
    }
    Write-Error2
}
finally {
    Write-Log "============================ Exit code: $Global:ExitCode ==========================" -Caller 'Info-End'
    Exit $Global:ExitCode
}
#EndRegion ----------------------------------------------------- [Main] ----------------------------------------------
# to do: exit codes, json, script for removing devices from groups based on xx days (another json) (read tables), email script read tables