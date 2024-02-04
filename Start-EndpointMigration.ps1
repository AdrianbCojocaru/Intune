<#

.Version 2.0.0

.Author Adrian Cojocaru

.Synopsis
    Migration script from one tenant to another

.Description
    Another script (running on the client device) gathers the serial number, hash and device name of the device that is being migrated. This information is being sent via a webhook.
    This script checks to see if the device exists in the target tenant, and if it does, it triggers the device wipe and sync. If successful, it deletes the device object from Intune, Windows Autopilot devices and Entra Id. (Source tenant)
    Once all the data has been removed from the source tenant, the script will upload the hardware hash to the target tenant.

#>

Param
(
    [Parameter (Mandatory = $false)]
    [object] $webhookData
)

#Region ----------------------------------------------------- [AzureAD Variables] ----------------------------------------------
[string]$SourceTenantId = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "DW-Automation-CLN-tenantid" }
[string]$SourceApplicationId = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "DW-Automation-CLN-appid" }
[string]$SourceApplicationSecret = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "DW-Automation-CLN-secret" }
[string]$DestinationTenantId = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "TenantId" }
[string]$DestinationApplicationId = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "DW-Automation-CLN-targetappid" }
[string]$DestinationApplicationSecret = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "DW-Automation-CLN-targetsecret" }


[string]$SASToken = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "AzTablesSASToken" } else { $env:SASToken }
[string]$StorageAccountName = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "StorageAccountName" } else { $env:StorageAccountName }
[string]$AzTableName = 'MigratedDevices'
[string]$AzNamingConventionTable = 'NamingConvention'
#EndRegion -------------------------------------------------- [AzureAD Variables] ----------------------------------------------
#Region ----------------------------------------------------- [Script Variables] ----------------------------------------------
[version]$ScriptVersion = [version]'1.0.0'
$Global:ExitCode = 0
$Global:GraphTokenRefreshLimit = 24
$Global:GraphTokenRefreshCount = 0
$Global:GatewayTimeoutCountLimit = 128
$Global:GatewayTimeoutCount = 0
$Global:CheckCountLimit = 128
$Global:CheckCount = 0
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
        [string]$TenantId,
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$AppId,
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$AppSecret,
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
function Import-WindowsAutopilotDevice {
    <#
  .DESCRIPTION
  Import device data to Intune Windows Autopilot devices

 .Example
   Import-WindowsAutopilotDevice -Token 'yourGraphToken' -DeviceSerialNumber 'GFD73EY7'  -WindowsProductID 'f75bbc93-9f55-4b74-abe2-7f01d6101b43'  -HardwareHash '4AAAAAAAAVXQBlJQwAAABW'
#>
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$Token,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$DeviceSerialNumber,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$WindowsProductID,
        [Parameter(Mandatory = $false, Position = 3, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$HardwareHash
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { if ($_.Key -notlike "*token*") { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName } }
    }
    End {
        $headers = @{
            Authorization  = "Bearer $Token"
            "Content-type" = "application/json"
        }
        #Build a json for the creating of the autopilot device
        $AutopilotDeviceIdentity = [ordered]@{
            '@odata.type'        = '#microsoft.graph.importedWindowsAutopilotDeviceIdentity'
            'groupTag'           = 'NO-ORA-OFC'
            'serialNumber'       = $DeviceSerialNumber
            'productKey'         = if ($WindowsProductID) { $WindowsProductID } else { "" }
            'hardwareIdentifier' = $HardwareHash
            #'assignedUserPrincipalName' = if ($UserPrincipalName) { "$($UserPrincipalName)" } else { "" }
            'state'              = @{
                '@odata.type'          = 'microsoft.graph.importedWindowsAutopilotDeviceIdentityState'
                'deviceImportStatus'   = 'pending'
                'deviceRegistrationId' = ''
                'deviceErrorCode'      = 0
                'deviceErrorRNName'    = ''
            }
        }
        try {
            #Getting rid of formatting errors and converting to json
            $body = $($($AutopilotDeviceIdentity | ConvertTo-Json -Compress) -replace "rn", "" -replace " ", "")  
            Write-LogRunbook "Importing $body" -Caller $CmdletName
                
            $url = "https://graph.microsoft.com/v1.0/deviceManagement/importedWindowsAutopilotDeviceIdentities"
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Body $body -Method Post -ErrorAction Stop
            Write-LogRunbook "ImportId: $($response.id) ImportState: $($response.state)" -Caller $CmdletName
            $response.id
            #$AutopilotDeviceIdentityResponse = Invoke-RestMethod -Headers @{Authorization = "Bearer $($TargetToken)" } -Uri $url -Method POST -Body $AutopilotDeviceIdentityJSON -ContentType "application/json" -ErrorAction Stop
        }
        catch {
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling '$url'")
        }
    }      
}
function Remove-WindowsAutopilotDevice {
    <#
  .DESCRIPTION
  Removes device data from Intune Windows Autopilot devices

 .Example
   Remove-WindowsAutopilotDevice -Token 'yourGraphToken' -DeviceSerialNumber '390da3ec-cc71-4544-904c-f851740f01f8'
#>
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$Token,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$DeviceSerialNumber = ''
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { if ($_.Key -notlike "*token*") { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName } }
    }
    End {
        $headers = @{
            Authorization  = "Bearer $SourceToken"
            "Content-type" = "application/json"
        }
        try {
            # get device by serial number    
            $url = "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$DeviceSerialNumber')"
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
            "StatusCode: $($response.StatusCode) (Expected value for success: 204) StatusDescription: $($response.StatusDescription) (Expected value for success: NoContent) $url" | Write-LogRunbook -Caller $CmdletName
            Write-LogRunbook "$($response.'@odata.count') device(s) found." -Caller $CmdletName
            if ($response.value) {
                $response.value | ConvertTo-Json -Compress | Write-LogRunbook -Caller $CmdletName
                $response.value | ForEach-Object {
                    
                    "Deleting Id $($_.id)" | Write-LogRunbook -Caller $CmdletName
                    $url = "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities/$($_.id)"
                    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Delete -ErrorAction Stop
                    "StatusCode: $($response.StatusCode) (Expected value for success: 204) StatusDescription: $($response.StatusDescription) (Expected value for success: NoContent) $url" | Write-LogRunbook -Caller $CmdletName

                }
            }
            else {
                Write-LogRunbook "Device not found" -Caller $CmdletName
            }
            #$AutopilotDeviceIdentityResponse = Invoke-RestMethod -Headers @{Authorization = "Bearer $($TargetToken)" } -Uri $url -Method POST -Body $AutopilotDeviceIdentityJSON -ContentType "application/json" -ErrorAction Stop
        }
        catch {
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "StatusCode: '$($($_.Exception).StatusCode)' (Expected value for success: 204) StatusDescription: '$($($_.Exception).Message)' (Expected value for success: NoContent) url: $url")
        }
    }      
}
function Get-WindowsAutopilotDevice {
    <#
  .DESCRIPTION
  Gets the information about an imported Windows Autopilot Device IdentityId

 .Example
   Get-WindowsAutopilotDevice -Token 'yourGraphToken' -importedWindowsAutopilotDeviceIdentityId '390da3ec-cc71-4544-904c-f851740f01f8'
   Get-WindowsAutopilotDevice -Token 'yourGraphToken' -DeviceSerialNumber '390da3ec'
#>
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$Token,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$importedWindowsAutopilotDeviceIdentityId,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$DeviceSerialNumber,
        [Parameter(Mandatory = $false, Position = 3, ValueFromPipeline = $false)]
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
            if ($DeviceSerialNumber) {    
                $url = "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$DeviceSerialNumber')"
                $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
                $response | ConvertTo-Json -Compress | Write-LogRunbook -Caller $CmdletName
                $response.value
            }
            else {
                $url = "https://graph.microsoft.com/v1.0/deviceManagement/importedWindowsAutopilotDeviceIdentities/$importedWindowsAutopilotDeviceIdentityId"
                $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
                Write-LogRunbook "ImportState: $($response.state)" -Caller $CmdletName
                #$AutopilotDeviceIdentityResponse = Invoke-RestMethod -Headers @{Authorization = "Bearer $($TargetToken)" } -Uri $url -Method POST -Body $AutopilotDeviceIdentityJSON -ContentType "application/json" -ErrorAction Stop
                $response.state
            }
        }
        catch {
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling '$url'")
        } 
    }      
}
function Update-WindowsAutopilotDeviceProperties {
    <#
  .DESCRIPTION
  Updates properties for an Autopilot device

 .Example
   Update-WindowsAutopilotDeviceProperties -Token 'yourGraphToken' -windowsAutopilotDeviceIdentityId 'f75bbc93-9f55-4b74-abe2-7f01d6101b43' -DeviceName 'AdiCojoVM10'
#>
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$Token,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$windowsAutopilotDeviceIdentityId,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$DeviceName
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { if ($_.Key -notlike "*token*") { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName } }
    }
    End {
        $headers = @{
            Authorization  = "Bearer $Token"
            "Content-type" = "application/json"
        }
        #Build a json for the creating of the autopilot device
        $body = @{'displayName' = $DeviceName }
        try {
            #Getting rid of formatting errors and converting to json
            $body = $body | ConvertTo-Json -Compress
            Write-LogRunbook "Updating $body" -Caller $CmdletName
            $url = "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities/$windowsAutopilotDeviceIdentityId/updateDeviceProperties"     #//updateDeviceProperties"
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Body $body -Method Post -UseBasicParsing -ErrorAction Stop
            "StatusCode: $($response.StatusCode) (Expected value for success: 204) StatusDescription: $($response.StatusDescription) (Expected value for success: NoContent)" | Write-LogRunbook -Caller $CmdletName
            #$response
        }
        catch {
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "StatusCode: '$($($_.Exception).StatusCode)' (Expected value for success: 204) StatusDescription: '$($($_.Exception).Message)' (Expected value for success: NoContent) url: $url")
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
            $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
            $headers = @{
                Authorization  = "Bearer $Token_Graph"
                "Content-type" = "application/json"
            }
            if ($IntuneDeviceId) {
                #Write-LogRunbook "IntuneDeviceId $IntuneDeviceId" -Caller $CmdletName
                #$url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{$IntuneDeviceId}?`$select=userPrincipalName,emailAddress,azureADDeviceId,deviceName"
                $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{$IntuneDeviceId}"
                $responseIntune = Invoke-RestMethod -Headers $headers -Uri $url -Method Get -ErrorAction Stop
                if ($responseIntune) {
                    $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{$IntuneDeviceId}/users"
                    $UsersIntune = Invoke-RestMethod -Headers $headers -Uri $url -Method Get -ErrorAction Stop
                    $responseIntune | Add-Member -NotePropertyName PrimaryUser -NotePropertyValue  $UsersIntune.value[0].userPrincipalName
                    if ($UsersIntune.value.count -gt 1 ) {
                        Write-LogRunbook "Found $($($UsersIntune.value.count)) Intune users for intune device Id '$IntuneDeviceId'" -Caller $CmdletName
                    }
                    elseif (($UsersIntune.value.count -eq 0) -and $responseIntune.azureADDeviceId) {
                        Write-LogRunbook "No Primaryy user in Intune for azureADDeviceId '$($responseIntune.azureADDeviceId)'" -Caller $CmdletName
                        #$url = "https://graph.microsoft.com/v1.0/devices(deviceId='{$AzureAdDeviceId}')?`$select=id,displayName"
                        $url = "https://graph.microsoft.com/v1.0/devices(deviceId='{$($responseIntune.azureADDeviceId)}')/registeredOwners"
                        $responseAzureAd = Invoke-RestMethod -Headers $headers -Uri $url -Method Get -ErrorAction Stop
                        #$AzureAdDeviceObjectId
                        $responseIntune | Add-Member -NotePropertyName PrimaryUser -NotePropertyValue  $responseAzureAd[0].value.userPrincipalName -Force
                        if ($responseAzureAd.count -gt 1 ) {
                            Write-LogRunbook "Found $($responseAzureAd.count) AzureAD owners for AzureAD device Id '$($responseIntune.azureADDeviceId)' -Caller $CmdletName"
                        }
                    }
                }
                $responseIntune
            }
            else {
                Write-LogRunbook "IntuneDeviceId params was empty." -Caller $CmdletName
            }

        }
        catch {
            switch ($_.Exception.Response.StatusCode) {
                'Unauthorized' {
                    if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                        Write-LogRunbook "Token expired. Getting a new one. GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'" -Caller $CmdletName
                        $global:Token_Graph = Get-GraphToken
                        $Global:GraphTokenRefreshCount++
                        Get-IntuneDevicePrimaryUser @PSBoundParameters
                    }
                    else {
                        Write-ErrorRunbook
                        throw [CustomException]::new( $CmdletName, "GraphTokenRefreshLimit '$Global:GraphTokenRefreshCount' reached! ")
                    }
                }
                'NotFound' { 
                    Write-LogRunbook "AzureAD object not found." -Caller $CmdletName
                }
                Default {
                    Write-ErrorRunbook
                    throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling '$url'")
                }
            }
        }
    }
    End {
        # Write-LogRunbook "Ended" -Caller $CmdletName
    }
}
function ConvertTo-AADDeviceObjectId {
    <#
  .DESCRIPTION
  Returns the AzureAD Device Object ID for a given IntuneDeviceId, AzureAdDeviceId or DisplayName.
  If multiple devices have the same DisplayName, only the Azure AD Device Object ID for the first one will be returned.

 .Example
  Convert-ToAADDeviceObjectId -Token 'yourGraphToken' -IntuneDeviceId $devices[3].DeviceId
  Convert-ToAADDeviceObjectId -Token 'yourGraphToken' -DeviceName 'ORAIDIDNL17076'
#>
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$Token,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$AzureAdDeviceId,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$IntuneDeviceId,
        [Parameter(Mandatory = $false, Position = 3, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$DeviceName
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process {
        try {
            $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { if ($_.Key -notlike "*token*") { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName } }
            $headers = @{
                Authorization  = "Bearer $Token"
                "Content-type" = "application/json"
            }
            if ($IntuneDeviceId) {
                #Write-Log "IntuneDeviceId $IntuneDeviceId" -Caller $CmdletName
                #$url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{$IntuneDeviceId}?`$select=userPrincipalName,emailAddress,azureADDeviceId,deviceName"
                $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{$IntuneDeviceId}?`$select=azureADDeviceId"
                $responseIntune = Invoke-RestMethod -Headers $headers -Uri $url -Method Get -ErrorAction Stop
                $AzureAdDeviceId = $responseIntune.azureADDeviceId
            }
            if ($AzureAdDeviceId) {
                #$url = "https://graph.microsoft.com/v1.0/devices(deviceId='{$AzureAdDeviceId}')?`$select=id,displayName"
                $url = "https://graph.microsoft.com/v1.0/devices(deviceId='{$AzureAdDeviceId}')?`$select=id"
                $responseAzureAd = Invoke-RestMethod -Headers $headers -Uri $url -Method Get -ErrorAction Stop
                #$AzureAdDeviceObjectId
                $responseAzureAd.id
            }
            elseif ($DeviceName) {
                #for multiple device ID returned by DeviceName, only the 1st one is returned. Check if this is what you want
                $url = "https://graph.microsoft.com/v1.0/devices?`$filter=displayName eq '$DeviceName'&`$select=id&`$top=1"
                $response = Invoke-RestMethod -Headers $headers -Uri $url -Method Get -ErrorAction Stop
                #$AzureAdDeviceObjectId
                $response.value.id
            }
            else {
                Write-LogRunbook "All params can't be empty." -Caller $CmdletName
            }
        }
        catch {
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "$($response.StatusCode) StatusCode calling '$url'")
        }
    }
    End {
        # Write-Log "Ended" -Caller $CmdletName
    }
}
function Remove-AADDeviceObject {
    <#
  .DESCRIPTION
  Gets the Intune information about a device

 .Example
   Remove-AADDeviceObject -Token $SourceToken -AzureADDeviceObjectId 'f75bbc93-9f55-4b74-abe2-7f01d6101b43'
#>
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$Token,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$AzureADDeviceObjectId
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { if ($_.Key -notlike "*token*") { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName } }
        $headers = @{
            Authorization  = "Bearer $Token"
            "Content-type" = "application/json"
        }
    }
    process {
        try {
            $url = "https://graph.microsoft.com/v1.0/devices/$AzureADDeviceObjectId"
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Method Delete -UseBasicParsing -ErrorAction Stop
            "StatusCode: $($response.StatusCode) (Expected value for success: 204) StatusDescription: $($response.StatusDescription) (Expected value for success: NoContent)" | Write-LogRunbook -Caller $CmdletName
        }
        catch {
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "StatusCode: '$($($_.Exception).StatusCode)' (Expected value for success: 204) StatusDescription: '$($($_.Exception).Message)' (Expected value for success: NoContent) url: $url")
        } 
    }
    End { }      
}
function Get-IntuneDevcieInfo {
    <#
  .DESCRIPTION
  Gets the Intune information about a device

 .Example
   Get-IntuneDevcieInfo -Token $SourceToken -DeviceName 'us-467995179101'
   Get-IntuneDevcieInfo -Token $SourceToken -IntuneDeviceId '066b2ce2-f103-4522-882f-55c19fffb6e5'
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
        [switch]$HideParams
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { if ($_.Key -notlike "*token*") { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName } }
    }
    End {
        $headers = @{
            Authorization  = "Bearer $Token"
            "Content-type" = "application/json"
        }
        try {
            if ($IntuneDeviceId) {
                $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$IntuneDeviceId"
            }
            elseif ($AzureDeviceId) {
                $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/?`$filter=azureADDeviceId%20eq%20'$AzureADDeviceId'"
            }
            else {
                $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/?`$filter=deviceName%20eq%20'$DeviceName'"
            }
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
            if ($DeviceName) {
                "The request returned $($response.'@odata.count') device(s)." | Write-LogRunbook -Caller $CmdletName
                if (-not $HideParams) { $response.value | ConvertTo-Json -Compress | Write-LogRunbook -Caller $CmdletName }
                $response.value
            }
            else {
                $response | ConvertTo-Json -Compress | Write-LogRunbook -Caller $CmdletName
                $response
            }
        }
        catch {
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "Check the above error calling '$url'")
        } 
    }      
}
function Start-IntuneDeviceWipeAndSync {
    <#
  .DESCRIPTION
  Triggers device wipe & sync for a given IntuneDeviceId

 .Example
   Start-IntuneDeviceWipeAndSync -Token 'yourGraphToken' -IntuneDeviceId '390da3ec-cc71-4544-904c-f851740f01f8'
#>
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$Token,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$IntuneDeviceId
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
            $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$IntuneDeviceId/wipe"
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Body $body -Method Post -UseBasicParsing -ErrorAction Stop
            Write-LogRunbook "Wipe StatusCode: '$($response.StatusCode)' (Expected value for success: 204) Wipe StatusDescription: '$($response.StatusDescription)' (Expected value for success: NoContent)" -Caller $CmdletName
            $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$IntuneDeviceId/syncDevice"
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Body $body -Method Post -UseBasicParsing -ErrorAction Stop
            Write-LogRunbook "syncDevice StatusCode: '$($response.StatusCode)' (Expected value for success: 204) syncDevice StatusDescription: '$($response.StatusDescription)' (Expected value for success: NoContent)" -Caller $CmdletName
        }
        catch {
            Write-ErrorRunbook
            throw [CustomException]::new( $CmdletName, "StatusCode: '$($($_.Exception).StatusCode)' (Expected value for success: 204) StatusDescription: '$($($_.Exception).Message)' (Expected value for success: NoContent) url: $url")
        } 
    }      
}
function Start-IntuneAutopilotDevicesSync {
    <#
  .DESCRIPTION
  Initiates a sync of all AutoPilot registered devices from Store for Business and other portals. If the sync successful, this action returns a 204 No Content response code. If a sync is already in progress, the action returns a 409 Conflict response code. If this sync action is called within 10 minutes of the previous sync, the action returns a 429 Too Many Requests response code.

 .Example
   Start-IntuneAutopilotDevicesSync -Token 'yourGraphToken'
#>
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$Token
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
            $url = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotSettings/sync"
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Method Post -UseBasicParsing -ErrorAction Stop
            "StatusCode: $($response.StatusCode) (Expected value for success: 204) StatusDescription: $($response.StatusDescription) (Expected value for success: NoContent)" | Write-LogRunbook -Caller $CmdletName
        }
        catch {
            $CurrentError = $_
            switch ($_.Exception.StatusCode) {
                'Conflict' {
                    "<Conflict> StatusCode: '$($($CurrentError.Exception).StatusCode)' (Expected value for success: 204) StatusDescription: '$($($CurrentError.Exception).Message)' (Expected value for success: NoContent)" | Write-LogRunbook -Caller $CmdletName
                }
                'TooManyRequests' {
                    "<TooManyRequests> StatusCode: '$($($CurrentError.Exception).StatusCode)' (Expected value for success: 204) StatusDescription: '$($($CurrentError.Exception).Message)' (Expected value for success: NoContent)" | Write-LogRunbook -Caller $CmdletName
                }
                Default {
                    Write-ErrorRunbook
                    throw [CustomException]::new( $CmdletName, "StatusCode: '$($($CurrentError.Exception).StatusCode)' (Expected value for success: 204) StatusDescription: '$($($CurrentError.Exception).Message)' (Expected value for success: NoContent) url: $url")
                }
            } 
        }      
    }
}
function Get-WindowsAutopilotSettings {
    <#
  .DESCRIPTION
  Returns the current status of the windowsAutopilotSettings

 .Example
   Get-WindowsAutopilotSettings -Token 'yourGraphToken'
#>
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$Token
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
            $url = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotSettings"
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -UseBasicParsing -ErrorAction Stop
            #"StatusCode: $($response.StatusCode) (Expected value for success: 204) StatusDescription: $($response.StatusDescription) (Expected value for success: NoContent)" | Write-LogRunbook -Caller $CmdletName
            $response.Content | Write-LogRunbook -Caller $CmdletName
            $response.Content | ConvertFrom-Json
        }
        catch {
            $CurrentError = $_
            switch ($_.Exception.Response.StatusCode) {
                'TooManyRequests' {
                    "StatusCode: '$($($CurrentError.Exception).StatusCode)' (Expected value for success: 204) StatusDescription: '$($($CurrentError.Exception).Message)' (Expected value for success: NoContent)" | Write-LogRunbook -Caller $CmdletName
                }
                Default {
                    Write-ErrorRunbook
                    throw [CustomException]::new( $CmdletName, "StatusCode: '$($($CurrentError.Exception).StatusCode)' (Expected value for success: 204) StatusDescription: '$($($CurrentError.Exception).Message)' (Expected value for success: NoContent) url: $url")
                }
            } 
        }      
    }
}
function New-DeviceName {
    <#
  .DESCRIPTION
  Returns the current status of the windowsAutopilotSettings

 .Example
   Get-WindowsAutopilotSettings -Token 'yourGraphToken'
#>
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [pscustomobject]$NamingConvention
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        if (-not $HideParams) { $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { if ($_.Key -notlike "*token*") { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName } } }
    }
    End {

        try {

        }
        catch {

        }      
    }
}

#EndRegion -------------------------------------------------- [Functions] ----------------------------------------------


#Region -------------------------------------------------------- [Main] ----------------------------------------------

try {  
    $RequestBody = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { ConvertFrom-Json -InputObject $WebhookData.RequestBody }
    #Format the input data and post it into the data stream
    $DeviceHashData = $RequestBody.DeviceHashData 
    $SerialNumber = $RequestBody.SerialNumber
    $ProductKey = $RequestBody.ProductKey
    $GroupTag = $RequestBody.GroupTag
    $ComputerName = $RequestBody.ComputerName

    $RequestBody | ConvertTo-Json -Compress | Write-LogRunbook -Caller 'Get-DeviceInfoMain'
    [string]$OutDateTime = (Get-Date -Format 'MM-dd-yyyy HH\:mm\:ss.fff').ToString()
    Write-Output "[$OutDateTime] :: DeviceHashData: $DeviceHashData SerialNumber: $SerialNumber ProductKey: $ProductKey GroupTag: $GroupTag ComputerName: $ComputerName"
    
    #Getting rid of formatting errors
    $DeviceHashData = $DeviceHashData -creplace "rn", "rrnn" -creplace "RN", "RRNN" -creplace "Rn", "RRnn" -creplace "rN", "rrNN"
    $SerialNumber = $SerialNumber -creplace "rn", "rrnn" -creplace "RN", "RRNN" -creplace "Rn", "RRnn" -creplace "rN", "rrNN"
    $ProductKey = $ProductKey -creplace "rn", "rrnn" -creplace "RN", "RRNN" -creplace "Rn", "RRnn" -creplace "rN", "rrNN"
    $GroupTag = $GroupTag -creplace "rn", "rrnn" -creplace "RN", "RRNN" -creplace "Rn", "RRnn" -creplace "rN", "rrNN"
    $ComputerName = $ComputerName -creplace "rn", "rrnn" -creplace "RN", "RRNN" -creplace "Rn", "RRnn" -creplace "rN", "rrNN"
    Write-Output "After replace rn: DeviceHashData: $DeviceHashData SerialNumber: $SerialNumber ProductKey: $ProductKey GroupTag: $GroupTag ComputerName: $ComputerName"
    If ($SerialNumber -and $DeviceHashData) {
        Write-LogRunbook "Serial and hash was successfully collected for computer $($ComputerName)" -Caller 'Get-DeviceInfoMain'
    }

    Else {
        Write-LogRunbook "Serial and hash was not collected for computer $($ComputerName)" -Caller 'Get-DeviceInfoMain'
        Exit
    }

    ## Device name check
    $TargetToken = Get-Token -TenantId $DestinationTenantId -AppId $DestinationApplicationId -AppSecret $DestinationApplicationSecret
    $DeviceNameObj = Get-AzureTableEntities -StorageAccountName $StorageAccountName -TableName $AzTableName -filter "RowKey%20eq%20'$ComputerName'" #moved up
    $NamingConventionOjb = Get-AzureTableEntities -StorageAccountName $StorageAccountName -TableName $AzNamingConventionTable
    if (-not $DeviceNameObj) { throw [CustomException]::new( "Get-DeviceName", "Entry with RowKey '$ComputerName' was not found in table '$AzTableName'") }
    #####################################################################
    #####################################################################
    [string]$OutDateTime = (Get-Date -Format 'MM-dd-yyyy HH\:mm\:ss.fff').ToString()
    Write-Output "[$OutDateTime] :: Source tenant: '$SourceTenantId'"
    $SourceToken = Get-Token -TenantId $SourceTenantId -AppId $SourceApplicationId -AppSecret $SourceApplicationSecret
    $IntuneDeviceInfo = Get-IntuneDevcieInfo -Token $SourceToken -DeviceName $ComputerName #'us-467995179101'
    if (-not $IntuneDeviceInfo) { throw [CustomException]::new( "Get-IntuneDevcieInfoMain", "No device found for $ComputerName") }

   # start device wipe and sync for each intune entry matching the device info
    $IntuneDeviceInfo | ForEach-Object {
        [string]$OutDateTime = (Get-Date -Format 'MM-dd-yyyy HH\:mm\:ss.fff').ToString()
        Write-Output "[$OutDateTime] :: Intune device found: IntuenDeviceId '$($_.id)' AzureADDeviceId '$($_.azureADDeviceId)' DeviceName '$($_.deviceName)'."
        Write-Output "[$OutDateTime] :: DeviceEnrollmentType: '$($_.deviceEnrollmentType)' DevcieManagementAgent: '$($_.managementAgent)'."
        if ($_.deviceEnrollmentType -eq "windowsCoManagement" -and $_.managementAgent -eq "configurationManagerClientMdm") {
            Write-Output "[$OutDateTime] :: This is an Hybrid Azure AD Joined or co-managed device."
        }
        Write-Output "[$OutDateTime] :: Starting device wipe..."
        Start-IntuneDeviceWipeAndSync -Token $SourceToken -IntuneDeviceId $_.id
        
        # Wait until the device is removed from Intune for SourceTenantId
        $IntuneDeviceInfoCheck = Get-IntuneDevcieInfo -Token $SourceToken -IntuneDeviceId $_.id #'us-467995179101'
        While ($IntuneDeviceInfoCheck) {
            if ($Global:CheckCount -gt $Global:CheckCountLimit) { throw [CustomException]::new( "Get-IntuneDevcieInfoMain", "Retry count limit reached:$Global:CheckCount. Intune device still exists. Id:'$($_.id)'") }
            Start-Sleep -Seconds 90
            $Global:CheckCount++
            Write-LogRunbook "Intune device still exists: IntuenDeviceId '$($_.id)' AzureADDeviceId '$($_.azureADDeviceId)'" -Caller 'Get-IntuneDevcieInfoMain'
            $IntuneDeviceInfoCheck = Get-IntuneDevcieInfo -Token $SourceToken -IntuneDeviceId $_.id -HideParams #'us-467995179101'
        }
        [string]$OutDateTime = (Get-Date -Format 'MM-dd-yyyy HH\:mm\:ss.fff').ToString()
        Write-Output "[$OutDateTime] :: This device was removed from Intune. It is currently being wiped."

        # Remove the device from Windows Autopilot devices if exists. In some cases Hybrid joined devices were also imported to Intune Autopilot.
        if (Get-WindowsAutopilotDevice -Token $SourceToken -DeviceSerialNumber $SerialNumber) {
            [string]$OutDateTime = (Get-Date -Format 'MM-dd-yyyy HH\:mm\:ss.fff').ToString()
            Write-Output "[$OutDateTime] :: Device found in Windows Autopilot Devices for tenant '$SourceTenantId'. Removing Autopilot device..."
            Remove-WindowsAutopilotDevice -Token $SourceToken -DeviceSerialNumber $SerialNumber
        } else {
            [string]$OutDateTime = (Get-Date -Format 'MM-dd-yyyy HH\:mm\:ss.fff').ToString()
            Write-Output "[$OutDateTime] :: Device was not found in Windows Autopilot Devices for tenant '$SourceTenantId'."
        }

        # Run Windows Autopilot devices Sync if it is not already running. Wait until the sync finishes regardless of who started it.
        Write-Output "[$OutDateTime] :: Run Windows Autopilot devices Sync if it is not already running. Wait until the sync finishes regardless of who started it."
        try {
            $AutopilotSettingsState = Get-WindowsAutopilotSettings -Token $SourceToken
            $AutopilotSettingsStateJson = $AutopilotSettingsState | ConvertTo-Json -Compress
            [string]$OutDateTime = (Get-Date -Format 'MM-dd-yyyy HH\:mm\:ss.fff').ToString()
            if ($AutopilotSettingsState.syncStatus -ne 'completed') {
                Write-Output "[$OutDateTime] :: IntuneAutopilotDevicesSync will not run. Current state: $AutopilotSettingsStateJson"
            }
            else {
                Write-Output "[$OutDateTime] :: Running IntuneAutopilotDevicesSync. Current state: $AutopilotSettingsStateJson"
                Start-IntuneAutopilotDevicesSync -Token $SourceToken # check if this is actually needed....
            }
            $AutopilotSettingsState = Get-WindowsAutopilotSettings -Token $SourceToken
            while (($AutopilotSettingsState.syncStatus -eq 'inProgress') -and ($Global:CheckCount -le $Global:CheckCountLimit)) {
                #if ($Global:CheckCount -gt $Global:CheckCountLimit) { throw [CustomException]::new( "Start-IntuneAutopilotDevicesSyncMain", "Retry count limit reached:$Global:CheckCount. Autopilot sync not done") } c# not vital if sync not done, just continue
                Start-Sleep -Seconds 15
                $Global:CheckCount++
                $AutopilotSettingsState = Get-WindowsAutopilotSettings -Token $SourceToken
                Write-LogRunbook "Sync in progress for $SourceTenantId" -Caller 'Get-WindowsAutopilotSettingsMain'
            }
        }
        catch {
            switch ($_.Exception.Message) {
                'Start-IntuneAutopilotDevicesSync' { Write-Output "Start-IntuneAutopilotDevicesSync error caught: $($($_.Exception).additionalData)"; Write-Output $Error[-1] }
                Default { Write-Output "Start-IntuneAutopilotDevicesSync other error caught."; Write-Output $Error[-1] }
            }
        }
        Start-Sleep -Seconds 5
        if ($AutopilotSettingsState.syncStatus -ne 'completed') {
            $AutopilotSettingsStateJson = $AutopilotSettingsState | ConvertTo-Json -Compress
            throw [CustomException]::new( "Start-IntuneAutopilotDevicesSyncStatus", "There was a problem with the intune Windows Autopilot devices sync. CheckCount: [$CheckCount] $AutopilotSettingsStateJson")  # maybe should be no error here, just continue. test with throw for now
        }
        Write-LogRunbook "Sync FINISHED for $SourceTenantId. Status = $($AutopilotSettingsState.syncStatus)" -Caller 'Get-WindowsAutopilotSettingsMain'
        [string]$OutDateTime = (Get-Date -Format 'MM-dd-yyyy HH\:mm\:ss.fff').ToString()
        Write-Output "[$OutDateTime] :: Sync FINISHED for $SourceTenantId. Status = $($AutopilotSettingsState.syncStatus)"
        Write-Output "[$OutDateTime] :: Removing device object from Azure."
        
        # remove device from Azure
        ConvertTo-AADDeviceObjectId -Token $SourceToken -AzureAdDeviceId $_.azureADDeviceId | Remove-AADDeviceObject -Token $SourceTokenAAD
    }
    [string]$OutDateTime = (Get-Date -Format 'MM-dd-yyyy HH\:mm\:ss.fff').ToString()
    Write-Output "[$OutDateTime] :: All done for Source Tenant Id: $SourceTenantId."

    #########################################################################
    # Target Tenant
    #########################################################################
    [string]$OutDateTime = (Get-Date -Format 'MM-dd-yyyy HH\:mm\:ss.fff').ToString()
    Write-Output "[$OutDateTime] :: Target tenant: $DestinationTenantId"
    $TargetToken = Get-Token -TenantId $DestinationTenantId -AppId $DestinationApplicationId -AppSecret $DestinationApplicationSecret
    # import device to target tenant autopilot
    $DeviceNameObj | ConvertTo-Json -Compress | Write-Output
    if (Get-WindowsAutopilotDevice -Token $TargetToken -DeviceSerialNumber $SerialNumber) {
        Write-LogRunbook "The device with serial number '$SerialNumber' already exists in WindowsAutopilot for tenant '$DestinationTenantId'" -Caller 'Get-WindowsAutopilotDeviceMain'
        [string]$OutDateTime = (Get-Date -Format 'MM-dd-yyyy HH\:mm\:ss.fff').ToString()
        Write-Output "[$OutDateTime] :: The device with serial number '$SerialNumber' already exists in '$DestinationTenantId'"
    }
    else {
        [string]$OutDateTime = (Get-Date -Format 'MM-dd-yyyy HH\:mm\:ss.fff').ToString()
        Write-Output "[$OutDateTime] :: The device with serial number '$SerialNumber' does not exist in WindowsAutopilot for tenant '$DestinationTenantId'. Importing..."
        $ImportId = Import-WindowsAutopilotDevice -Token $TargetToken -DeviceSerialNumber $SerialNumber -WindowsProductID $ProductKey -HardwareHash $DeviceHashData
        $ImportState = Get-WindowsAutopilotDevice -Token $TargetToken -importedWindowsAutopilotDeviceIdentityId $ImportId
        # to import a device to source tenant, use below
        #$ImportId = Import-WindowsAutopilotDevice -Token $SourceToken -DeviceSerialNumber $SerialNumber -WindowsProductID $ProductKey -HardwareHash $DeviceHashData
        #$ImportState = Get-WindowsAutopilotDevice -Token $SourceToken -importedWindowsAutopilotDeviceIdentityId $ImportId
    
        # Check if the Windows Autopilot device import went ok
        while (($ImportState.deviceImportStatus -eq 'unknown') -and ($Global:CheckCount -le $Global:CheckCountLimit)) {
            Start-Sleep -Seconds 9
            $Global:CheckCount++
            $ImportState = Get-WindowsAutopilotDevice -Token $TargetToken -importedWindowsAutopilotDeviceIdentityId $ImportId -HideParams
            Write-LogRunbook "Import in progress in progress for $DestinationTenantId" -Caller 'Get-WindowsAutopilotDeviceMain'
        }
        if ($ImportState.deviceErrorCode -ne 0) {
            $ImportStateJson = $ImportState | ConvertTo-Json -Compress
            if ([string]::IsNullOrWhitespace($ImportState.deviceRegistrationId)) { throw [CustomException]::new( "Get-WindowsAutopilotDeviceMain", "There was an issue importing this device CheckCount: [$CheckCount]. $ImportStateJson") }
            throw [CustomException]::new( "Get-WindowsAutopilotDeviceMain", "There was a problem importing the autopilot data for this device. $ImportStateJson") 
        }
    }
    [string]$OutDateTime = (Get-Date -Format 'MM-dd-yyyy HH\:mm\:ss.fff').ToString()
    Write-Output "[$OutDateTime] :: Import-WindowsAutopilotDevice done."

    # Update device name
    Update-WindowsAutopilotDeviceProperties -Token $TargetToken -windowsAutopilotDeviceIdentityId $ImportState.deviceRegistrationId -DeviceName $DeviceNameObj.PartitionKey
    [string]$OutDateTime = (Get-Date -Format 'MM-dd-yyyy HH\:mm\:ss.fff').ToString()
    Write-Output "[$OutDateTime] :: Update-WindowsAutopilotDeviceProperties done."
    Write-Output "[$OutDateTime] :: Start-IntuneAutopilotDevicesSyncMain"
    try {
        $AutopilotSettingsState = Get-WindowsAutopilotSettings -Token $TargetToken
        $AutopilotSettingsStateJson = $AutopilotSettingsState | ConvertTo-Json -Compress
        [string]$OutDateTime = (Get-Date -Format 'MM-dd-yyyy HH\:mm\:ss.fff').ToString()
        if ($AutopilotSettingsState.syncStatus -ne 'completed') {
            Write-Output "[$OutDateTime] :: IntuneAutopilotDevicesSync will not run. Current state: $AutopilotSettingsStateJson"
        }
        else {
            Write-Output "[$OutDateTime] :: Running IntuneAutopilotDevicesSync. Current state: $AutopilotSettingsStateJson"
            Start-IntuneAutopilotDevicesSync -Token $TargetToken # check if this is actually needed....
        }
    }
    catch {
        switch ($_.Exception.Message) {
            'Start-IntuneAutopilotDevicesSync' { Write-Output "Start-IntuneAutopilotDevicesSync error caught: $($($_.Exception).additionalData)"; Write-Output $Error[-1] }
            Default { Write-Output "Start-IntuneAutopilotDevicesSync other error caught."; Write-Output $_] }
        }
    }
    $AutopilotSettingsState = Get-WindowsAutopilotSettings -Token $TargetToken
    while (($AutopilotSettingsState.syncStatus -eq 'inProgress') -and ($Global:CheckCount -le $Global:CheckCountLimit)) {
        Start-Sleep -Seconds 15
        $Global:CheckCount++
        $AutopilotSettingsState = Get-WindowsAutopilotSettings -Token $TargetToken
    }
    if ($AutopilotSettingsState.syncStatus -ne 'completed') {
        $AutopilotSettingsStateJson = $AutopilotSettingsState | ConvertTo-Json -Compress
        throw [CustomException]::new( "Start-IntuneAutopilotDevicesSyncStatus", "There was a problem with the intune Windows Autopilot devices sync. $AutopilotSettingsStateJson") 
    }
    Start-Sleep -Seconds 90
    Write-LogRunbook "Sync FINISHED for $SourceTenantId. Status = $($AutopilotSettingsState.syncStatus)" -Caller 'Get-WindowsAutopilotSettingsMain'
    [string]$OutDateTime = (Get-Date -Format 'MM-dd-yyyy HH\:mm\:ss.fff').ToString()
    Write-Output "[$OutDateTime] :: Sync FINISHED for $SourceTenantId. Status = $($AutopilotSettingsState.syncStatus)"
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
    Write-LogRunbook "Execution completed with exit code: $Global:ExitCode" -Caller 'Info-End'
}