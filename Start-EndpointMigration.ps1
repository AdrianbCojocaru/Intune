<#
.Version 3.0.0
.Author Adrian
.Synopsis
    Migration script from one tenant to another
.Description
    Gathers the hardware hash on the device and triggers the Intune wipe action on the device. The script will delete the autopilot hardware hash and the azure ad object on the source tenant.
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
[string]$DestinationAccountUser = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "DW-Automation-CLN-targetaccuser" }
[string]$DestinationAccountPass = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "DW-Automation-CLN-targetaccpass" }
[string]$SASToken = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "AzTablesSASToken" }
[string]$StorageAccountName = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "StorageAccountName" }
[string]$AzTableName = 'MigratedDevices'

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
            'groupTag'           = 'NO-SWM-OFC'#if ($GroupTag) { "$($GroupTag)" } else { "" }
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
            #New-DWLicMNGTLogAnalyticsEvent -Log_Message "Uploading hardware hash to <Destination> tenant for $($ComputerName)" -Severity "Information" -Computer "$($ComputerName)" -Operation "Import"
                
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
        [string]$DeviceSerialNumber
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

            #New-DWLicMNGTLogAnalyticsEvent -Log_Message "Uploading hardware hash to <Destination> tenant for $($ComputerName)" -Severity "Information" -Computer "$($ComputerName)" -Operation "Import"
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
            } else {
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
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $false)]
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
            #New-DWLicMNGTLogAnalyticsEvent -Log_Message "Uploading hardware hash to <Destination> tenant for $($ComputerName)" -Severity "Information" -Computer "$($ComputerName)" -Operation "Import"
                
            $url = "https://graph.microsoft.com/v1.0/deviceManagement/importedWindowsAutopilotDeviceIdentities/$importedWindowsAutopilotDeviceIdentityId"
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
            Write-LogRunbook "ImportState: $($response.state)" -Caller $CmdletName
            #$AutopilotDeviceIdentityResponse = Invoke-RestMethod -Headers @{Authorization = "Bearer $($TargetToken)" } -Uri $url -Method POST -Body $AutopilotDeviceIdentityJSON -ContentType "application/json" -ErrorAction Stop
            $response.state
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
            #New-DWLicMNGTLogAnalyticsEvent -Log_Message "Uploading hardware hash to <Destination> tenant for $($ComputerName)" -Severity "Information" -Computer "$($ComputerName)" -Operation "Import"
            $url = "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities/$windowsAutopilotDeviceIdentityId/updateDeviceProperties"     #//updateDeviceProperties"
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Body $body -Method Post -ErrorAction Stop
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
  Convert-ToAADDeviceObjectId -Token 'yourGraphToken' -DeviceName 'IDIDNL17076'
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
            #New-DWLicMNGTLogAnalyticsEvent -Log_Message "Uploading hardware hash to <Destination> tenant for $($ComputerName)" -Severity "Information" -Computer "$($ComputerName)" -Operation "Import"
            $url = "https://graph.microsoft.com/v1.0/devices/$AzureADDeviceObjectId"
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Method Delete -ErrorAction Stop
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
            #New-DWLicMNGTLogAnalyticsEvent -Log_Message "Uploading hardware hash to <Destination> tenant for $($ComputerName)" -Severity "Information" -Computer "$($ComputerName)" -Operation "Import"
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
                if (-not $HideParams) {$response.value | ConvertTo-Json -Compress | Write-LogRunbook -Caller $CmdletName}
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
            #New-DWLicMNGTLogAnalyticsEvent -Log_Message "Uploading hardware hash to <Destination> tenant for $($ComputerName)" -Severity "Information" -Computer "$($ComputerName)" -Operation "Import"
            $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$IntuneDeviceId/wipe"
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Body $body -Method Post -ErrorAction Stop
            Write-LogRunbook "Wipe StatusCode: '$($response.StatusCode)' (Expected value for success: 204) Wipe StatusDescription: '$($response.StatusDescription)' (Expected value for success: NoContent)" -Caller $CmdletName
            $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$IntuneDeviceId/syncDevice"
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Body $body -Method Post -ErrorAction Stop
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
            #New-DWLicMNGTLogAnalyticsEvent -Log_Message "Uploading hardware hash to <Destination> tenant for $($ComputerName)" -Severity "Information" -Computer "$($ComputerName)" -Operation "Import"
            $url = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotSettings/sync"
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Method Post -ErrorAction Stop
            "StatusCode: $($response.StatusCode) (Expected value for success: 204) StatusDescription: $($response.StatusDescription) (Expected value for success: NoContent)" | Write-LogRunbook -Caller $CmdletName
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
            #New-DWLicMNGTLogAnalyticsEvent -Log_Message "Uploading hardware hash to <Destination> tenant for $($ComputerName)" -Severity "Information" -Computer "$($ComputerName)" -Operation "Import"
            $url = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotSettings"
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -ErrorAction Stop
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

#EndRegion -------------------------------------------------- [Functions] ----------------------------------------------


#Region -------------------------------------------------------- [Main] ----------------------------------------------

