<#

.Version 1.0.0
.Date 28-May-2024
.Author Adrian Cojocaru

.Synopsis
    Write bulk group tags for Windows Autopilot devices.

.Description
    Takes a *.csv file as input either from a blob container or local drive.
    Mandatory CSV columns:
    SerialNumber | GroupTag
    5CG2076CJL | US-STFN-L
    For each serial number in the csv file, the coresponding group tag will be written in the Windows Autopilot device object properties.

#>


#Region ----------------------------------------------------- [AzureAD Variables] ----------------------------------------------
[string]$Global:TenantId = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "TenantId" }                                  
[string]$Global:ApplicationId = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "DW-Automation-CLN-targetappid" }        
[string]$Global:ApplicationSecret = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "DW-Automation-CLN-targetsecret" }   

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
  $Thumbprint variable needs to be initialized before calling the function.
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
function Get-WindowsAutopilotDevice {
    <#
  .DESCRIPTION
  Gets the information about an imported Windows Autopilot Device IdentityId.

 .Example
   Get-WindowsAutopilotDevice -Token 'yourGraphToken' -importedWindowsAutopilotDeviceIdentityId '390da3ec-cc71-4544-904c-f851740f01f8'
   Get-WindowsAutopilotDevice -Token 'yourGraphToken' -DeviceSerialNumber '390daox3ec'
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
            #New-DWLicMNGTLogAnalyticsEvent -Log_Message "Uploading hardware hash to Myizhora tenant for $($ComputerName)" -Severity "Information" -Computer "$($ComputerName)" -Operation "Import"
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
                #$AutopilotDeviceIdentityResponse = Invoke-RestMethod -Headers @{Authorization = "Bearer $($Token)" } -Uri $url -Method POST -Body $AutopilotDeviceIdentityJSON -ContentType "application/json" -ErrorAction Stop
                $response.state
            }
        }
        catch {
            $CurrentError = $_
            switch ($_.Exception.Response.StatusCode) {
                'Unauthorized' {
                    if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                        "StatusCode: '$($($($CurrentError.Exception).Response).StatusCode)'; StatusDescription: '$($($CurrentError.Exception).Message)'; GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'; url: '$url'" | Write-LogRunbook -Caller $CmdletName
                        $Global:Token = Get-Token -TenantId $TenantId -AppId $ApplicationId -AppSecret $ApplicationSecret
                        $PSBoundParameters.Token = $Global:Token
                        $Global:GraphTokenRefreshCount++
                        Get-WindowsAutopilotDevice @PSBoundParameters
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
function Update-WindowsAutopilotDeviceProperties {
    <#
  .DESCRIPTION
  Updates properties for an Autopilot device.

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
        [string]$DeviceName,
        [Parameter(Mandatory = $false, Position = 3, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$GroupTag
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
        $body = if ($DeviceName) { @{'displayName' = $DeviceName } } else { @{'groupTag' = $GroupTag } }
        try {
            #Getting rid of formatting errors and converting to json
            $body = $body | ConvertTo-Json -Compress
            Write-LogRunbook "Updating $body" -Caller $CmdletName
            #New-DWLicMNGTLogAnalyticsEvent -Log_Message "Uploading hardware hash to Myizhora tenant for $($ComputerName)" -Severity "Information" -Computer "$($ComputerName)" -Operation "Import"
            $url = "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities/$windowsAutopilotDeviceIdentityId/updateDeviceProperties"     #//updateDeviceProperties"
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Body $body -Method Post -UseBasicParsing -ErrorAction Stop
            "StatusCode: $($response.StatusCode) (Expected value for success: 204) StatusDescription: $($response.StatusDescription) (Expected value for success: NoContent)" | Write-LogRunbook -Caller $CmdletName
            #$response
        }
        catch {
            $CurrentError = $_
            switch ($_.Exception.Response.StatusCode) {
                'Unauthorized' {
                    if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                        "StatusCode: '$($($($CurrentError.Exception).Response).StatusCode)'; StatusDescription: '$($($CurrentError.Exception).Message)'; GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'; url: '$url'" | Write-LogRunbook -Caller $CmdletName
                        $Global:Token = Get-Token -TenantId $TenantId -AppId $ApplicationId -AppSecret $ApplicationSecret
                        $PSBoundParameters.Token = $Global:Token
                        $Global:GraphTokenRefreshCount++
                        Update-WindowsAutopilotDeviceProperties @PSBoundParameters
                    }
                    else {
                        Write-ErrorRunbook
                        throw [CustomException]::new( $CmdletName, "GraphTokenRefreshLimit '$Global:GraphTokenRefreshCount' reached! ")
                    }
                }
                Default {
                    Write-ErrorRunbook
                    throw [CustomException]::new( $CmdletName, "StatusCode: '$($($($CurrentError.Exception).Response).StatusCode)' (Expected value for success: 204); StatusDescription: '$($($CurrentError.Exception).Message)' (Expected value for success: NoContent); url: '$url'")
                }
            } 
        }
    }      
}


#EndRegion -------------------------------------------------- [Functions] ----------------------------------------------

#Region -------------------------------------------------------- [Main] ----------------------------------------------

# New-AzureStorageContext -StorageAccountName $Global:StorageAccountName -SASToken $Global:SASToken
# Get-AzureStorageFileContent -ShareName a -Path "b/test.csv" -Destination $env:temp -Context $
$Global:Token = Get-Token -TenantId $TenantId -AppId $ApplicationId -AppSecret $ApplicationSecret
[string]$DownloadUrl = 'https://xyz.blob.core.windows.net/dwc/DevicesForGroupTagUpdate.csv'
if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) {
    $CsvFilePath = "$env:TEMP\DevicesForGroupTagUpdate.csv"
    Invoke-RestMethod $DownloadUrl -OutFile $CsvFilePath
}
else { $CsvFilePath = "C:\Users\acojoca4\Downloads\MigratedDevicesTest.csv" } 

$AllCSVDevices = Import-Csv -Path $CsvFilePath
$AllCSVDevices | ForEach-Object {
    if ($_.GroupTag) {
        $CurrentAutopilotDevice = Get-WindowsAutopilotDevice -Token $Global:Token -DeviceSerialNumber $_.SerialNumber
        if ($CurrentAutopilotDevice) {
            Write-Output "Updating device: SerialNumber '$($_.SerialNumber)' GroupTag '$($_.GroupTag)' AutopilotId: '$($CurrentAutopilotDevice.id)'"
            Update-WindowsAutopilotDeviceProperties -Token $Global:Token -windowsAutopilotDeviceIdentityId $CurrentAutopilotDevice.id -GroupTag $_.GroupTag
        }
        else {
            Write-Output "Device with SerialNumber '$($_.SerialNumber)' does not exist in Autopilot for TenantId '$Global:TenantId'"
        }
    }
    else {
        Write-Output "No GroupTag provided for the device with SerialNumber '$($_.SerialNumber)'"
    }
}

