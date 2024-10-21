<#PSScriptInfo

.VERSION 1.0

.DATE 28-Aug-2023

.AUTHOR adrian.cojocaru

#>

<#
  .SYNOPSIS
  Check if the devices are part of certain AAD groups via their Intune IDs or DeviceName.

  .DESCRIPTION
  Check if the devices inside a CSV file are part of certain AzureAD groups defined in the $groupsToCheck Array.
  This check can be done via Intune ID (precise but slower) or Device Name (faster but less precise).
  The CSV should have a column called DeviceName or DeviceId depending what we are looking for.
  This CSV can come Intune from exports of Proactive Remediation, Compliance policy reports etc.

  .PARAMETER DevicesCSV
  The path to the CSV file containing the name of the device

  .OUTPUTS
  A log file ($LogPath) will be created by default under the "Logs-<ScriptName>" folder next to the script.
  An output folder ($OutputFolder) "Output-<ScriptName>" will be created by default next to the script.
  The resulting CSV has all the info in the original one plus AzureADObjectId & PartOfGroup (true/false).

  .EXAMPLE
  .\Get-IntuneDeviceIdPartOfAADGroup -DevicesCSV "C:\Users\acojoca4\DeviceRunStates.csv"

#>
Param
(
    [Parameter (Mandatory = $false)]
    [string]$DevicesCSV = "4006-4c66-b926-722717adef24.csv"
)
#Region ----------------------------------------------------- [AzureAD Variables] ----------------------------------------------
[string]$tenantId = if ($env:AZUREPS_HOST_ENVIRONMENT) { Get-AutomationVariable -Name "MyTenantId" } else { $env:MyTenantId }
[string]$clientId = if ($env:AZUREPS_HOST_ENVIRONMENT) { Get-AutomationVariable -Name "MyAppClientId" } else { $env:MyAppClientId }
[string]$appSecret = if ($env:AZUREPS_HOST_ENVIRONMENT) { Get-AutomationVariable -Name "MyDAppSecret" } else { $env:MyDAppSecret }
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
$DateTime = Get-Date
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
function  Get-GraphToken {
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
    }
    End {
        try {
            $GraphUrl = "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token"
            $body = @{
                Grant_Type    = "client_credentials"
                Scope         = "https://graph.microsoft.com/.default"
                Client_Id     = $clientId
                Client_Secret = $appSecret
            }
              
            $connection = Invoke-RestMethod -Method Post -Uri $GraphUrl -Body $body -ErrorAction Stop
            $connection.access_token
        }
        catch {
            Write-Error2
            throw [CustomException]::new( $CmdletName, "Error calling $GraphUrl")
        }
    } 
}

function Convert-ToAADDeviceObjectId {
    <#
  .DESCRIPTION
  Returns the AzureAD Device Object ID for a given IntuneDeviceId, AzureAdDeviceId or DisplayName.
  If multiple devices have the same DisplayName, only the Azure AD Device Object ID for the first one will be returned.

 .Example
  Convert-ToAADDeviceObjectId -IntuneDeviceId $devices[3].DeviceId
  Convert-ToAADDeviceObjectId -DeviceName 'MyIDIDNL17076'
#>
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$AzureAdDeviceId,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$IntuneDeviceId,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$DeviceName
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
                <#
                If ($DeviceObjectId.Count -ne 0) {
                    $DeviceObjectId | ForEach-Object {
                        $URL = "https://graph.microsoft.com/beta/devices/$_/memberOf?`$select=displayName,id"
                        $responseGR = Invoke-RestMethod -Headers $headers -Uri $URL -Method Get -ErrorAction Stop
                        $GroupList.Add($responseGR.value)
                    }
                }
                #$AADDeviceInfoList.Add($response)
                #$AlreadyAddedList.Add($DeviceName)
                $GroupList
                #>
            }
            else {
                Write-Log "All params can't be empty." -Caller $CmdletName
            }
        }
        catch {
            switch ($_.Exception.Response.StatusCode) {
                'Unauthorized' {
                    if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                        Write-Log "Token expired. Getting a new one. GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'" -Caller $CmdletName
                        $global:Token_Graph = Get-GraphToken
                        $Global:GraphTokenRefreshCount++
                        Convert-ToAADDeviceObjectId @PSBoundParameters
                    } else {
                        Write-Error2
                        throw [CustomException]::new( $CmdletName, "GraphTokenRefreshLimit '$Global:GraphTokenRefreshCount' reached! ")
                    }
                }
                'NotFound' { 
                    Write-Log "AzureAD object not found." -Color DarkYellow -Caller $CmdletName
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
function  Get-AADDeviceGroupMembership {
    <#
  .DESCRIPTION
  Returns the Azure AD groups that the device is a DIRECT member of

 .Example
   "AzureADDeviceId1","AzureADDeviceId2","AzureADDeviceId3" | Get-AADDeviceInfo
#>
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$AADDeviceObjectId
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
        #$AlreadyAddedList = [System.Collections.ArrayList]::new()
        #$GroupList = [System.Collections.ArrayList]::new()
    }
    Process {
        try {
            $headers = @{
                Authorization  = "Bearer $Token_Graph"
                "Content-type" = "application/json"
            }
            $URL = "https://graph.microsoft.com/beta/devices/$AADDeviceObjectId/memberOf?`$select=id"
            $responseGR = Invoke-RestMethod -Headers $headers -Uri $URL -Method Get -ErrorAction Stop
            $responseGR.value.id
        }
        catch {
            switch ($_.Exception.Response.StatusCode) {
                'Unauthorized' {
                    if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                        Write-Log "Token expired. Getting a new one. GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'" -Caller $CmdletName
                        $global:Token_Graph = Get-GraphToken
                        $Global:GraphTokenRefreshCount++
                        Get-AADDeviceGroupMembership @PSBoundParameters
                    } else {
                        Write-Error2
                        throw [CustomException]::new( $CmdletName, "GraphTokenRefreshLimit '$Global:GraphTokenRefreshCount' reached! ")
                    }
                }
                'NotFound' { 
                    Write-Log "AzureAD object not found." -Color DarkYellow -Caller $CmdletName
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
function  Get-AADTransitiveGroupMembers {
    <#
  .DESCRIPTION
  Returns a flat list of all nested members in an AzureAD group

 .Example
   Get-AADTransitiveGroupMembers -AADGroupId 'wwwwwwwww'
#>
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message Object id of the Azure AD group.
        [string]$AADGroupId
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        #$AlreadyAddedList = [System.Collections.ArrayList]::new()
        $MembersList = @()
    }
    Process {
        try {
            $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller $CmdletName }
            $headers = @{
                Authorization  = "Bearer $Token_Graph"
                "Content-type" = "application/json"
            }
            $url = "https://graph.microsoft.com/v1.0/groups/$AADGroupId/transitiveMembers?`$select=id,displayName,deviceId,#@odata.type"
            $responseGR = Invoke-RestMethod -Headers $headers -Uri $url -Method Get -ErrorAction Stop
            if ($responseGR.value) { $MembersList += $responseGR.value}
            while ($responseGR.'@odata.nextLink') {
                $responseGR = Invoke-RestMethod -Headers $headers -Uri $responseGR.'@odata.nextLink' -Method Get -ErrorAction Stop
                if ($responseGR.value) { $MembersList += $responseGR.value}
            }
            $MembersList
        }
        catch {
            switch ($_.Exception.Response.StatusCode) {
                'Unauthorized' {
                    if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                        Write-Log "Token expired. Getting a new one. GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'" -Caller $CmdletName
                        $global:Token_Graph = Get-GraphToken
                        $Global:GraphTokenRefreshCount++
                        Get-AADTransitiveGroupMembers @PSBoundParameters
                    } else {
                        Write-Error2
                        throw [CustomException]::new( $CmdletName, "GraphTokenRefreshLimit '$Global:GraphTokenRefreshCount' reached! ")
                    }
                }
                'NotFound' { 
                    Write-Log "AzureAD object not found." -Color DarkYellow -Caller $CmdletName
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

try {
    if (-not (Test-Path $LogFolder)) { New-Item -ItemType Directory $LogFolder | Out-Null }
    if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory $OutputFolder | Out-Null }
    "====================================================================" | Write-Log -Caller 'Info-Start'
    "======================= ScriptVersion: $Scriptversion =======================" | Write-Log -Caller 'Info-Start'
    $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-Log -Caller 'Info-Start' }
    $Token_Graph = Get-GraphToken

    $groupsToCheck = @(
        'MyGroupId-2d8af6210ecc'
        'MyGroupId-78f27a5d8c58'
        'MyGroupId-a05a3348fdf0'
        'MyGroupId-83388c14de2b'
        'MyGroupId-450e853a4bc9'
        'MyGroupId-756251ebedd4'
        'MyGroupId-2ca2741e3bde'
        'MyGroupId-ed7f821c2321'
        'MyGroupId-2e27fe958c4a'
        'MyGroupId-a34a19f83b1e'
        'MyGroupId-ec12c6956fe5'
        'MyGroupId-1ab76c1a3d20'
        'MyGroupId-274fe98e50df'
        'MyGroupId-f37baac0cc95'
        'MyGroupId-9bea5dee2ec2'
        'MyGroupId-22bef8057737'
        'MyGroupId-4d4385f3c68b'
        'MyGroupId-3548d6ed4fb8'
        'MyGroupId-bf5eba421a33'
    )
    $AllDevicesInGroups = $groupsToCheck | Get-AADTransitiveGroupMembers
    #$UniqueDevicesInGroups = $AllDevicesInGroups | Group-Object -Property displayName
    $UniqueDeviceObjectIdsInGroups = ($AllDevicesInGroups | Group-Object -Property id).Name
    #$ARRcurdevice = Get-AADDeviceGroupMembership -AADDeviceObjectId '0001a02e-3bb3-4ff2-b2c3-27407769db1b'
    $devices = Import-Csv $DevicesCSV
    $devices | ForEach-Object { 
        $DeviceAzureADObjectId = Convert-ToAADDeviceObjectId -IntuneDeviceId $_.DeviceId
        $_ | Add-Member -NotePropertyName AzureADObjectId -NotePropertyValue $DeviceAzureADObjectId
        if ($UniqueDeviceObjectIdsInGroups -contains $DeviceAzureADObjectId) {
            $_ | Add-Member -NotePropertyName PartOfGroup -NotePropertyValue $true
        } else {
            $_ | Add-Member -NotePropertyName PartOfGroup -NotePropertyValue $false

        }
    }
    <#
    $ExcludedDevices = Compare-Object -ReferenceObject $UniqueDeviceObjectIdsInGroups -DifferenceObject $devices.AzureADObjectId -IncludeEqual -ExcludeDifferent
    $ExcludedDevices | ForEach-Object{
        if ($devices.DeviceId -contains $_.Name) {
            $_.PartOfGroup = $true 
        }
    }
    #>

    <#
    $devices | Add-Member -NotePropertyName PartOfGroup -NotePropertyValue $false
    $devices | ForEach-Object {
        $CurrentDeviceGroups = Convert-ToAADDeviceObjectId -IntuneDeviceId $_.DeviceId | Get-AADDeviceGroupMembership
        if (Compare-Object -ReferenceObject $groupsToCheck -DifferenceObject @($CurrentDeviceGroups | Select-Object) -IncludeEqual -ExcludeDifferent) {
            $_.PartOfGroup = $true
            Write-Log "$( $_.DeviceId)" -Color Blue -Caller 'Get-ExcludedDevice'
        }
    }
    #>
    # Convert-ToAADDeviceObjectId -IntuneDeviceId $devices[3].DeviceId
    # Convert-ToAADDeviceObjectId -DeviceName 'MyIDIDNL17076'
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
    $devices | Export-Csv "$OutputFolder\$ScriptName-$TimeStamp.csv" -NoTypeInformation
    Write-Log "============================ Exit code: $Global:ExitCode ==========================" -Caller 'Info-End'
    Exit $Global:ExitCode
}
#token expiration counter