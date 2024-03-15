<#

.Version 1.0.0

.Author Adrian Cojocaru

.Synopsis
    Device compliance report for one or more compliance policies

.Description
    This script combines data from EntraID, Intune and Compliance for each device in the Policy assignment group, ignoring devices from the exclusion group to create a comprehensive report.

#>

#Region ----------------------------------------------------- [AzureAD Variables] ----------------------------------------------
[string]$Global:TenantId = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "TenantId" }
[string]$Global:ApplicationId = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "DWC-EUD-Automation_AppId" }
[string]$Global:Thumbprint = if ($env:AZUREPS_HOST_ENVIRONMENT -or $PSPrivateMetadata.JobId) { Get-AutomationVariable -Name "DWC-EUD-Automation_CertThumbprint" }

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
class CustomQueryException : Exception {
    [string] $additionalData

    CustomQueryException($Message, $additionalData) : base($Message) {
        $this.additionalData = $additionalData
    }
}
#EndRegion ----------------------------------------------------- [Classes] ----------------------------------------------
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
                Authorization  = "Bearer $Token"
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
                        Get-IntuneDevicePrimaryUser @PSBoundParameters
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
    End {
        # Write-LogRunbook "Ended" -Caller $CmdletName
    }
}
function  Test-AADGroup {
    <#
.DESCRIPTION
Check if the AzureAD group exists and the Id matches the name.
This is a safeguard in case of mistakes in the config file
.Example
Test-AADGroup -GroupId '0ed6c216-dde9-4a06-83fe-923f1e42c86a' -GroupName 'TestAADGroup1'
#>
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$GroupId,
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$GroupName
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
    }
    End {
        try {
            $headers = @{ 'Authorization' = "Bearer $Token_Graph" }
            $url = "https://graph.microsoft.com/v1.0/groups/$GroupId"
            $response = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -UseBasicParsing -ErrorAction Stop
            $GroupInfo = $response.Content | ConvertFrom-Json
            #check this when the group will have a few members..
            if ($GroupInfo.displayName -eq $GroupName) {
                Write-LogRunbook 'Group Name & Id match.' -Caller $CmdletName
                return $true
            }
            else {
                Write-LogRunbook "The provided Group name: '$GroupName' doesn't match the actual Group display name: '$($GroupInfo.displayName)' for GroupId: '$GroupId'." -Caller $CmdletName
                return $false
            }
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
                        Test-AADGroup @PSBoundParameters
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

function  Get-AllAADGroupMembers {
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        [string]$Token,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$GroupId
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
        $GroupMembersList = @()
        $count = 0
    }
    End {
        try {
            $headers = @{ 'Authorization' = "Bearer $Token" }
            $url = "https://graph.microsoft.com/v1.0/groups/$GroupId/members"
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -UseBasicParsing -ErrorAction Stop
            #$response.Content | ConvertFrom-Json
            #check this when the group will have a few members..
            $response.value | Select-Object -Property '@odata.type', 'id', 'deviceId', 'displayName' | Out-String | Write-LogRunbook -Caller $CmdletName
            if ($response.value) { $GroupMembersList += $response.value }
            while ($response.'@odata.nextLink') {
                $count++
                Write-LogRunbook "Current @odata.nextLink: $count" -Caller $CmdletName
                #Start-Sleep -Seconds 1
                $response = Invoke-RestMethod -Headers $headers -Uri $response.'@odata.nextLink' -Method Get -ErrorAction Stop
                if ($response.value) { 
                    $response.value | Select-Object -Property '@odata.type', 'id', 'deviceId', 'displayName' | Out-String | Write-LogRunbook -Caller $CmdletName
                    $GroupMembersList += $response.value 
                }
            }
            $GroupMembersList
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
                        Get-AllAADGroupMembers @PSBoundParameters
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
function  Add-AADGroupMembers {
    <#

.DESCRIPTION
  Adds one or more members to an AzureAD group.

.PARAMETER MemberType
  One or more AzureAD Object IDs that you want added.
  Careful what you put here :)
#>
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$AADGroupObjectId,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. One or more AzureAD Object IDs that you want added.
        [string[]]$AADObjectIds
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
        #$urlref = "https://graph.microsoft.com/v1.0/groups/$AADGroupObjectId/members/`$ref"
        $urlMultiObj = "https://graph.microsoft.com/v1.0/groups/$AADGroupObjectId"
        $headers = @{
            Authorization  = "Bearer $Token_Graph"
            "Content-type" = "application/json"
        }
    }
    Process {
        #Write-LogRunbook "Next batch of ObjectIds:" -Caller $CmdletName # comment this later on
        #$ObjectIds | Out-String | Write-LogRunbook -Caller $CmdletName # comment this later on
    }
    End {
        try {
            #Note that up to 20 members can be added in a single request
            # https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0&tabs=http
            $CurrentCount = 0
            $ObjIdsToBeAdded = New-Object System.Collections.Generic.List[System.Object]
            $AADObjectIds | ForEach-Object { $ObjIdsToBeAdded.Add("https://graph.microsoft.com/v1.0/directoryObjects/$_") }
            while ($CurrentCount -lt $AADObjectIds.count) {
                $body = @{}
                # A maximum of 20 objects can be added in a single request
                $NewCount = $CurrentCount + 19
                Write-LogRunbook "Batch of objects to be added:" -Caller $CmdletName
                $ObjIdsToBeAdded[$CurrentCount..$NewCount] | Out-String | Write-LogRunbook -Caller $CmdletName   
                $body.Add("members@odata.bind", $ObjIdsToBeAdded[$CurrentCount..$NewCount])
                $bodyJSON = $body | ConvertTo-Json
                $response = Invoke-RestMethod -Headers $headers -Uri $urlMultiObj -Method Patch -Body $bodyJSON -ErrorAction Stop
                #Write-LogRunbook "$($AADObjectIds.count) objects added. StatusCode = $($response.StatusCode)" -Caller $CmdletName
                Write-LogRunbook "Objects successfully added." -Caller $CmdletName
                $CurrentCount = $NewCount + 1
            }
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
                        Add-AADGroupMembers @PSBoundParameters
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
function  Remove-AADDirectGroupMember {
    <#

.DESCRIPTION
  Removes a member direct from an AzureAD group.
  e.g. If Objects are part of a group that is member of our group, they can't be removed individually

#>
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $false)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$AADGroupObjectId,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Mandatory. Specifies the message string.
        [string]$ObjectId
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        #$urlref = "https://graph.microsoft.com/v1.0/groups/$AADGroupObjectId/members/`$ref"
        $headers = @{
            Authorization  = "Bearer $Token_Graph"
            "Content-type" = "application/json"
        }
    }
    Process {
        try {
            $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
            $url = "https://graph.microsoft.com/v1.0/groups/$AADGroupObjectId/members/$ObjectId/`$ref"
            Write-LogRunbook "Removing $url" -Caller $CmdletName
            $response = Invoke-RestMethod -Headers $headers -Uri $url -Method Delete -ErrorAction Stop
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
                        Remove-AADDirectGroupMember @PSBoundParameters
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
    End {
    }
}
function ConvertTo-AADDeviceObjectId {
    <#
  .DESCRIPTION
  Returns the AzureAD Device Object ID for a given IntuneDeviceId, AzureAdDeviceId or DisplayName.
  If multiple devices have the same DisplayName, only the Azure AD Device Object ID for the first one will be returned.

 .Example
  Convert-ToAADDeviceObjectId -Token 'yourGraphToken' -IntuneDeviceId $devices[3].DeviceId
  Convert-ToAADDeviceObjectId -Token 'yourGraphToken' -DeviceName 'DeviceName'
#>
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $false)]
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
            $CurrentError = $_
            switch ($_.Exception.Response.StatusCode) {
                'Unauthorized' {
                    if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                        "StatusCode: '$($($($CurrentError.Exception).Response).StatusCode)'; StatusDescription: '$($($CurrentError.Exception).Message)'; GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'; url: '$url'" | Write-LogRunbook -Caller $CmdletName
                        $Global:Token = Get-Token -TenantId $TenantId -AppId $ApplicationId -AppSecret $ApplicationSecret
                        $PSBoundParameters.Token = $Global:Token
                        $Global:GraphTokenRefreshCount++
                        ConvertTo-AADDeviceObjectId @PSBoundParameters
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
    End {
        # Write-Log "Ended" -Caller $CmdletName
    }
}
function Get-IntuneDevcieInfo {
    <#
  .DESCRIPTION
  Gets the Intune information about a device

 .Example
   Get-IntuneDevcieInfo -Token $Token -DeviceName 'us-467995179101'
   Get-IntuneDevcieInfo -Token $Token -IntuneDeviceId 'b1c7f08e7-1609-4342-9a3b-803275bbf8af'
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
                        $global:Token_Graph = Get-Token -AppIdSecret
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
function Get-deviceComplianceassignments {
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
            $url = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/{$deviceCompliancePolicyId}/assignments"
            #$ComplianceFilter = "?`$filter=userPrincipalName ne 'nonCompliant'"
            #or
            ##$ComplianceFilter = "?`$filter=userPrincipalName ne 'System account'"
            #$NewUrl = $url + $ComplianceFilter
            #https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/{ffae1e8a-1102-4fb4-a546-cb2a52a41a1f}/deviceStatuses?$filter=status eq 'nonCompliant'
            #Invoke-RestMethod : The remote server returned an error: (501) Not Implemented.1"
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
            #($response.Content | ConvertFrom-Json).value
            if ($response.value) { $assignments += $response.value }
            while ($response.'@odata.nextLink') {
                $count++
                Write-LogRunbook "nextLink nr $count" -Caller $CmdletName
                #Start-Sleep -Seconds 1
                $response = Invoke-RestMethod -Headers $headers -Uri $response.'@odata.nextLink' -Method Get -ErrorAction Stop
                if ($response.value) { $assignments += $response.value }
            }
            $assignments
        }
        catch {
            switch ($_.Exception.Response.StatusCode) {
                'Unauthorized' {
                    if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                        Write-LogRunbook "Token expired. Getting a new one. GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'" -Caller $CmdletName
                        $global:Token_Graph = Get-Token -AppIdSecret
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
function Get-AzureObjectGroupMembership {
    #https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/1559f885-4ca8-4d2f-8927-7450634a123f/deviceRunStates/?$expand=*
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [AllowEmptyString()]
        # Optional. Powershell Health scripts (remediation + detection)
        [string]$AzureObjectId
    )
    Begin {
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        $PSBoundParameters.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { "$($_.Key) = $($_.Value)" | Write-LogRunbook -Caller $CmdletName }
        $StatusesList = @()
        $count = 0
    }
    End {
        try {
            if ($AzureObjectId) {
                $headers = @{ 'Authorization' = "Bearer $Token" }
                $url = "https://graph.microsoft.com/v1.0/devices/$AzureObjectId/memberOf"
                #$ComplianceFilter = "?`$filter=userPrincipalName ne 'nonCompliant'"
                #or
                ##$ComplianceFilter = "?`$filter=userPrincipalName ne 'System account'"
                #$NewUrl = $url + $ComplianceFilter
                #https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/{ffae1e8a-1102-4fb4-a546-cb2a52a41a1f}/deviceStatuses?$filter=status eq 'nonCompliant'
                #Invoke-RestMethod : The remote server returned an error: (501) Not Implemented.1"
                $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
                #($response.Content | ConvertFrom-Json).value
                if ($response.value) { $Groups += $response.value }
                while ($response.'@odata.nextLink') {
                    $count++
                    Write-LogRunbook "nextLink nr $count" -Caller $CmdletName
                    #Start-Sleep -Seconds 1
                    $response = Invoke-RestMethod -Headers $headers -Uri $response.'@odata.nextLink' -Method Get -ErrorAction Stop
                    if ($response.value) { $Groups += $response.value }
                }
                $Groups 
            }
            else {
                Write-LogRunbook "Empty AzureObjectId."
            }
        }
        catch {
            switch ($_.Exception.Response.StatusCode) {
                'Unauthorized' {
                    if ($Global:GraphTokenRefreshCount -lt $Global:GraphTokenRefreshLimit) {
                        Write-LogRunbook "Token expired. Getting a new one. GraphTokenRefreshCount: '$Global:GraphTokenRefreshCount'" -Caller $CmdletName
                        $global:Token_Graph = Get-Token -AppIdSecret
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
#EndRegion -------------------------------------------------- [Functions] ----------------------------------------------

$TenantId
$IntuneApplicationId
$Thumbprint
$Global:Token = Get-Token -TenantId $Global:TenantId -AppId $Global:ApplicationId -CertThumbprint $Global:Thumbprint

<#
$AllEntraIDGroupMembers = Get-AllAADGroupMembers -Token $Global:Token -GroupId 'b1c7f08e7-1609-4342-9a3b-803275bbf8af'
$AllEntraIDGroupMembers | ForEach-Object {
    $this = Get-IntuneDevcieInfo -Token $Global:Token -AzureADDeviceId $_.deviceId
    $_ | Add-Member -NotePropertyName 'IntuneEnrolledDateTime' -NotePropertyValue $this.enrolledDateTime
    $_ | Add-Member -NotePropertyName 'IntunelastSyncDateTime' -NotePropertyValue $this.lastSyncDateTime
    $_ | Add-Member -NotePropertyName 'IntuneDeviceRegistrationState' -NotePropertyValue $this.deviceRegistrationState
    $_ | Add-Member -NotePropertyName 'managementAgent' -NotePropertyValue $this.managementAgent
}
#>

#Get-IntuneDevcieInfo -Token $Global:Token -AzureADDeviceId $AllEntraIDGroupMembers[3].deviceId

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
#$AllEntraIDGroupMembers = Get-AllAADGroupMembers -Token $Global:Token -GroupId 'b1c7f08e7-1609-4342-9a3b-803275bbf8af'
$CompliancePolicyId = 'e8c4e1d4-b7ff-4162-bf95-44a32b19283a'
$CompliancePolicyAssignments = Get-deviceComplianceassignments -deviceCompliancePolicyId $CompliancePolicyId
#$CompliancePolicyAssignments | ForEach-Object {
#    if ($_.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget'){
#        ${$_.groupId} = Get-AllAADGroupMembers -Token $Global:Token -GroupId $_.groupId
#    }  
#}
# $CompliancePolicyAssignments[1].target.'@odata.type'
# $CompliancePolicyAssignments[1].target.groupId
$ComplianceReport = Get-deviceComplianceDeviceStatus -deviceCompliancePolicyId $CompliancePolicyId
$AllDevicesInAssignmentGroups = New-Object System.Collections.Generic.List[System.Object]
$AllPolicyExclusionGroups = New-Object System.Collections.Generic.List[System.Object]
$CompliancePolicyAssignments | ForEach-Object {
    #if ($_.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget'){
    if ($_.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
        $AllDevicesInAssignmentGroupsTemp = [System.Collections.Generic.List[PSObject]]::new()
        $AllDevicesInAssignmentGroupsTemp = Get-AllAADGroupMembers -Token $Global:Token -GroupId $_.target.groupId
        $AllDevicesInAssignmentGroupsTemp | ForEach-Object {
            if ($_.'@odata.type' -eq '#microsoft.graph.device') {
                $AllDevicesInAssignmentGroups.Add($_)
            } else {$_.'@odata.type' }
        }
    }
    elseif ($_.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
        $AllPolicyExclusionGroups.Add($_.target.groupId)
    }
}

$AllDevicesInAssignmentGroups | ForEach-Object {
    #$_.PSObject.Properties.Remove('ExclusionGroups')
    [string]$ExclusionGroups = ''
    Get-AzureObjectGroupMembership -AzureObjectId $_.id | ForEach-Object {
        if ($AllPolicyExclusionGroups -contains $_.id) {
            $ExclusionGroups += "$($_.displayName);"
        }
    }
    $IntuneDevice = Get-IntuneDevcieInfo -Token $Token -AzureADDeviceId $_.deviceId
    $_ | Add-Member -NotePropertyName 'IntuneDeviceId' -NotePropertyValue $IntuneDevice.id
    $_ | Add-Member -NotePropertyName 'IntuneUserId' -NotePropertyValue $IntuneDevice.userId
    $_ | Add-Member -NotePropertyName 'IntuneuserPrincipalName' -NotePropertyValue $IntuneDevice.userPrincipalName
    $_ | Add-Member -NotePropertyName 'IntuneDeviceName' -NotePropertyValue $IntuneDevice.deviceName
    $_ | Add-Member -NotePropertyName 'IntunemanagedDeviceOwnerType' -NotePropertyValue $IntuneDevice.managedDeviceOwnerType
    $_ | Add-Member -NotePropertyName 'IntuneenrolledDateTime' -NotePropertyValue $IntuneDevice.enrolledDateTime
    $_ | Add-Member -NotePropertyName 'IntunelastSyncDateTime' -NotePropertyValue $IntuneDevice.lastSyncDateTime
    $_ | Add-Member -NotePropertyName 'IntuneoperatingSystem' -NotePropertyValue $IntuneDevice.operatingSystem
    $_ | Add-Member -NotePropertyName 'IntuneazureADDeviceId' -NotePropertyValue $IntuneDevice.azureADDeviceId
    $_ | Add-Member -NotePropertyName 'IntuneserialNumber' -NotePropertyValue $IntuneDevice.serialNumber
    $_ | Add-Member -NotePropertyName 'IntunedeviceRegistrationState' -NotePropertyValue $IntuneDevice.deviceRegistrationState
    $_ | Add-Member -NotePropertyName 'ExclusionGroups' -NotePropertyValue $ExclusionGroups
    
    #$ComplianceReportGrouped =  $ComplianceReport | Group-Object -Property 'deviceDisplayName'
}
#>
$AllDevicesInAssignmentGroups_o = $AllDevicesInAssignmentGroups
$AllDevicesInAssignmentGroups = $AllDevicesInAssignmentGroups_o
$AllDevicesInAssignmentGroups | ForEach-Object {
    $_ | Add-Member -NotePropertyName 'ComplianceReport_status' -NotePropertyValue '' -force
    $_ | Add-Member -NotePropertyName 'ComplianceReport_userPrincipalName' -NotePropertyValue '' -force
    $_ | Add-Member -NotePropertyName 'ComplianceReport_lastReportedDateTime' -NotePropertyValue '' -force
}
$count = 0
$ComplianceReport | ForEach-Object {
    #$_ | Add-Member -NotePropertyName 'ReportIntuneDeviceId' -NotePropertyValue $_.id.split('_')[2]
    $CurrentDevice = $_
    $count
    $AllDevicesInAssignmentGroups | ForEach-Object {
        if ($_.IntuneDeviceId -eq $CurrentDevice.id.split('_')[2]) {
            $_.ComplianceReport_status = $CurrentDevice.status
            $_.ComplianceReport_userPrincipalName = $CurrentDevice.userPrincipalName
            $_.ComplianceReport_lastReportedDateTime = $CurrentDevice.lastReportedDateTime
        }
    }
    $count++
}
$AllDevicesInAssignmentGroups | Export-Csv "$env:temp\$CompliancePolicyId-04March.csv"