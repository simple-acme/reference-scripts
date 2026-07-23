<#
.SYNOPSIS
    Send the result of a simple-acme certificate renewal event to NinjaRMM via a custom field.

.DESCRIPTION
    Takes the output from a simple-acme certificate renewal event and sends it to NinjaRMM via a custom field.
    Requires the simple-acme settings.json to be configured with the script path and parameters including your own Ninja RMM custom field name. 
    See Notes below for more information.

.NOTES
    Configure settings.json in your simple-acme folder as follows, ensuring you maintain the order of the parameters:
        "Script": {
        "Path": "<path to this script, ensure you escape the backslashes>",
        "Parameters": "{EventType} <custom field name in NinjaRMM> {Errors}",
        "NotifyOnSuccess": true
        }

    The ninjarmm-cli tool only works when it is executed by an Administrator, so ensure that any test runs from WACS or scheduled executions are
    performed by an Administrator or the script will error with "Unable to find ninjarmm-cli.exe"
    
    If creating a condition monitor in Ninja, the following are the EventType statuses as defined by the simple-acme Github repository:
    created, success, success-with-errors, failure, cancel, test
    https://github.com/simple-acme/simple-acme/pull/427
#>

# Take the input parameters as defined in settings.json, order is important
$strEventType = $args[0]
$strNinjaField = $args[1]
$strErrors = $args[2]

# Exit the script if the Ninja RMM field isn't defined, as the script will fail anyway
if (!$strNinjaField) {
    Write-Error "!! [ERROR] NinjaRMM field name not provided."
    Exit 1
}

Write-Host "Event Type: $strEventType"
Write-Host "Errors: $strErrors"
Write-Host "Ninja Field: $strNinjaField"

# Compose the string to send to Ninja
if ($strErrors) {
    $strNinjaOutput = "Status: $strEventType `nErrors: $strErrors"
} else {
    $strNinjaOutput = "Status: $strEventType"
}

try {
    # Write the data to the Ninja custom field - usually takes 1-2 minutes for the update to be reflected in the Ninja UI
    Write-Host "Sending output to NinjaRMM"
    if ([Environment]::OSVersion.Version -lt (New-Object 'Version' 10,0)) {
        # If we're running an older OS, then it's possible the Ninja PowerShell modules aren't registered, so fallback to using the CLI tool
        Start-Process $env:NINJARMMCLI -ArgumentList "set $strNinjaField $strNinjaOutput" -Wait -NoNewWindow
    } else {
        # Otherwise, we'll use the proper PowerShell cmdlets for forward compatibility purposes
        Set-NinjaProperty -Name $strNinjaField -Type Multiline -Value $strNinjaOutput
    }
} catch {
    Write-Error "!! [ERROR] We failed to write the data to Ninja. Are you running as an Administrator, does the custom field exist in Ninja and is the name defined in settings.json correct?"
    Write-Error $_
}

# Assuming it all went through without error, we're done!
Write-Host "Output sent to NinjaRMM custom field '$strNinjaField':"
Write-Host $strNinjaOutput
Write-Host "Script completed successfully."
