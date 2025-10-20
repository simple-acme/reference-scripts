param (
    [string]$command,     # "create" oder "delete"
    [string]$domain,      # Domain (z. B. example.com)
    [string]$recordName,  # The complete record name
    [string]$value        # The value of the DNS record (challenge token)
)

# API-URL
$apiUrl = "https://ipv64.net/api.php"

# API-Token (Add your Account API Token  https://ipv64.net/api_settings )
$apiToken = ""

$headers = @{
    "Authorization" = "Bearer $apiToken"
}

$praefix = $recordName -split "\." | Select-Object -First 1

Write-Output "Used Präfix: $praefix"
Write-Output "Domain: $domain"

if ($command -eq "create") {         
    Write-Output "Create DNS record for $praefix.$domain with value '$value'"

    $formData = @{
        "add_record" = $domain
        "praefix" = $praefix
        "type" = "TXT"
        "content" = $value
    }

    try {
        # API-Request senden
        $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers -Body $formData
        Write-Output "DNS record successfully created!"
        
        # Warte auf DNS-Propagation
        Start-Sleep -Seconds 30
        exit 0
    } catch {
        Write-Error "Error creating DNS record: $_"
        exit 1
    }

} elseif ($command -eq "delete") {
    Write-Output "Delete DNS record for $praefix.$domain"

    # Form-Daten für das Löschen des TXT-Records
    $formData = @{
        "del_record" = $domain
        "praefix" = $praefix
        "type" = "TXT"
        "content" = $value
    }

    try {
        # API-Request senden
        $response = Invoke-RestMethod -Uri $apiUrl -Method Delete -Headers $headers -Body $formData
        Write-Output "DNS record successfully deleted!"
        exit 0
    } catch {
        Write-Error "Error deleting the DNS record: $_"
        exit 1
    }

} else {
    Write-Error "Invalid command '$command'. Allowed: create or delete"
    exit 1
}
