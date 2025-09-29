<#
.SYNOPSIS
Imports a cert from WACS renewal into SQL Server Rerporting Services
.DESCRIPTION
Note that this script is intended to be run via the install script plugin from win-acme via the batch script wrapper. As such, we use positional parameters to avoid issues with using a dash in the cmd line. 

Proper information should be available here

https://github.com/win-acme/win-acme

.PARAMETER NewCertThumbprint
The exact thumbprint of the cert to be imported.


.EXAMPLE 

ImportSQL.ps1 <certThumbprint>

./wacs.exe --target manual --host hostname.example.com --installation script --script ".\Scripts\ImportSQL.ps1" --scriptparameters "'{CertThumbprint}'" --certificatestore My --acl-read "NT Service\MSSQLSERVER"

.NOTES

#>
param(
    [Parameter(Position=0,Mandatory=$true)]
    [string]$NewCertThumbprint,
    [Parameter(Position=1)]
    [int]$httpsPort=443,
    [Parameter(Position=2)]
    [string]$ipAddress = "0.0.0.0"
)

#inspired by https://blogs.infosupport.com/configuring-sql-server-encrypted-connections-using-powershell/
$CertInStore = Get-ChildItem -Path Cert:\LocalMachine -Recurse | Where-Object {$_.thumbprint -eq $NewCertThumbprint} | Sort-Object -Descending | Select-Object -f 1
if($CertInStore){
    try{
        #$Thumbprint = (Get-PfxData -Password $certpwd1 -FilePath  :\Temp\INBLRSHCPR12371.pfx).EndEntityCertificates.Thumbprint.ToLower()
        $wmiName=(Get-WmiObject -namespace "root\Microsoft\SqlServer\ReportServer" -class __Namespace -ComputerName $env:COMPUTERNAME).Name
        $version = (Get-WmiObject –namespace "root\Microsoft\SqlServer\ReportServer\$wmiName"  –class __Namespace).Name
        $rsConfig = Get-WmiObject –namespace "root\Microsoft\SqlServer\ReportServer\$wmiName\$version\Admin" -class  MSReportServer_ConfigurationSetting
        $rsconfig.SetServiceState($false, $false, $false)
        $certs = $rsConfig.ListSSLCertificateBindings((Get-Culture).LCID).CertificateHash
        # This assumes that the same certificate is used for both!
        $rsConfig.RemoveSSLCertificateBindings('ReportServerWebApp', $certs[0], $ipAddress, $httpsPort, (Get-Culture).LCID)
        $rsConfig.RemoveSSLCertificateBindings('ReportServerWebService', $certs[0], $ipAddress, $httpsPort, (Get-Culture).LCID)
        $rsConfig.RemoveURL("ReportServerWebApp","https://+:$httpsPort",(Get-Culture).Lcid)
        $rsConfig.RemoveURL("ReportServerWebService","https://+:$httpsPort",(Get-Culture).Lcid)
        $rsConfig.ReserveURL("ReportServerWebApp","https://+:$httpsPort",(Get-Culture).Lcid)
        $rsConfig.ReserveURL("ReportServerWebService","https://+:$httpsPort",(Get-Culture).Lcid)
        $rsConfig.CreateSSLCertificateBinding('ReportServerWebApp', $CertInStore.Thumbprint.ToLower(), $ipAddress, $httpsPort, (Get-Culture).LCID)
        $rsConfig.CreateSSLCertificateBinding('ReportServerWebService', $CertInStore.Thumbprint.ToLower(), $ipAddress, $httpsPort, (Get-Culture).Lcid) 
        
        $rsconfig.SetServiceState($true, $true, $true)
    }catch{
        "Cert thumbprint was not set successfully"
        "Error: $($Error[0])"
    }
} else {
    "Cert thumbprint not found in the cert store... which is strange because it should be there."
}
