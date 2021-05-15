# This Script will Request, Generate and Install a Free 90 Day Trusted SSL for your vCenter Server.
# Posh-ACME PowerShell Module Requred - Credit to Ryan Bolger - https://github.com/rmbolger
# Version: 1.0
# Tested on vCenter 7
# Test with PowerShell 5.1 and PowerShell 7
# Script Author: Nicholas Mangraviti #VirtuallyWired
# Blog URL: virtuallywired.io
# Usage: Just enter the vCenter URL or IP, Common Name, Email Contact.
# You will be prompted for vCenter Credentials.
# You will be prompted to create a TXT record on your DNS to validate Domain Ownership.

# --- Required Functions ---
function Show-Failure {
    $global:helpme = $body
    $global:helpmoref = $moref
    $global:result = $_.Exception.Response.GetResponseStream()
    $global:reader = New-Object System.IO.StreamReader($global:result)
    $global:responseBody = $global:reader.ReadToEnd();
    Write-Host -BackgroundColor:Black -ForegroundColor:Red "Status: A system exception was caught."
    Write-Host -BackgroundColor:Black -ForegroundColor:Red $global:responsebody
    Write-Host -BackgroundColor:Black -ForegroundColor:Red "The request body has been saved to `$global:helpme"
    break
}

# --- Edit Variables Below ---
    
$vCenterURL = "vc.domain.com"
$CommonName = "vc.domain.com"
$EmailContact = "user@domain.com"
$Credential = Get-Credential
    
# --- Do Not Edit Below This Point ---

# --- This will install the Posh-ACME Module if not found.
Write-Host "Checking for Required Module Posh-ACME" -ForegroundColor Green
    
if (Get-Module -ListAvailable -Name Posh-ACME) {
    Write-Host "Posh-ACME Module Already Installed" -ForegroundColor Green
} 
else {
    Write-Host "Posh-ACME Module Not Found, Attempting to Install" -ForegroundColor Yellow
    Install-Module -Name Posh-ACME -Scope CurrentUser
} 
    
# --- This section ignores invalid SSL for the WebRequest for Powershell 5.1 or Lower.
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
    $certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
}
[ServerCertificateValidationCallback]::Ignore() 

# --- Get Some Credentials and Determine Authorisation Methods
$auth = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Credential.UserName + ':' + $Credential.GetNetworkCredential().Password))
$head = @{
    'Authorization' = "Basic $auth"
}
 
# --- Setting up Inital Params
$Params = @{
 
    Method  = "POST"
    Headers = $head
    Uri     = "https://$vCenterURL/rest/com/vmware/cis/session"
}
 
# --- Support for PowerShell Core certificate checking
if ($IsCoreCLR) {
    $Params.Add("SkipCertificateCheck", $true)
}
 
# --- Invoke WebRequest to get Session Token
 
try {
    $RestApi = Invoke-WebRequest @Params
    $token = (ConvertFrom-Json $RestApi.Content).value
    $session = @{'vmware-api-session-id' = $token }
    Write-Host "Session Token Created Successfully" -ForegroundColor Green
}
catch {
    Write-Error "Unable to get Session Token, Terminating Script"
    Show-Failure
} 
# --- Generate Free Let's Encrypt 90 Day SSL - Requires you to Validatr Domain Ownership.
Write-Host "Requesting SSL for '$($CommonName)'" -ForegroundColor Green

If ($EmailContact) {
    New-PACertificate $CommonName -AcceptTOS -Contact $EmailContact -Force
}
else {
    New-PACertificate $CommonName -AcceptTOS -Force 
}

## rootCA DST Root CA X3 - This will be appended to the Chain of trusted root certificates.
## https://www.identrust.com/dst-root-ca-x3
## Note: This Root CA Expires Sep 2021.

## Downloading DST Root CA X3 from my Github Repo and Validate MD5 Hash.
Write-Host "Downloading ROOT CA" -ForegroundColor Green
$wc = [System.Net.WebClient]::new()
$rootCaPath = 'https://raw.githubusercontent.com/virtuallywired/Install-vCenterSSL/main/DST_Root_CA_X3.key'
$publishedHash = '139A5E4A4E0FA505378C72C5F700934CE8333F4E6B1B508886C4B0EB14F4BE99'
$FileHash = Get-FileHash -InputStream ($wc.OpenRead($rootCaPath))

If ($FileHash.Hash -eq $publishedHash) {
    $root_CA = (New-Object System.Net.WebClient).DownloadString($rootCaPath)
    Write-Host "Successfully Validated ROOT CA" -ForegroundColor Green
}
else {
    Throw "Could not validate ROOT CA - Please Raise an Issue at https://github.com/virtuallywired/Install-vCenterSSL"
}
# --- Get the Content of the Certificate Files.
Write-Host "Loading Certificate Files" -ForegroundColor Green
$sslcert = Get-Content ((Get-PACertificate).CertFile)
$privatekey = Get-Content ((Get-PACertificate).KeyFile)
$fullchain = ((Get-Content ((Get-PACertificate).ChainFile)) + $root_CA) -replace "`t|`n|`r",""

# --- Reformats Certificate to string in PEM format
Write-Host "Reformating Certificates to String" -ForegroundColor Green

$cert = ((([string]$sslcert).Replace(" ", "")`
    ).Replace("-----BEGINCERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n")`
).Replace("-----ENDCERTIFICATE-----", "\n-----END CERTIFICATE-----")

$key = ((([string]$privatekey).Replace(" ", "")`
    ).Replace("-----BEGINPRIVATEKEY-----", "-----BEGIN PRIVATE KEY-----\n")`
).Replace("-----ENDPRIVATEKEY-----", "\n-----END PRIVATE KEY-----")

$chain = ((([string]$fullchain).Replace(" ", "")`
    ).Replace("-----BEGINCERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n")`
).Replace("-----ENDCERTIFICATE-----", "\n-----END CERTIFICATE-----"`
).Replace("----------", "-----\n-----") 

# --- Creates Spec in JSON for WebRequest Body
Write-Host "Creating Payload" -ForegroundColor Green

$json = @"
{
    "cert": "$cert",
    "key": "$key",
    "root_cert": "$chain"
    }
"@
# --- Updating Params
$Params = @{
    Method      = "PUT"
    Headers     = $session
    Uri         = "https://$vCenterURL/api/vcenter/certificate-management/vcenter/tls"
    ContentType = "application/json"
    Body        = $json
}

# --- Support for PowerShell Core certificate checking
if ($IsCoreCLR) {
    $Params.Add("SkipCertificateCheck", $true)
}
## Invoke WebRequest to Replace Certificates
Write-Host "Preparing to Replace Certificate." -ForegroundColor Green

try {
    $Response = Invoke-WebRequest @Params
    Write-Host "Response Code: $($Response.StatusCode)" -ForegroundColor Blue
}
catch {
    Write-Error "Failed to Replace Certificate, Terminating Script"
    Show-Failure
}

If ($Response.StatusCode -eq "204") {
    Write-Host "Successfully Replaced Certificate" -ForegroundColor Green
    Write-Host "After this operation completes, the services using the certificate will be restarted for the new certificate to take effect." -ForegroundColor Green
}
else {

    Write-Error "Failed to Replace Certificate, Please verify Correct Configuration and Retry"
}
