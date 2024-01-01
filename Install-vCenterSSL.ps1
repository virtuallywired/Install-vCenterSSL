# This Script will Request, Generate and Install a Free 90 Day Trusted SSL for your vCenter Server.
# Posh-ACME PowerShell Module Requred - Credit to Ryan Bolger - https://github.com/rmbolger
# Version: 1.5
# Tested on vCenter 7 & vCenter 8
# Tested with PowerShell 5.1 and PowerShell 7.x
# Script Author: Nicholas Mangraviti #VirtuallyWired
# Blog URL: virtuallywired.io
# Usage: Just enter the vCenter URL or IP, Common Name, Email Contact.
# You will be prompted for vCenter Credentials.
# You will be prompted to create a TXT record on your DNS to validate Domain Ownership.
# Added Functionally to reuse Previously Generated Valid Certificate is Found Locally.
# Removed Dependancy for DST Root CA X3 and now works with ISRG Root X1 Certificate.
# Added Preferred Chain "ISRG Root X1"
# Support for first time Posh-ACME Module Usage.

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

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -Confirm:$false

# --- Edit Variables Below ---
    
$vCenterURL = "vc.vmware.io"
$CommonName = "vc.vmware.io"
$EmailContact = "user@vmware.io"
$Credential = Get-Credential
    
# --- Do Not Edit Below This Point ---

# --- This will install the Posh-ACME Module if not found.
Write-Host "Checking for Required Module Posh-ACME" -ForegroundColor Green
    
if (Get-Module -ListAvailable -Name Posh-ACME) {
    Write-Host "Posh-ACME Module Already Installed" -ForegroundColor Green
}
else {
    Write-Host "Posh-ACME Module Not Found, Attempting to Install" -ForegroundColor Yellow
    Install-Module -Name Posh-ACME -Scope CurrentUser -Force -Confirm:$false
}

# --- Importing the Posh-ACME Module.
if (Get-Module -ListAvailable -Name Posh-ACME) {
    Write-Host "Importing Posh-ACME Module" -ForegroundColor Green
    Import-Module -Name Posh-ACME -Force
}

# --- Setting ACME Server For First time Use - For Information See https://poshac.me/docs/v4/Functions/Set-PAServer/
if ((Get-PAServer).name -eq "LE_PROD") {
    Write-Host "ACME Server Already Set to $((Get-PAServer).Name)" -ForegroundColor Green
}
else {
    Write-Host "Setting ACME Server to LE_PROD" -ForegroundColor Yellow
    Set-PAServer -DirectoryUrl LE_PROD
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

# --- Check for Valid previously generated Certificate.

$CheckSLL = Get-PACertificate -MainDomain $CommonName
If ((($CheckSLL).AllSANs) -eq $CommonName -and (Get-Date) -gt ($CheckSLL.NotBefore) -and (Get-Date) -lt ($CheckSLL.NotAfter)) {
    Write-Host "A Previously Generated Certificate For '$("$CommonName")' Valid Until '$($CheckSLL.NotAfter)' Was Found" -ForegroundColor Yellow
    $Question = Read-Host "Would You Like To Reuse It? (Yes / No)"
}

# --- Generate Free Let's Encrypt 90 Day SSL - Requires you to Validatr Domain Ownership.
If ($Question -match '^(No|N)$') {
    If ($EmailContact) {
        New-PACertificate $CommonName -AcceptTOS -Contact $EmailContact -PreferredChain "ISRG Root X1" -Force
        Write-Host "Requesting SSL for '$($CommonName)'" -ForegroundColor Green
    }
    else {
        New-PACertificate $CommonName -AcceptTOS -PreferredChain "ISRG Root X1" -Force
        Write-Host "Requesting SSL for '$($CommonName)' Without Contact Email" -ForegroundColor Green
    }
}

## Downloading ISRG Root X1 - This will be appended to the Chain of trusted root certificates to complete the chain.
## Validate MD5 Hash of ISRG Root X1 root Certificate

Write-Host "Downloading ROOT CA" -ForegroundColor Green
$wc = [System.Net.WebClient]::new()
$rootCaPath = 'https://letsencrypt.org/certs/isrgrootx1.pem.txt'
$publishedHash = '22B557A27055B33606B6559F37703928D3E4AD79F110B407D04986E1843543D1'
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
$sslcert = ((Get-Content ((Get-PACertificate).FullChainFile)) + $root_CA) -replace "`t|`n|`r", ""
$privatekey = Get-Content ((Get-PACertificate).KeyFile)
$fullchain = ((Get-Content ((Get-PACertificate).ChainFile)) + $root_CA) -replace "`t|`n|`r", ""

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
