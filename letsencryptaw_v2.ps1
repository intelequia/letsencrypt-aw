#######################################################################################
# Script that renews a Let's Encrypt certificate for an Azure Application Gateway
# Pre-requirements:
#      - Have a storage account in which the folder path has been created: 
#        '/.well-known/acme-challenge/', to put here the Let's Encrypt DNS check files

#      - Add "Path-based" rule in the Application Gateway with this configuration: 
#           - Path: '/.well-known/acme-challenge/*'
#           - Check the configure redirection option
#           - Choose redirection type: permanent
#           - Choose redirection target: External site
#           - Target URL: <Blob public path of the previously created storage account>
#                - Example: 'https://test.blob.core.windows.net/public'
#      - For execution on Azure Automation: Import 'AzureRM.profile', 'AzureRM.Network' 
#        and 'ACMESharp' modules in Azure
#
#      UPDATE 2019-11-27
#      - Due to deprecation of ACMEv1, a new script is required to use ACMEv2.
#        The module to use is called ACME-PS.
#
#######################################################################################

Param(
    [string]$domain,
    [string]$EmailAddress,
    [string]$STResourceGroupName,
    [string]$storageName,
    [string]$AGResourceGroupName,
    [string]$AGName,
    [string]$AGOldCertName
)

## Azure Login ##
# If Runbook for Azure Automation
$connection = Get-AutomationConnection -Name AzureRunAsConnection
Login-AzureRmAccount -ServicePrincipal -Tenant $connection.TenantID -ApplicationID $connection.ApplicationID -CertificateThumbprint $connection.CertificateThumbprint

# Create a state object and save it to the harddrive
$state = New-ACMEState -Path $env:TEMP
$serviceName = 'LetsEncrypt'

# Fetch the service directory and save it in the state
Get-ACMEServiceDirectory $state -ServiceName $serviceName -PassThru;

# Get the first anti-replay nonce
New-ACMENonce $state;

# Create an account key. The state will make sure it's stored.
New-ACMEAccountKey $state -PassThru;

# Register the account key with the acme service. The account key will automatically be read from the state
New-ACMEAccount $state -EmailAddresses $EmailAddress -AcceptTOS;

# Load an state object to have service directory and account keys available
$state = Get-ACMEState -Path $env:TEMP;

# It might be neccessary to acquire a new nonce, so we'll just do it for the sake of the example.
New-ACMENonce $state -PassThru;

# Create the identifier for the DNS name
$identifier = New-ACMEIdentifier $domain;

# Create the order object at the ACME service.
$order = New-ACMEOrder $state -Identifiers $identifier;

# Fetch the authorizations for that order
$authZ = Get-ACMEAuthorization -State $state -Order $order;

# Select a challenge to fullfill
$challenge = Get-ACMEChallenge $state $authZ "http-01";

# Inspect the challenge data
$challenge.Data;

# Create the file requested by the challenge
$fileName = $env:TMP + '\' + $challenge.Token;
Set-Content -Path $fileName -Value $challenge.Data.Content -NoNewline;

$blobName = ".well-known/acme-challenge/" + $challenge.Token
$storageAccount = Get-AzureRmStorageAccount -ResourceGroupName $STResourceGroupName -Name $storageName
$ctx = $storageAccount.Context
Set-AzureStorageBlobContent -File $fileName -Container "public" -Context $ctx -Blob $blobName

# Signal the ACME server that the challenge is ready
$challenge | Complete-ACMEChallenge $state;

# Wait a little bit and update the order, until we see the states
while($order.Status -notin ("ready","invalid")) {
    Start-Sleep -Seconds 10;
    $order | Update-ACMEOrder $state -PassThru;
}

# We should have a valid order now and should be able to complete it
# Therefore we need a certificate key
$certKey = New-ACMECertificateKey -Path "$env:TEMP\$domain.key.xml";

# Complete the order - this will issue a certificate singing request
Complete-ACMEOrder $state -Order $order -CertificateKey $certKey;

# Now we wait until the ACME service provides the certificate url
while(-not $order.CertificateUrl) {
    Start-Sleep -Seconds 15
    $order | Update-Order $state -PassThru
}

# As soon as the url shows up we can create the PFX
$password = ConvertTo-SecureString -String "Passw@rd123***" -Force -AsPlainText
Export-ACMECertificate $state -Order $order -CertificateKey $certKey -Path "$env:TEMP\$domain.pfx" -Password $password;

# Delete blob to check DNS
Remove-AzureStorageBlob -Container "public" -Context $ctx -Blob $blobName

### RENEW APPLICATION GATEWAY CERTIFICATE ###
$appgw = Get-AzureRmApplicationGateway -ResourceGroupName $AGResourceGroupName -Name $AGName
Set-AzureRmApplicationGatewaySSLCertificate -Name $AGOldCertName -ApplicationGateway $appgw -CertificateFile "$env:TEMP\$domain.pfx" -Password $password
Set-AzureRmApplicationGateway -ApplicationGateway $appgw
