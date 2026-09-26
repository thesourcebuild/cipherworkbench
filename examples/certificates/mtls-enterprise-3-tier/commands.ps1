<#
.SYNOPSIS
    mTLS Enterprise (3-Tier) Suite Management & Verification
.DESCRIPTION
    Verify 3-tier chains, test enterprise mTLS server/client, and validate TLS protocol versions.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("run", "verify", "server", "client", "client-pem", "client-p12", "test-tls", "trust-root", "install-client", "help")]
    [string]$Action = "verify",

    [Parameter(Position = 1)]
    [ValidateSet("auto", "1.1", "1.2", "1.3", "all")]
    [string]$TlsVersion = "auto"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

switch ($Action) {
    "run" {
        Write-Host "=== Generating 3-Tier Enterprise PKI Suite via TypeScript Engine ===" -ForegroundColor Cyan
        npx tsx .\run.ts
    }
    "verify" {
        Write-Host "=== Verifying 3-Tier Chains against Root CA (-untrusted intermediate.crt) ===" -ForegroundColor Cyan
        & openssl verify -CAfile ".\ca.crt" -untrusted ".\intermediate.crt" ".\server.crt"
        & openssl verify -CAfile ".\ca.crt" -untrusted ".\intermediate.crt" ".\client.crt"
        & openssl crl -in ".\ca.crl" -noout -text
    }
    "server" {
        Write-Host "=== Starting 3-Tier Enterprise mTLS Server on port 8443 (TLS Version: $TlsVersion) ===" -ForegroundColor Cyan
        python .\server.py --tls-version $TlsVersion
    }
    "client" {
        Write-Host "=== Running Python 3-Tier Enterprise mTLS Client (TLS Version: $TlsVersion) ===" -ForegroundColor Cyan
        python .\client.py --tls-version $TlsVersion
    }
    "client-pem" {
        Write-Host "=== Testing 3-Tier mTLS Handshake with cURL (PEM chain) ===" -ForegroundColor Cyan
        & curl -vk https://localhost:8443/ --cacert ".\ca.crt" --cert ".\client-chain.pem" --key ".\client.key"
    }
    "client-p12" {
        Write-Host "=== Testing 3-Tier mTLS Handshake with cURL (PKCS#12 container) ===" -ForegroundColor Cyan
        & curl -vk https://localhost:8443/ --cacert ".\ca.crt" --cert ".\client.p12:EnterprisePass123!"
    }
    "test-tls" {
        Write-Host "=== Verifying 3-Tier Enterprise mTLS across TLS 1.3, TLS 1.2, and TLS 1.1 ===" -ForegroundColor Cyan
        npx tsx -e "
import { testTlsProtocolMatrix } from '../tls_test_harness.ts';
testTlsProtocolMatrix({ basePort: 9564, cert: './server-chain.pem', key: './server.key', ca: './ca-chain.pem', verifyClient: true, clientCert: './client.crt', clientKey: './client.key', clientChain: './intermediate.crt' }).then(res => {
  for (const r of res) console.log('  ✓ ' + r.version.toUpperCase() + ': ' + r.protocol + ' | ' + r.cipher + ' | MutualAuth=' + (r.verified ? 'OK' : 'FAIL'));
});
"
    }
    "trust-root" {
        Write-Host "=== Importing Root CA to Windows 'Trusted Root Certification Authorities' ===" -ForegroundColor Cyan
        Import-Certificate -FilePath ".\ca.crt" -CertStoreLocation Cert:\LocalMachine\Root
        Write-Host "[SUCCESS] Imported ca.crt! Browsers receiving server-chain.pem will now trust it automatically." -ForegroundColor Green
    }
    "install-client" {
        Write-Host "=== Opening PKCS#12 Client Certificate Installer ===" -ForegroundColor Cyan
        Write-Host "Password is: EnterprisePass123!" -ForegroundColor Yellow
        Start-Process ".\client.p12"
    }
    "help" {
        Write-Host "Usage: .\commands.ps1 [run | verify | server | client | client-pem | client-p12 | test-tls | trust-root | install-client] [auto | 1.1 | 1.2 | 1.3 | all]"
    }
}
