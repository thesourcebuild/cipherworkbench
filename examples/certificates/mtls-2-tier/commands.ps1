<#
.SYNOPSIS
    mTLS (2-Tier) Suite Management & Verification
.DESCRIPTION
    Verify chains, run mTLS server, test Python / cURL / OpenSSL across TLS versions.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("run", "verify", "server", "client", "client-pem", "client-p12", "test-tls", "trust-ca", "install-client", "help")]
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
        Write-Host "=== Generating 2-Tier mTLS Suite via TypeScript Engine ===" -ForegroundColor Cyan
        npx tsx .\run.ts
    }
    "verify" {
        Write-Host "=== Verifying Server and Client Chains against Root CA ===" -ForegroundColor Cyan
        & openssl verify -CAfile ".\ca.crt" ".\server.crt"
        & openssl verify -CAfile ".\ca.crt" ".\client.crt"
    }
    "server" {
        Write-Host "=== Starting 2-Tier mTLS Server on port 8443 (TLS Version: $TlsVersion) ===" -ForegroundColor Cyan
        python .\server.py --tls-version $TlsVersion
    }
    "client" {
        Write-Host "=== Running Python mTLS Client (TLS Version: $TlsVersion) ===" -ForegroundColor Cyan
        python .\client.py --tls-version $TlsVersion
    }
    "client-pem" {
        Write-Host "=== Testing mTLS Handshake with cURL (PEM certificates) ===" -ForegroundColor Cyan
        & curl -vk https://localhost:8443/ --cacert ".\ca.crt" --cert ".\client.crt" --key ".\client.key"
    }
    "client-p12" {
        Write-Host "=== Testing mTLS Handshake with cURL (PKCS#12 container) ===" -ForegroundColor Cyan
        & curl -vk https://localhost:8443/ --cacert ".\ca.crt" --cert ".\client.p12:changeit"
    }
    "test-tls" {
        Write-Host "=== Verifying mTLS Support across TLS 1.3, TLS 1.2, and TLS 1.1 ===" -ForegroundColor Cyan
        npx tsx -e "
import { testTlsProtocolMatrix } from '../tls_test_harness.ts';
testTlsProtocolMatrix({ basePort: 9557, cert: './server.crt', key: './server.key', ca: './ca.crt', verifyClient: true, clientCert: './client.crt', clientKey: './client.key' }).then(res => {
  for (const r of res) console.log('  ✓ ' + r.version.toUpperCase() + ': ' + r.protocol + ' | ' + r.cipher + ' | MutualAuth=' + (r.verified ? 'OK' : 'FAIL'));
});
"
    }
    "trust-ca" {
        Write-Host "=== Importing Root CA to Windows 'Trusted Root Certification Authorities' ===" -ForegroundColor Cyan
        Import-Certificate -FilePath ".\ca.crt" -CertStoreLocation Cert:\LocalMachine\Root
        Write-Host "[SUCCESS] Imported ca.crt! Browsers will now trust server.crt without warnings." -ForegroundColor Green
    }
    "install-client" {
        Write-Host "=== Opening PKCS#12 Client Certificate Installer ===" -ForegroundColor Cyan
        Write-Host "Password is: changeit" -ForegroundColor Yellow
        Start-Process ".\client.p12"
    }
    "help" {
        Write-Host "Usage: .\commands.ps1 [run | verify | server | client | client-pem | client-p12 | test-tls | trust-ca | install-client] [auto | 1.1 | 1.2 | 1.3 | all]"
    }
}
