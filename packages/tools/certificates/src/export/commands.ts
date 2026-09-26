export interface CommandAction {
  id: string;
  description: string;
  commands: string[];
}

export interface VerificationScriptSpec {
  title: string;
  description: string;
  defaultAction?: string;
  actions: CommandAction[];
  reproduceCommand?: string;
}

export interface CommandScripts {
  sh: string;
  ps1: string;
  bat: string;
}

/**
 * Universal Linux/macOS Shell Script generator.
 *
 * Enforces POSIX-friendly error handling, performs sanity check for OpenSSL with
 * concrete package manager guidance across all major Linux distros (Debian/Ubuntu,
 * RHEL/Fedora, Arch, Alpine) and macOS, and routes actions through a unified switch.
 */
function buildBashScript(spec: VerificationScriptSpec): string {
  const defaultAction = spec.defaultAction ?? spec.actions[0]?.id ?? "verify";
  const validActions = spec.actions.map((a) => a.id);
  if (spec.reproduceCommand) validActions.push("reproduce");

  const actionCases = spec.actions.map((action) => {
    const lines = [
      `  ${action.id})`,
      `    echo "=== Running: ${action.description} ==="`,
      ...action.commands.map((cmd) => `    ${cmd}`),
      '    echo ""',
      '    echo "[SUCCESS] Action completed successfully!"',
      "    ;;",
    ];
    return lines.join("\n");
  });

  if (spec.reproduceCommand) {
    actionCases.push(
      [
        "  reproduce)",
        '    echo "=== Equivalent OpenSSL Workflow ==="',
        `    echo "${spec.reproduceCommand.replace(/"/g, '\\"')}"`,
        "    ;;",
      ].join("\n"),
    );
  }

  const helpLines = [
    `    echo "Usage: ./commands.sh [${validActions.join(" | ")}]"`,
    '    echo ""',
    '    echo "Available actions:"',
    ...spec.actions.map((a) => `    echo "  - ${a.id}: ${a.description}"`),
    ...(spec.reproduceCommand
      ? ['    echo "  - reproduce: Print an equivalent OpenSSL CLI workflow"']
      : []),
  ];

  return [
    "#!/usr/bin/env bash",
    "set -eu",
    "",
    `# ${spec.title}`,
    `# ${spec.description}`,
    "",
    "# Sanity check: Ensure OpenSSL is present in PATH",
    "if ! command -v openssl >/dev/null 2>&1; then",
    '  echo "[ERROR] OpenSSL is not installed or not in PATH." >&2',
    '  echo "Please install OpenSSL using your system package manager:" >&2',
    '  echo "  - Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y openssl" >&2',
    '  echo "  - Fedora/RHEL:   sudo dnf install -y openssl" >&2',
    '  echo "  - Arch Linux:    sudo pacman -S openssl" >&2',
    '  echo "  - Alpine Linux:  sudo apk add openssl" >&2',
    '  echo "  - macOS:         brew install openssl" >&2',
    "  exit 1",
    "fi",
    "",
    'echo "[OK] Detected OpenSSL: $(openssl version)"',
    'echo ""',
    "",
    `ACTION="\${1:-${defaultAction}}"`,
    'SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"',
    'cd "$SCRIPT_DIR"',
    "",
    'case "$ACTION" in',
    actionCases.join("\n"),
    "  *)",
    helpLines.join("\n"),
    "    ;;",
    "esac",
    "",
  ].join("\n");
}

/**
 * Universal Windows PowerShell Script generator.
 *
 * Enforces ErrorAction Stop, performs sanity check for OpenSSL with winget / choco / scoop
 * install guidance, and routes actions through a typed parameter switch.
 */
function buildPowerShellScript(spec: VerificationScriptSpec): string {
  const defaultAction = spec.defaultAction ?? spec.actions[0]?.id ?? "verify";
  const validActions = spec.actions.map((a) => a.id);
  if (spec.reproduceCommand) validActions.push("reproduce");
  validActions.push("help");

  const validSetParam = validActions.map((a) => `"${a}"`).join(", ");

  const actionCases = spec.actions.map((action) => {
    const lines = [
      `    "${action.id}" {`,
      `        Write-Host "=== Running: ${action.description} ===" -ForegroundColor Cyan`,
      ...action.commands.map((cmd) => {
        // Prefix with & if command starts with an executable like openssl or curl
        const trimmed = cmd.trim();
        const needsAmp = /^(openssl|curl)\b/.test(trimmed);
        return `        ${needsAmp ? `& ${trimmed}` : trimmed}`;
      }),
      '        Write-Host ""',
      '        Write-Host "[SUCCESS] Action completed successfully!" -ForegroundColor Green',
      "    }",
    ];
    return lines.join("\r\n");
  });

  if (spec.reproduceCommand) {
    actionCases.push(
      [
        '    "reproduce" {',
        '        Write-Host "=== Equivalent OpenSSL Workflow ===" -ForegroundColor Cyan',
        `        Write-Host "${spec.reproduceCommand.replace(/"/g, '`"')}"`,
        "    }",
      ].join("\r\n"),
    );
  }

  const helpLines = [
    `        Write-Host "Usage: .\\commands.ps1 [${validActions.join(" | ")}]"`,
    '        Write-Host ""',
    '        Write-Host "Available actions:"',
    ...spec.actions.map((a) => `        Write-Host "  - ${a.id}: ${a.description}"`),
    ...(spec.reproduceCommand
      ? ['        Write-Host "  - reproduce: Print an equivalent OpenSSL CLI workflow"']
      : []),
  ];

  return [
    "<#",
    ".SYNOPSIS",
    `    ${spec.title}`,
    ".DESCRIPTION",
    `    ${spec.description}`,
    "#>",
    "[CmdletBinding()]",
    "param(",
    "    [Parameter(Position = 0)]",
    `    [ValidateSet(${validSetParam})]`,
    `    [string]$Action = "${defaultAction}"`,
    ")",
    "",
    '$ErrorActionPreference = "Stop"',
    "",
    "# Sanity check: Ensure OpenSSL is present in PATH",
    "$opensslCmd = Get-Command openssl -ErrorAction SilentlyContinue",
    "if (-not $opensslCmd) {",
    '    Write-Host "[ERROR] OpenSSL is not installed or not in your PATH." -ForegroundColor Red',
    '    Write-Host "Please install OpenSSL using a package manager and restart your terminal:" -ForegroundColor Yellow',
    '    Write-Host "  - Winget:     winget install ShiningLight.OpenSSL" -ForegroundColor Yellow',
    '    Write-Host "  - Chocolatey: choco install openssl" -ForegroundColor Yellow',
    '    Write-Host "  - Scoop:      scoop install openssl" -ForegroundColor Yellow',
    "    exit 1",
    "}",
    "",
    "$opensslVer = & openssl version",
    'Write-Host "[OK] Detected OpenSSL: $opensslVer" -ForegroundColor Green',
    'Write-Host ""',
    "",
    "$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path",
    "Set-Location $scriptDir",
    "",
    "switch ($Action) {",
    actionCases.join("\r\n"),
    '    "help" {',
    helpLines.join("\r\n"),
    "    }",
    "}",
    "",
  ].join("\r\n");
}

/**
 * Common Windows Batch wrapper that checks for OpenSSL in PATH,
 * resolves either PowerShell 7+ (pwsh) or Windows PowerShell (powershell),
 * forwards all CLI arguments, and pauses on exit if launched via GUI double-click.
 */
function buildBatWrapper(): string {
  return [
    "@echo off",
    "setlocal",
    "",
    "REM Sanity check: Ensure OpenSSL is present in PATH",
    "where /q openssl",
    "if %ERRORLEVEL% neq 0 (",
    "    echo [ERROR] OpenSSL was not found in your PATH.",
    "    echo Please install OpenSSL (e.g. via 'winget install ShiningLight.OpenSSL' or 'choco install openssl') and ensure it is in your PATH.",
    '    if "%~1"=="" pause',
    "    exit /b 1",
    ")",
    "",
    "REM Select PowerShell engine (pwsh or powershell)",
    'set "PSEXE=pwsh"',
    'where /q pwsh || set "PSEXE=powershell"',
    "",
    '"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0commands.ps1" %*',
    'set "EXIT_CODE=%ERRORLEVEL%"',
    'if "%~1"=="" pause',
    "exit /b %EXIT_CODE%",
    "",
  ].join("\r\n");
}

/**
 * Builds the cross-platform command script bundle (sh, ps1, bat) through a single unified engine.
 */
export function buildVerificationScripts(spec: VerificationScriptSpec): CommandScripts {
  return {
    sh: buildBashScript(spec),
    ps1: buildPowerShellScript(spec),
    bat: buildBatWrapper(),
  };
}

/**
 * Generate verification and management scripts for a single Certificate.
 */
export function generateCertCommandScripts(opts: {
  certFile: string;
  keyFile: string;
  chainFile?: string;
  opensslCommand: string;
}): CommandScripts {
  const { certFile, keyFile, chainFile, opensslCommand } = opts;

  return buildVerificationScripts({
    title: "Certificate & Private Key Verification",
    description: `Inspect and verify ${certFile} and validate private key integrity.`,
    actions: [
      {
        id: "verify",
        description: "Inspect certificate and validate private key",
        commands: [
          `openssl x509 -in "${certFile}" -text -noout`,
          `openssl pkey -in "${keyFile}" -text -noout`,
          ...(chainFile ? [`openssl verify -CAfile "${chainFile}" "${certFile}"`] : []),
        ],
      },
      {
        id: "info",
        description: "Inspect certificate fields and extensions",
        commands: [`openssl x509 -in "${certFile}" -text -noout`],
      },
      {
        id: "key",
        description: "Validate private key parameters",
        commands: [`openssl pkey -in "${keyFile}" -text -noout`],
      },
      {
        id: "server",
        description: "Launch OpenSSL mock TLS server on port 8443",
        commands: [
          `openssl s_server -cert "${certFile}" -key "${keyFile}" -port 8443 -www`,
        ],
      },
      {
        id: "client",
        description: "Test HTTPS TLS connection with cURL",
        commands: [
          `curl -vk https://localhost:8443 --cacert "${chainFile ?? certFile}"`,
        ],
      },
    ],
    reproduceCommand: opensslCommand,
  });
}

/**
 * Generate verification and testing scripts for an mTLS PKI Suite.
 */
export function generateMtlsCommandScripts(opts: {
  pkiHierarchy: "2-tier" | "3-tier";
  opensslServer: string;
  curlPem: string;
  curlP12: string;
}): CommandScripts {
  const { pkiHierarchy, opensslServer, curlPem, curlP12 } = opts;

  const verifyCommands =
    pkiHierarchy === "3-tier"
      ? [
          "openssl verify -CAfile ca.crt -untrusted intermediate.crt server.crt",
          "openssl verify -CAfile ca.crt -untrusted intermediate.crt client.crt",
          "openssl crl -in ca.crl -noout -text",
        ]
      : [
          "openssl verify -CAfile ca.crt server.crt",
          "openssl verify -CAfile ca.crt client.crt",
          "openssl crl -in ca.crl -noout -text",
        ];

  return buildVerificationScripts({
    title: "mTLS PKI Suite Verification & Testing",
    description:
      "Verify certificate chains, CRLs, and execute mock TLS client/server handshakes.",
    actions: [
      {
        id: "verify",
        description: "Verify server and client certificate chains against CA and inspect CRL",
        commands: verifyCommands,
      },
      {
        id: "server",
        description:
          "Start OpenSSL Mock TLS Server on port 8443 (requiring client certificate)",
        commands: [opensslServer],
      },
      {
        id: "client-pem",
        description: "Test client connection with cURL (PEM certificates)",
        commands: [curlPem],
      },
      {
        id: "client-p12",
        description: "Test client connection with cURL (PKCS#12 password-protected container)",
        commands: [curlP12],
      },
    ],
  });
}

/**
 * Generate verification and management scripts for a Certificate Signing Request (CSR).
 */
export function generateCsrCommandScripts(opts: {
  csrFile: string;
  keyFile: string;
  opensslCommand: string;
}): CommandScripts {
  const { csrFile, keyFile, opensslCommand } = opts;

  return buildVerificationScripts({
    title: "Certificate Signing Request (CSR) Verification",
    description: `Verify proof-of-possession self-signature and inspect ${csrFile}.`,
    actions: [
      {
        id: "verify",
        description: "Cryptographically verify CSR self-signature and inspect details",
        commands: [
          `openssl req -in "${csrFile}" -noout -verify`,
          `openssl req -in "${csrFile}" -noout -text`,
          `openssl pkey -in "${keyFile}" -text -noout`,
        ],
      },
      {
        id: "info",
        description: "Inspect CSR Subject DN, SANs, and requested attributes",
        commands: [`openssl req -in "${csrFile}" -noout -text`],
      },
      {
        id: "key",
        description: "Validate private key parameters",
        commands: [`openssl pkey -in "${keyFile}" -text -noout`],
      },
    ],
    reproduceCommand: opensslCommand,
  });
}
