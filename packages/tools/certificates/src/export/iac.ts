export interface IacTemplateParams {
  certFilename?: string;
  keyFilename?: string;
  caFilename?: string;
  chainFilename?: string;
  serverName?: string;
  isMtls?: boolean;
  clientCertFilename?: string;
  clientKeyFilename?: string;
  p12Filename?: string;
  p12Password?: string;
  alias?: string;
  certPem?: string;
  keyPem?: string;
  caPem?: string;
  chainPem?: string;
  namespace?: string;
  secretName?: string;
}

/**
 * Universal ASCII/Latin1 Base64 encoder safe across Browser and Node environments.
 */
function toBase64Ascii(str: string): string {
  if (typeof btoa === "function") {
    try {
      return btoa(str);
    } catch {
      // Fallback if non-latin1
    }
  }
  if (typeof Buffer !== "undefined") {
    return Buffer.from(str, "utf8").toString("base64");
  }
  return "";
}

/**
 * Indents each line of a multiline string by a given number of spaces.
 */
function indentLines(str: string, spaces: number): string {
  const pad = " ".repeat(spaces);
  return str
    .split("\n")
    .map((line) => (line.length > 0 ? `${pad}${line}` : line))
    .join("\n");
}

/**
 * Generates an automated Terraform configuration (main.tf) to deploy certificates
 * to the filesystem or infrastructure with secure file permissions (0644 / 0600).
 */
export function generateTerraformConfig(params: IacTemplateParams = {}): string {
  const certFile = params.certFilename ?? "server.crt";
  const keyFile = params.keyFilename ?? "server.key";
  const caFile = params.caFilename ?? "ca.crt";

  return `# ==============================================================================
# CipherWorkbench Generated Terraform Configuration (main.tf)
# Automated Infrastructure-as-Code TLS Provisioning
# ==============================================================================

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    local = {
      source  = "hashicorp/local"
      version = "~> 2.4"
    }
  }
}

variable "tls_cert_dest_dir" {
  type        = string
  default     = "/etc/ssl/certs"
  description = "Target directory for public X.509 TLS certificates"
}

variable "tls_key_dest_dir" {
  type        = string
  default     = "/etc/ssl/private"
  description = "Target directory for private TLS keys (strict permissions 0600)"
}

# Deploy Server Certificate (Public, 0644)
resource "local_file" "server_certificate" {
  filename        = "\${var.tls_cert_dest_dir}/${certFile}"
  content         = file("\${path.module}/${certFile}")
  file_permission = "0644"
}

# Deploy Server Private Key (Sensitive, 0600)
resource "local_sensitive_file" "server_private_key" {
  filename        = "\${var.tls_key_dest_dir}/${keyFile}"
  content         = file("\${path.module}/${keyFile}")
  file_permission = "0600"
}

# Deploy Certificate Authority Anchor (Public, 0644)
resource "local_file" "ca_certificate" {
  filename        = "\${var.tls_cert_dest_dir}/${caFile}"
  content         = file("\${path.module}/${caFile}")
  file_permission = "0644"
}

output "installed_cert_path" {
  value       = local_file.server_certificate.filename
  description = "Deployed TLS certificate path"
}

output "installed_key_path" {
  value       = local_sensitive_file.server_private_key.filename
  description = "Deployed TLS private key path"
  sensitive   = true
}
`;
}

/**
 * Generates an automated Ansible Playbook (deploy-playbook.yaml) to install
 * certificates and private keys with POSIX 0644 / 0600 permissions.
 */
export function generateAnsiblePlaybook(params: IacTemplateParams = {}): string {
  const certFile = params.certFilename ?? "server.crt";
  const keyFile = params.keyFilename ?? "server.key";
  const caFile = params.caFilename ?? "ca.crt";

  return `---
# ==============================================================================
# CipherWorkbench Automated TLS Deployment Playbook (deploy-playbook.yaml)
# Enforces POSIX 0644 / 0600 permissions and directory hardening
# ==============================================================================

- name: Deploy TLS Certificates & Private Keys
  hosts: all
  become: true
  gather_facts: false
  vars:
    ssl_cert_dir: /etc/ssl/certs
    ssl_private_dir: /etc/ssl/private
    cert_file_name: "${certFile}"
    key_file_name: "${keyFile}"
    ca_file_name: "${caFile}"

  tasks:
    - name: Ensure SSL directories exist with hardened permissions
      ansible.builtin.file:
        path: "{{ item.path }}"
        state: directory
        owner: root
        group: root
        mode: "{{ item.mode }}"
      loop:
        - { path: "{{ ssl_cert_dir }}", mode: "0755" }
        - { path: "{{ ssl_private_dir }}", mode: "0700" }

    - name: Deploy Leaf Server Certificate (0644)
      ansible.builtin.copy:
        src: "{{ cert_file_name }}"
        dest: "{{ ssl_cert_dir }}/{{ cert_file_name }}"
        owner: root
        group: root
        mode: "0644"
        backup: true

    - name: Deploy Private Key (Strict Permissions 0600)
      ansible.builtin.copy:
        src: "{{ key_file_name }}"
        dest: "{{ ssl_private_dir }}/{{ key_file_name }}"
        owner: root
        group: root
        mode: "0600"
        backup: true

    - name: Deploy CA Certificate (if available)
      ansible.builtin.copy:
        src: "{{ ca_file_name }}"
        dest: "{{ ssl_cert_dir }}/{{ ca_file_name }}"
        owner: root
        group: root
        mode: "0644"
      ignore_errors: true

    - name: Verify Certificate Expiry and Subject DN
      ansible.builtin.command: >
        openssl x509 -in {{ ssl_cert_dir }}/{{ cert_file_name }} -noout -subject -dates
      register: cert_check
      changed_when: false

    - name: Display Verification Result
      ansible.builtin.debug:
        msg: "{{ cert_check.stdout_lines }}"
`;
}

/**
 * Generates a ready-to-apply Kubernetes TLS Secret and Ingress manifest (k8s-tls-secret.yaml).
 * Includes base64-encoded tls.crt, tls.key, and ca.crt if PEM strings are supplied.
 */
export function generateKubernetesTlsSecret(params: IacTemplateParams = {}): string {
  const secretName = params.secretName ?? "tls-server-secret";
  const namespace = params.namespace ?? "default";
  const serverName = params.serverName ?? "localhost";

  const certB64 = params.certPem ? toBase64Ascii(params.certPem.trim()) : "<BASE64_CERTIFICATE>";
  const keyB64 = params.keyPem ? toBase64Ascii(params.keyPem.trim()) : "<BASE64_PRIVATE_KEY>";
  const caB64 = params.caPem ? toBase64Ascii(params.caPem.trim()) : undefined;

  const parts = [
    `# ==============================================================================`,
    `# CipherWorkbench Kubernetes TLS Secret & Ingress Manifest (k8s-tls-secret.yaml)`,
    `# Apply directly with: kubectl apply -f k8s-tls-secret.yaml`,
    `# ==============================================================================`,
    `apiVersion: v1`,
    `kind: Secret`,
    `metadata:`,
    `  name: ${secretName}`,
    `  namespace: ${namespace}`,
    `type: kubernetes.io/tls`,
    `data:`,
    `  tls.crt: ${certB64}`,
    `  tls.key: ${keyB64}`,
  ];

  if (caB64) {
    parts.push(`  ca.crt: ${caB64}`);
  }

  if (params.caPem) {
    parts.push(
      `---`,
      `apiVersion: v1`,
      `kind: ConfigMap`,
      `metadata:`,
      `  name: ${secretName}-ca-bundle`,
      `  namespace: ${namespace}`,
      `data:`,
      `  ca.crt: |`,
      indentLines(params.caPem.trim(), 4),
    );
  }

  parts.push(
    `---`,
    `apiVersion: networking.k8s.io/v1`,
    `kind: Ingress`,
    `metadata:`,
    `  name: ${secretName}-ingress`,
    `  namespace: ${namespace}`,
    `  annotations:`,
    `    nginx.ingress.kubernetes.io/ssl-redirect: "true"`,
    `spec:`,
    `  tls:`,
    `    - hosts:`,
    `        - ${serverName}`,
    `      secretName: ${secretName}`,
    `  rules:`,
    `    - host: ${serverName}`,
    `      http:`,
    `        paths:`,
    `          - path: /`,
    `            pathType: Prefix`,
    `            backend:`,
    `              service:`,
    `                name: web-service`,
    `                port:`,
    `                  number: 80`,
  );

  return parts.join("\n") + "\n";
}

/**
 * Generates a hardened NGINX TLS virtual host configuration (nginx.conf) with TLS 1.3 / 1.2,
 * Mozilla modern/intermediate ciphers, HSTS, session caching, and optional mTLS client verification.
 */
export function generateNginxTlsConfig(params: IacTemplateParams = {}): string {
  const certFile = params.chainFilename ?? params.certFilename ?? "server.crt";
  const keyFile = params.keyFilename ?? "server.key";
  const caFile = params.caFilename ?? "ca.crt";
  const serverName = params.serverName ?? "localhost";
  const isMtls = Boolean(params.isMtls);

  return `# ==============================================================================
# CipherWorkbench Hardened NGINX TLS Configuration (nginx.conf)
# Supports TLSv1.3 & TLSv1.2 with Mozilla Intermediate Cipher Profile
# ==============================================================================

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${serverName};

    # Certificate & Private Key
    ssl_certificate /etc/nginx/ssl/${certFile};
    ssl_certificate_key /etc/nginx/ssl/${keyFile};
${
  isMtls
    ? `
    # Mutual TLS (mTLS) Client Verification
    ssl_client_certificate /etc/nginx/ssl/${caFile};
    ssl_verify_client on;
    ssl_verify_depth 2;
`
    : ""
}
    # Protocols and High-Security Ciphers
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Performance & Session Optimization
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;

    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
${
  isMtls
    ? `        proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert;
        proxy_set_header X-SSL-Client-DN $ssl_client_s_dn;
`
    : ""
}    }
}
`;
}

/**
 * Generates a turnkey Caddyfile configuration with custom TLS certificate, key, and optional mTLS client auth.
 */
export function generateCaddyTlsConfig(params: IacTemplateParams = {}): string {
  const certFile = params.chainFilename ?? params.certFilename ?? "server.crt";
  const keyFile = params.keyFilename ?? "server.key";
  const caFile = params.caFilename ?? "ca.crt";
  const serverName = params.serverName ?? "localhost";
  const isMtls = Boolean(params.isMtls);

  return `# ==============================================================================
# CipherWorkbench Caddyfile TLS Configuration
# ==============================================================================

${serverName}:443 {
    tls /etc/caddy/ssl/${certFile} /etc/caddy/ssl/${keyFile} {
${
  isMtls
    ? `        client_auth {
            mode require_and_verify
            trusted_ca_cert_file /etc/caddy/ssl/${caFile}
        }
`
    : ""
}    }

    reverse_proxy 127.0.0.1:8080 {
${
  isMtls
    ? `        header_up X-Client-Cert-Subject {http.request.tls.client.subject}
`
    : ""
}    }
}
`;
}

/**
 * Generates a production-ready docker-compose.yaml that launches an NGINX TLS reverse proxy
 * mounting the generated certificates with secure POSIX permissions.
 */
export function generateDockerComposeConfig(params: IacTemplateParams = {}): string {
  const certFile = params.chainFilename ?? params.certFilename ?? "server.crt";
  const keyFile = params.keyFilename ?? "server.key";
  const caFile = params.caFilename ?? "ca.crt";

  return `# ==============================================================================
# CipherWorkbench Production Docker Compose TLS Stack (docker-compose.yaml)
# Run with: docker compose up -d
# ==============================================================================

version: "3.8"

services:
  web:
    image: nginx:alpine
    container_name: tls-web-server
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ./${certFile}:/etc/nginx/ssl/${certFile}:ro
      - ./${keyFile}:/etc/nginx/ssl/${keyFile}:ro
      - ./${caFile}:/etc/nginx/ssl/${caFile}:ro
    environment:
      - NGINX_PORT=443
`;
}

/**
 * Generates an Apache HTTP Server SSL VirtualHost configuration (httpd-ssl.conf).
 */
export function generateApacheTlsConfig(params: IacTemplateParams = {}): string {
  const certFile = params.chainFilename ?? params.certFilename ?? "server.crt";
  const keyFile = params.keyFilename ?? "server.key";
  const caFile = params.caFilename ?? "ca.crt";
  const serverName = params.serverName ?? "localhost";
  const isMtls = Boolean(params.isMtls);

  return `# ==============================================================================
# CipherWorkbench Apache HTTP Server SSL VirtualHost (httpd-ssl.conf)
# ==============================================================================

<VirtualHost *:443>
    ServerName ${serverName}
    DocumentRoot "/var/www/html"

    SSLEngine on
    SSLCertificateFile "/etc/ssl/certs/${certFile}"
    SSLCertificateKeyFile "/etc/ssl/private/${keyFile}"
    SSLCACertificateFile "/etc/ssl/certs/${caFile}"
${
  isMtls
    ? `    SSLVerifyClient require
    SSLVerifyDepth 2
`
    : ""
}
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite HIGH:!aNULL:!MD5:!3DES
    SSLHonorCipherOrder off

    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
</VirtualHost>
`;
}

/**
 * Generates an Envoy v3 TLS downstream transport socket configuration (envoy.yaml).
 */
export function generateEnvoyTlsConfig(params: IacTemplateParams = {}): string {
  const certFile = params.chainFilename ?? params.certFilename ?? "server.crt";
  const keyFile = params.keyFilename ?? "server.key";
  const caFile = params.caFilename ?? "ca.crt";
  const isMtls = Boolean(params.isMtls);

  return `# ==============================================================================
# CipherWorkbench Envoy v3 Proxy TLS Configuration (envoy.yaml)
# ==============================================================================

static_resources:
  listeners:
  - name: https_listener
    address:
      socket_address: { address: 0.0.0.0, port_value: 443 }
    filter_chains:
    - transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            tls_certificates:
            - certificate_chain: { filename: "/etc/ssl/certs/${certFile}" }
              private_key: { filename: "/etc/ssl/private/${keyFile}" }
${
  isMtls
    ? `            validation_context:
              trusted_ca: { filename: "/etc/ssl/certs/${caFile}" }
              require_client_certificate: true
`
    : ""
}    filters:
    - name: envoy.filters.network.http_connection_manager
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
        stat_prefix: ingress_https
        route_config:
          name: local_route
          virtual_hosts:
          - name: default
            domains: ["*"]
            routes:
            - match: { prefix: "/" }
              route: { cluster: local_service }
        http_filters:
        - name: envoy.filters.http.router
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
`;
}

/**
 * Generates an HAProxy frontend TLS configuration (haproxy.cfg).
 */
export function generateHaproxyTlsConfig(params: IacTemplateParams = {}): string {
  const certFile = params.chainFilename ?? params.certFilename ?? "server.crt";
  const caFile = params.caFilename ?? "ca.crt";
  const isMtls = Boolean(params.isMtls);

  return `# ==============================================================================
# CipherWorkbench HAProxy Frontend TLS Configuration (haproxy.cfg)
# ==============================================================================

frontend https_in
    bind :443 ssl crt /etc/haproxy/certs/${certFile} ${isMtls ? `ca-file /etc/haproxy/certs/${caFile} verify required` : ""}
    mode http
    option httplog
    http-response set-header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    default_backend app_servers

backend app_servers
    mode http
    server app1 127.0.0.1:8080 check
`;
}

/**
 * Generates turnkey CLI import scripts for AWS ACM, HashiCorp Vault, GCP Certificate Manager,
 * Azure Key Vault, and Java Keytool (cloud-import.sh).
 */
export function generateCloudImportCommands(params: IacTemplateParams = {}): string {
  const certFile = params.chainFilename ?? params.certFilename ?? "server.crt";
  const keyFile = params.keyFilename ?? "server.key";
  const caFile = params.caFilename ?? "ca.crt";
  const serverName = (params.alias ?? params.serverName ?? "server").replace(/[^a-zA-Z0-9-]/g, "-");
  const p12File = params.p12Filename ?? "bundle.pfx";
  const p12Pass = params.p12Password ?? "changeit";

  return `#!/usr/bin/env bash
# ==============================================================================
# CipherWorkbench Cloud & Enterprise Keystore Import Workflow (cloud-import.sh)
# ==============================================================================
set -eu

echo "=== 1. AWS Certificate Manager (ACM) Import ==="
echo "aws acm import-certificate \\"
echo "  --certificate fileb://${certFile} \\"
echo "  --private-key fileb://${keyFile} \\"
echo "  --certificate-chain fileb://${caFile}"
echo ""

echo "=== 2. HashiCorp Vault PKI Import ==="
echo "# Write private key and certificate bundle into Vault KV / PKI engine:"
echo "vault write secret/data/tls/${serverName} \\"
echo "  certificate=@${certFile} \\"
echo "  private_key=@${keyFile} \\"
echo "  ca_chain=@${caFile}"
echo ""

echo "=== 3. Google Cloud Certificate Manager Import ==="
echo "gcloud certificate-manager certificates create ${serverName} \\"
echo "  --certificate-file=${certFile} \\"
echo "  --private-key-file=${keyFile}"
echo ""

echo "=== 4. Azure Key Vault Import ==="
echo "# Combine cert and key into PKCS#12 bundle first, then import:"
${params.p12Filename ? `echo "# Using existing PKCS#12 container: ${p12File}"` : `echo "openssl pkcs12 -export -out ${p12File} -inkey ${keyFile} -in ${certFile} -certfile ${caFile} -passout pass:${p12Pass}"`}
echo "az keyvault certificate import \\"
echo "  --vault-name YourKeyVault \\"
echo "  --name ${serverName} \\"
echo "  --file ${p12File} \\"
echo "  --password ${p12Pass}"
echo ""

echo "=== 5. Java Keystore (JKS) Conversion ==="
echo "# Convert PKCS#12 to Java JKS using JDK keytool:"
echo "keytool -importkeystore \\"
echo "  -srckeystore ${p12File} -srcstoretype PKCS12 -srcstorepass ${p12Pass} \\"
echo "  -destkeystore keystore.jks -deststoretype JKS -deststorepass ${p12Pass}"
echo ""
`;
}

