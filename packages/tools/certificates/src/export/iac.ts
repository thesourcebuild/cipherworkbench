export interface IacTemplateParams {
  certFilename?: string;
  keyFilename?: string;
  caFilename?: string;
  serverName?: string;
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
