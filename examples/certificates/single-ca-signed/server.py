import http.server
import ssl
import os
import sys
import argparse

PORT = 8443
DIR = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(DIR, "server.crt")
KEY_FILE = os.path.join(DIR, "server.key")
CA_FILE = os.path.join(DIR, "ca.crt")

class HelloHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        tls_version = "Unknown"
        cipher = "Unknown"
        try:
            sock = self.request
            if hasattr(sock, "version"):
                tls_version = sock.version() or "Unknown"
                cipher = (sock.cipher() or ("Unknown",))[0]
        except Exception:
            pass

        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        body = (
            f'{{"status": "ok", "mode": "single-ca-signed", "tls_version": "{tls_version}", "cipher": "{cipher}"}}\n'
        )
        self.wfile.write(body.encode("utf-8"))

def run_server(tls_version="auto"):
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        print(f"Error: Certificate or key not found in {DIR}. Run 'npx tsx run.ts' first.")
        sys.exit(1)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    if tls_version == "1.1":
        context.minimum_version = ssl.TLSVersion.TLSv1_1
        context.maximum_version = ssl.TLSVersion.TLSv1_1
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    elif tls_version == "1.2":
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    elif tls_version == "1.3":
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3

    server_address = ("127.0.0.1", PORT)
    httpd = http.server.HTTPServer(server_address, HelloHandler)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"Single CA-Signed HTTPS Server running on https://127.0.0.1:{PORT}")
    print(f"Supported TLS: {'All (TLS 1.2 & 1.3 Auto)' if tls_version == 'auto' else 'TLS ' + tls_version}")
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Single CA-Signed HTTPS Server")
    parser.add_argument("--tls-version", choices=["auto", "1.1", "1.2", "1.3"], default="auto", help="TLS version to enforce")
    args = parser.parse_args()
    run_server(args.tls_version)
