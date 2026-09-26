import ssl
import http.client
import os
import sys
import argparse

DIR = os.path.dirname(os.path.abspath(__file__))
CA_FILE = os.path.join(DIR, "ca.crt")
HOST = "127.0.0.1"
PORT = 8443

def create_ssl_context(tls_version="auto"):
    ctx = ssl.create_default_context(cafile=CA_FILE)
    if tls_version == "1.1":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    elif tls_version == "1.2":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    elif tls_version == "1.3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    return ctx

def run_single_test(tls_version="auto"):
    print(f"Connecting to https://{HOST}:{PORT} (TLS: {tls_version}) verifying against Root CA...")
    ctx = create_ssl_context(tls_version)

    conn = http.client.HTTPSConnection(HOST, PORT, context=ctx, timeout=5)
    try:
        conn.connect()
        ssl_sock = conn.sock
        negotiated_proto = ssl_sock.version() if ssl_sock else "Unknown"
        cipher_tuple = ssl_sock.cipher() if ssl_sock else ("Unknown",)

        conn.request("GET", "/")
        res = conn.getresponse()
        body = res.read().decode("utf-8")

        print(f"  ✓ PASS: CA-Signed TLS Handshake Successful!")
        print(f"    - Protocol:    {negotiated_proto}")
        print(f"    - Cipher:      {cipher_tuple[0]}")
        print(f"    - HTTP Status: {res.status}")
        print(f"    - Server Data: {body.strip()}")
        return True
    except ConnectionRefusedError:
        print("  Notice: Server is not running. Start 'python server.py' in another terminal first.")
        return False
    except ssl.SSLError as e:
        print(f"  ✗ FAIL: SSL Handshake Failed: {e}")
        return False
    finally:
        conn.close()

def main():
    if not os.path.exists(CA_FILE):
        print(f"Error: {CA_FILE} not found. Run 'npx tsx run.ts' first.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Python HTTPS Client for CA-Signed Cert")
    parser.add_argument("--tls-version", choices=["auto", "1.1", "1.2", "1.3", "all"], default="auto", help="TLS version to request")
    args = parser.parse_args()

    print("=================================================")
    print("   PYTHON CLIENT: SINGLE CA-SIGNED TEST          ")
    print("=================================================")

    if args.tls_version == "all":
        for v in ["1.3", "1.2", "1.1"]:
            print(f"\n--- Testing TLS {v} ---")
            run_single_test(v)
    else:
        run_single_test(args.tls_version)

if __name__ == "__main__":
    main()
