import ssl
import http.client
import os
import sys
import argparse

DIR = os.path.dirname(os.path.abspath(__file__))
CA_FILE = os.path.join(DIR, "ca.crt")
CLIENT_CHAIN = os.path.join(DIR, "client-chain.pem")
CLIENT_KEY = os.path.join(DIR, "client.key")
HOST = "127.0.0.1"
PORT = 8443

def create_ssl_context(with_client_cert=True, tls_version="auto"):
    ctx = ssl.create_default_context(cafile=CA_FILE)
    if with_client_cert:
        ctx.load_cert_chain(certfile=CLIENT_CHAIN, keyfile=CLIENT_KEY)

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

def test_authenticated(tls_version="auto"):
    print(f"\n--- Test 1: 3-Tier Enterprise mTLS Handshake (TLS: {tls_version}) ---")
    ctx = create_ssl_context(with_client_cert=True, tls_version=tls_version)
    conn = http.client.HTTPSConnection(HOST, PORT, context=ctx, timeout=5)
    try:
        conn.connect()
        ssl_sock = conn.sock
        proto = ssl_sock.version() if ssl_sock else "Unknown"
        cipher = ssl_sock.cipher()[0] if ssl_sock else "Unknown"

        conn.request("GET", "/")
        res = conn.getresponse()
        body = res.read().decode("utf-8")

        print("  ✓ PASS: 3-Tier Enterprise mTLS Connection Successful!")
        print(f"    - Protocol:    {proto}")
        print(f"    - Cipher:      {cipher}")
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

def test_unauthenticated(tls_version="auto"):
    print(f"\n--- Test 2: Unauthenticated Request (Expecting Rejection) ---")
    ctx = create_ssl_context(with_client_cert=False, tls_version=tls_version)
    conn = http.client.HTTPSConnection(HOST, PORT, context=ctx, timeout=5)
    try:
        conn.connect()
        conn.request("GET", "/")
        res = conn.getresponse()
        print(f"  ✗ FAIL: Server unexpectedly accepted unauthenticated request! Status: {res.status}")
    except (ssl.SSLError, ConnectionResetError) as e:
        print(f"  ✓ PASS: Server strictly rejected connection without client certificate:")
        print(f"    - Rejection details: {e}")
    except ConnectionRefusedError:
        print("  Notice: Server is not running. Start 'python server.py' in another terminal first.")
    finally:
        conn.close()

def main():
    if not os.path.exists(CA_FILE) or not os.path.exists(CLIENT_CHAIN) or not os.path.exists(CLIENT_KEY):
        print(f"Error: Certificate files not found in {DIR}. Run 'npx tsx run.ts' first.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Python 3-Tier Enterprise mTLS Client")
    parser.add_argument("--tls-version", choices=["auto", "1.1", "1.2", "1.3", "all"], default="auto", help="TLS version to request")
    args = parser.parse_args()

    print("=================================================================")
    print("   PYTHON CLIENT: 3-TIER ENTERPRISE mTLS TEST                    ")
    print("=================================================================")

    if args.tls_version == "all":
        for v in ["1.3", "1.2", "1.1"]:
            test_authenticated(v)
        test_unauthenticated("auto")
    else:
        connected = test_authenticated(args.tls_version)
        if connected:
            test_unauthenticated(args.tls_version)

if __name__ == "__main__":
    main()
