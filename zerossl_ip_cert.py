#!/usr/bin/env python3
"""
ZeroSSL IP-based Certificate Request Script
Requests and validates an SSL certificate for an IP address using ZeroSSL API
Includes automated HTTP verification
"""

import requests
import json
import time
import sys
import argparse
import os
from dotenv import load_dotenv
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from urllib.parse import urlparse
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import ipaddress

# Configuration
load_dotenv()
ZEROSSL_API_KEY = os.environ.get("ZEROSSL_API_KEY", "")
CERTIFICATE_VALIDITY_DAYS = 90

# ZeroSSL API endpoints
BASE_URL = "https://api.zerossl.com"
CREATE_CERT_URL = f"{BASE_URL}/certificates"
VERIFY_DOMAINS_URL = f"{BASE_URL}/certificates/{{cert_id}}/challenges"
DOWNLOAD_CERT_URL = f"{BASE_URL}/certificates/{{cert_id}}/download/return"

# Global variable for validation data
validation_data = {}

class ValidationHandler(BaseHTTPRequestHandler):
    """HTTP handler for serving validation files"""
    
    def do_GET(self):
        """Handle GET requests for validation files"""
        path = self.path
        
        if path in validation_data:
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(validation_data[path].encode())
            print(f"Served validation file: {path}")
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

def start_validation_server(port=80):
    """Start HTTP server for validation"""
    server = HTTPServer(('0.0.0.0', port), ValidationHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"Validation server started on port {port}")
    return server

def generate_csr_and_key(ip_address):
    """Generate a private key and CSR for the IP address"""
    print(f"Generating private key and CSR for IP: {ip_address}")
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Parse IP address
    ip_obj = ipaddress.ip_address(ip_address)
    
    # Create CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, ip_address),
    ])).add_extension(
        x509.SubjectAlternativeName([
            x509.IPAddress(ip_obj)
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    # Convert to PEM format
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    print("Private key and CSR generated successfully")
    return private_key_pem, csr_pem

def create_certificate(api_key, ip_address, validity_days):
    """Create a new certificate request for an IP address"""
    print(f"Creating certificate request for IP: {ip_address}")
    
    # Generate CSR and private key
    private_key_pem, csr_pem = generate_csr_and_key(ip_address)
    
    # Save private key
    private_key_filename = f"private_key_{ip_address.replace('.', '_')}.pem"
    with open(private_key_filename, "w") as f:
        f.write(private_key_pem)
    print(f"Private key saved as: {private_key_filename}")
    
    payload = {
        "certificate_domains": ip_address,
        "certificate_validity_days": validity_days,
        "certificate_csr": csr_pem
    }
    
    params = {"access_key": api_key}
    
    try:
        response = requests.post(CREATE_CERT_URL, params=params, data=payload)
        response.raise_for_status()
        cert_data = response.json()
        
        # Debug: Print the response structure
        print(f"\nAPI Response:")
        print(json.dumps(cert_data, indent=2))
        
        # Check for error in response
        if "error" in cert_data:
            print(f"\nError from ZeroSSL: {cert_data['error']}")
            sys.exit(1)
        
        # Try to get certificate ID
        cert_id = cert_data.get('id') or cert_data.get('certificate_id')
        if not cert_id:
            print(f"\nError: Could not find certificate ID in response")
            print("Response keys:", list(cert_data.keys()))
            sys.exit(1)
        
        print(f"\nCertificate created successfully!")
        print(f"Certificate ID: {cert_id}")
        return cert_data
    except requests.exceptions.RequestException as e:
        print(f"Error creating certificate: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response: {e.response.text}")
        sys.exit(1)

def get_verification_details(api_key, cert_id):
    """Get verification details for the certificate"""
    print(f"\nFetching verification details for certificate ID: {cert_id}")
    
    url = VERIFY_DOMAINS_URL.format(cert_id=cert_id)
    params = {"access_key": api_key}
    
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching verification details: {e}")
        sys.exit(1)

def verify_domain(api_key, cert_id, validation_method="HTTP_CSR_HASH"):
    """Start domain verification process"""
    print(f"\nStarting domain verification with method: {validation_method}")
    
    url = VERIFY_DOMAINS_URL.format(cert_id=cert_id)
    params = {"access_key": api_key}
    payload = {"validation_method": validation_method}
    
    try:
        response = requests.post(url, params=params, data=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error starting verification: {e}")
        if hasattr(e.response, 'text'):
            print(f"Response: {e.response.text}")
        sys.exit(1)

def check_certificate_status(api_key, cert_id):
    """Check the current status of the certificate"""
    url = f"{BASE_URL}/certificates/{cert_id}"
    params = {"access_key": api_key}
    
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        cert_info = response.json()
        return cert_info.get("status", "unknown")
    except requests.exceptions.RequestException as e:
        print(f"Error checking certificate status: {e}")
        return "error"

def download_certificate(api_key, cert_id):
    """Download the issued certificate"""
    print(f"\nDownloading certificate...")
    
    url = DOWNLOAD_CERT_URL.format(cert_id=cert_id)
    params = {"access_key": api_key}
    
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        cert_files = response.json()
        
        # Save certificate files
        with open(f"certificate_{cert_id}.crt", "w") as f:
            f.write(cert_files.get("certificate.crt", ""))
        
        with open(f"ca_bundle_{cert_id}.crt", "w") as f:
            f.write(cert_files.get("ca_bundle.crt", ""))
        
        print(f"Certificate saved as: certificate_{cert_id}.crt")
        print(f"CA Bundle saved as: ca_bundle_{cert_id}.crt")
        
        return cert_files
    except requests.exceptions.RequestException as e:
        print(f"Error downloading certificate: {e}")
        sys.exit(1)

def setup_http_validation(verification_data_response, port=80):
    """Setup HTTP validation by starting server and preparing validation files"""
    global validation_data
    
    # Check for validation data in different possible locations
    validation_info = verification_data_response.get("validation", {})
    
    # ZeroSSL might use "other_methods" instead of direct validation
    if "other_methods" in validation_info:
        validation_info = validation_info["other_methods"]
    
    if not validation_info:
        print("Error: No validation data found")
        return False
    
    # Extract validation information
    for domain, methods in validation_info.items():
        if isinstance(methods, dict) and "file_validation_url_http" in methods:
            url = methods["file_validation_url_http"]
            content = methods["file_validation_content"]
            
            # Content might be a list, join with newlines
            if isinstance(content, list):
                content = "\n".join(content)
            
            # Extract path from URL
            parsed_url = urlparse(url)
            path = parsed_url.path
            
            print(f"\nHTTP Validation Setup:")
            print(f"  URL: {url}")
            print(f"  Path: {path}")
            print(f"  Content length: {len(content)} characters")
            
            # Store validation data
            validation_data[path] = content
            
            return True
    
    print("Error: No HTTP validation method found")
    return False

def main():
    global validation_data
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Request an IP-based SSL certificate from ZeroSSL with automated HTTP verification"
    )
    parser.add_argument(
        "ip_address",
        help="IP address for the certificate (e.g., 192.0.2.1)"
    )
    parser.add_argument(
        "--api-key",
        default=ZEROSSL_API_KEY,
        help="ZeroSSL API key (overrides script default)"
    )
    parser.add_argument(
        "--validity",
        type=int,
        default=CERTIFICATE_VALIDITY_DAYS,
        help=f"Certificate validity in days (default: {CERTIFICATE_VALIDITY_DAYS})"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=80,
        help="Port for HTTP validation server (default: 80)"
    )
    parser.add_argument(
        "--no-auto-verify",
        action="store_true",
        help="Don't automatically setup HTTP verification server"
    )
    parser.add_argument(
        "--manual",
        action="store_true",
        help="Manual mode: display verification details but don't start server"
    )
    
    args = parser.parse_args()
    
    # Validate API key
    if args.api_key == "your_api_key_here":
        print("Error: Please provide a valid ZeroSSL API key")
        print("Use --api-key option or set it in the script")
        sys.exit(1)
    
    print("=" * 60)
    print("ZeroSSL IP-based Certificate Request")
    print("=" * 60)
    
    # Step 1: Create certificate
    cert_data = create_certificate(args.api_key, args.ip_address, args.validity)
    cert_id = cert_data.get('id') or cert_data.get('certificate_id')
    
    if not cert_id:
        print("Error: Could not extract certificate ID from response")
        sys.exit(1)
    
    # Step 2: Use verification details from cert_data (already included in response)
    verification_response = cert_data
    
    # Step 3: Setup HTTP verification
    if args.manual:
        print("\n" + "=" * 60)
        print("MANUAL MODE - VERIFICATION REQUIRED")
        print("=" * 60)
        
        validation_info = verification_response.get("validation", {})
        if "other_methods" in validation_info:
            methods_info = validation_info["other_methods"]
        else:
            methods_info = validation_info
            
        for domain, methods in methods_info.items():
            print(f"\nDomain/IP: {domain}")
            
            if isinstance(methods, dict) and "file_validation_url_http" in methods:
                print(f"\nHTTP Verification:")
                print(f"  URL: {methods['file_validation_url_http']}")
                content = methods['file_validation_content']
                if isinstance(content, list):
                    content = "\n".join(content)
                print(f"  Content:\n{content}")
            
            if isinstance(methods, dict) and "cname_validation_p1" in methods:
                print(f"\nCNAME Verification:")
                print(f"  Host: {methods['cname_validation_p1']}")
                print(f"  Value: {methods['cname_validation_p2']}")
        
        print(f"\nCertificate ID: {cert_id}")
        return
    
    if not args.no_auto_verify:
        print("\n" + "=" * 60)
        print("AUTOMATED HTTP VERIFICATION")
        print("=" * 60)
        
        # Setup validation files and start server
        if setup_http_validation(verification_response, args.port):
            # Check if we need root privileges for port 80
            #if args.port == 80 and os.geteuid() != 0:
             #   print("\nWARNING: Port 80 requires root privileges!")
              #  print("Run with sudo or use --port option to specify a different port")
               # print("Example: sudo python3 zerossl_ip_cert.py " + args.ip_address)
                #sys.exit(1)
            
            # Start the validation server
            server = start_validation_server(args.port)
            
            # Trigger verification
            print("\nTriggering verification...")
            verify_response = verify_domain(args.api_key, cert_id, "HTTP_CSR_HASH")
            print("Verification triggered successfully!")
            
            # Wait for certificate to be issued
            print("\nWaiting for certificate to be issued...")
            print("This may take a few minutes...")
            
            max_attempts = 60
            for attempt in range(max_attempts):
                status = check_certificate_status(args.api_key, cert_id)
                
                if status == "issued":
                    print(f"\n{'=' * 60}")
                    print("SUCCESS! Certificate has been issued!")
                    print("=" * 60)
                    server.shutdown()
                    download_certificate(args.api_key, cert_id)
                    break
                elif status in ["cancelled", "expired"]:
                    print(f"\nERROR: Certificate request failed with status: {status}")
                    server.shutdown()
                    sys.exit(1)
                elif attempt % 6 == 0:  # Print status every minute
                    print(f"Status: {status} (attempt {attempt + 1}/{max_attempts})")
                
                time.sleep(10)
            else:
                print("\nTimeout waiting for certificate.")
                print(f"Certificate ID: {cert_id}")
                print("Check status manually or try again later.")
                server.shutdown()
        else:
            print("\nHTTP validation setup failed.")
            print("Use --manual flag to see verification details.")
    else:
        print("\nAutomatic verification disabled.")
        print(f"Certificate ID: {cert_id}")
        print("Complete verification manually and check certificate status.")
    
    print(f"\nCertificate ID: {cert_id}")

if __name__ == "__main__":
    main()
