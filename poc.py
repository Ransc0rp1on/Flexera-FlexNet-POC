import socket
import re

# Version threshold for vulnerability
VULNERABLE_VERSION = "11.19.6.0"

def get_flexnet_version(host, port):
    """Connects to FlexNet Publisher and extracts version information."""
    try:
        # Create a socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        
        # Send a basic request (some FlexNet services respond with version info)
        sock.sendall(b"\n")
        response = sock.recv(1024).decode(errors="ignore")
        
        # Close the connection
        sock.close()
        
        # Extract the version using regex
        version_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", response)
        if version_match:
            return version_match.group(1)
        else:
            return None
    except Exception as e:
        print(f"[!] Error connecting to {host}:{port} -> {e}")
        return None

def compare_versions(version, vulnerable_version):
    """Compares two version strings."""
    return tuple(map(int, version.split("."))) < tuple(map(int, vulnerable_version.split(".")))

def main():
    print("[*] FlexNet Publisher Version Checker for CVE-2024-2658")
    
    # Get target input
    target = input("Enter target hostname/IP: ").strip()
    if not target:
        print("[!] Target cannot be empty!")
        return
    
    # Get port input with validation
    port_input = input("Enter target port [27000]: ").strip()
    if not port_input:
        port = 27000
    else:
        try:
            port = int(port_input)
            if not (1 <= port <= 65535):
                print("[!] Invalid port number. Using default 27000.")
                port = 27000
        except ValueError:
            print("[!] Invalid port. Using default 27000.")
            port = 27000
    
    print(f"\n[*] Checking FlexNet Publisher on {target}:{port}")

    version = get_flexnet_version(target, port)
    if version:
        print(f"[+] Detected Version: {version}")

        if compare_versions(version, VULNERABLE_VERSION):
            print("[!] Vulnerable to CVE-2024-2658! Upgrade to 11.19.6.0 or later.")
        else:
            print("[+] System is patched.")
    else:
        print("[!] Could not retrieve FlexNet Publisher version.")

if __name__ == "__main__":
    main()
