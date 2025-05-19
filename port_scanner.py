import socket

def scan_ports(target):
    ports = [22, 80, 443, 8080]
    print(f"Starting port scan on {target}...\n")
    
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # timeout 1 sec for quick scan
        
        result = sock.connect_ex((target, port))  # returns 0 if port is open
        
        if result == 0:
            print(f"Port {port} is OPEN")
        else:
            print(f"Port {port} is CLOSED")
        sock.close()

if __name__ == "__main__":
    target = input("Enter IP or domain to scan: ")
    scan_ports(target)
