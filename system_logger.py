import os
import platform
import socket
import getpass
import datetime
import subprocess

# === LOG FILE NAME ===
filename = f"system_log_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"

# === GET SUSPICIOUS KEYWORDS ===
with open("suspicious_keywords.txt", "r") as f:
    suspicious_words = [line.strip().lower() for line in f.readlines()]

# === START WRITING TO FILE ===
with open(filename, "w") as log:

    log.write("=== Basic System Information ===\n")
    log.write(f"User        : {getpass.getuser()}\n")
    log.write(f"Hostname    : {socket.gethostname()}\n")
    log.write(f"IP Address  : {socket.gethostbyname(socket.gethostname())}\n")
    log.write(f"OS          : {platform.system()} {platform.release()}\n")
    log.write(f"Directory   : {os.getcwd()}\n")

    log.write("\n=== Running Processes ===\n")

    try:
        processes = subprocess.check_output("tasklist", shell=True).decode()
    except:
        processes = subprocess.check_output(["ps", "-aux"]).decode()

    log.write(processes)

# === CHECK FOR SUSPICIOUS KEYWORDS ===
found_sus = [word for word in suspicious_words if word in processes.lower()]

if found_sus:
    print("⚠️ Suspicious processes found:\n")
    for word in found_sus:
        print(f" - {word}")
else:
    print("✅ No suspicious processes found.\n")

print(f"Log saved in: {filename}")
