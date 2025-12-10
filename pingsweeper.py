import csv
import socket
from scapy.all import ARP, Ether, srp
from threading import Thread, Lock
from queue import Queue

TARGET = "192.168.1.0/24"   # Change your network
threads_count = 50           # Increase for faster scan

print_lock = Lock()
queue = Queue()
results = []

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def scan_ip(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    try:
        ans = srp(packet, timeout=1, verbose=0)[0]
        for _, rcv in ans:
            hostname = resolve_hostname(rcv.psrc)
            with print_lock:
                print(f"[✔ ONLINE] {rcv.psrc}\tMAC: {rcv.hwsrc}\tHost: {hostname}")
            results.append({"IP": rcv.psrc, "MAC": rcv.hwsrc, "Hostname": hostname})
    except PermissionError:
        with print_lock:
            print("[⚠] Permission denied! Run this script as root/admin.")
    except Exception as e:
        with print_lock:
            print(f"[⚠] Error scanning {ip}: {e}")

def worker():
    while not queue.empty():
        ip = queue.get()
        scan_ip(ip)
        queue.task_done()

# Fill the queue with all IPs
base_ip = TARGET.split(".")
for i in range(1, 255):
    queue.put(f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.{i}")

# Start threads
thread_list = []
for _ in range(threads_count):
    t = Thread(target=worker)
    t.start()
    thread_list.append(t)

for t in thread_list:
    t.join()

# Save results
with open("scan_results.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["IP", "MAC", "Hostname"])
    writer.writeheader()
    writer.writerows(results)

print(f"\n🟩 Scan complete! Devices found: {len(results)}")
print("Results saved to scan_results.csv")
