import os
import sys
import time
from scapy.all import sniff, ARP, IP
import psycopg2
#Dit is gescreven meeste door LLM, ik heb zelf gevraagd om scapy te gebruiken
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")  
DB_NAME = os.getenv("DB_NAME", "sniffer_db")
DB_USER = os.getenv("DB_USER", "sniffer_admin")


DB_PASSWORD_FILE = os.getenv("DB_PASSWORD_FILE", "/run/secrets/db_password")

DB_PASSWORD = os.getenv("DB_PASSWORD", "")


if os.path.exists(DB_PASSWORD_FILE):
    with open(DB_PASSWORD_FILE, 'r') as f:
        DB_PASSWORD = f.read().strip()

INTERFACE = os.getenv("SNIFFER_INTERFACE", "ens3")  
LEARNING_MODE = os.getenv("LEARNING_MODE", "True").lower() == "true"

def get_db_connection():
    try:
        return psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            connect_timeout=3
        )
    except psycopg2.OperationalError as e:
        print(f"[-] Database verbindingsfout: {e}")
        return None

def init_database():
    conn = get_db_connection()
    if not conn:
        print("[-] Initialisatie mislukt: database onbereikbaar.")
        sys.exit(1)
        
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_baseline (
            mac_address VARCHAR(17) PRIMARY KEY,
            ip_address VARCHAR(15) NOT NULL,
            device_name VARCHAR(50),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id SERIAL PRIMARY KEY,
            mac_address VARCHAR(17) NOT NULL,
            ip_address VARCHAR(15) NOT NULL,
            issue_description TEXT NOT NULL,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    
    conn.commit()
    cursor.close()
    conn.close()
    print("[+] Database succesvol geïnitialiseerd en tabellen gecontroleerd.")

def add_to_baseline(mac, ip):
    print(f"[+] [LEERMODUS] Nieuw apparaat ontdekt! Toevoegen aan baseline: MAC={mac} | IP={ip}")
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO network_baseline (mac_address, ip_address, device_name) 
                VALUES (%s, %s, %s)
                ON CONFLICT (mac_address) DO NOTHING;
            """, (mac, ip, "Auto-discovered"))
            conn.commit()
        except Exception as e:
            print(f"[-] Fout bij automatisch vullen baseline: {e}")
        cursor.close()
        conn.close()

def check_mac_baseline(mac, ip):
    conn = get_db_connection()
    if not conn:
        return  
        
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address FROM network_baseline WHERE mac_address = %s;", (mac,))
    result = cursor.fetchone()
    
    if result is None:
        if LEARNING_MODE:
            add_to_baseline(mac, ip)
        else:
            log_incident(mac, ip, "Rogue Device Detected (Onbekend apparaat in netwerk)")
    elif result[0] != ip: 
        log_incident(mac, ip, f"MAC Spoofing gedetecteerd! Verwachtte IP: {result[0]}")
        
    cursor.close()
    conn.close()

def log_incident(mac, ip, issue):
    print(f"[!] ALERT: {issue} | MAC: {mac} | IP: {ip}")
    
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO incidents (mac_address, ip_address, issue_description) VALUES (%s, %s, %s);",
            (mac, ip, issue)
        )
        conn.commit()
        cursor.close()
        conn.close()
    
    try:
        with open("/var/log/alerts.log", "a") as f:
            f.write(f'[{time.strftime("%Y-%m-%d %H:%M:%S")}] ALERT: {issue} | MAC: {mac} | IP: {ip}\n')
    except IOError as e:
        print(f"[-] Kon niet schrijven naar alerts.log: {e}")

def packet_callback(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  
        src_mac = packet[ARP].hwsrc
        src_ip = packet[ARP].psrc
        check_mac_baseline(src_mac, src_ip)

if __name__ == "__main__":
    print("[+] Passive Network Sniffer v1.1 wordt opgestart...")
    
    init_database()
    
    print(f"[+] Status Leermodus (LEARNING_MODE) = {LEARNING_MODE}")
    print(f"[+] Sniffer luistert nu passief op interface: {INTERFACE}")
    
    sniff(iface=INTERFACE, filter="arp", prn=packet_callback, store=0)