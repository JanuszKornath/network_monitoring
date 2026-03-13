import subprocess
import psycopg2
import xml.etree.ElementTree as ET
import sys
from datetime import datetime, timedelta

DB_PARAMS = {
    "host": "localhost",
    "database": "nmapdb",
    "user": "nmapuser",
    "password": "nmap123"
}

TARGET_NETS = [
    "192.168.178.0/24",
    "10.8.0.0/24",
    "192.168.179.0/24"
]

# Zeitfenster, nach dem eine IP als 'down' markiert wird
OFFLINE_THRESHOLD_MINUTES = 15

def run_scan():
    try:
        conn = psycopg2.connect(**DB_PARAMS)
        cur = conn.cursor()
        
        # Startzeitpunkt fixieren für diesen Durchlauf
        scan_start_time = datetime.now()
        print(f"Scan gestartet um: {scan_start_time}")

        for net in TARGET_NETS:
            print(f"Scanne Netzwerk: {net}...")

            cmd = [
                "nmap", "-sn",
                "-PS22,80,443,445,3389",
                "--script", "nbstat",
                "--min-parallelism", "10",
                "-oX", "-", net
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            root = ET.fromstring(result.stdout)

            for host in root.findall('host'):
                status_elem = host.find('status')
                if status_elem is None or status_elem.get('state') != 'up':
                    continue
                
                ipv4_elem = host.find("address[@addrtype='ipv4']")
                if ipv4_elem is None:
                    continue

                ip = ipv4_elem.get('addr')

                # Hostname finden
                hostname = ""
                hostnames_elem = host.find('hostnames')
                if hostnames_elem is not None:
                    name_tag = hostnames_elem.find('hostname')
                    if name_tag is not None:
                        hostname = name_tag.get('name')

                # MAC & Vendor
                mac_elem = host.find("address[@addrtype='mac']")
                if mac_elem is not None:
                    mac = mac_elem.get('addr')
                    vendor = mac_elem.get('vendor') or "unknown"
                else:
                    # Spezialfall Localhost oder L3-Hops
                    mac = f"IP-{ip}"
                    vendor = "L3-Hop/Internal"

                # 1. Gerät (MAC) upserten
                # Bei Clustern/keepalived bleibt die MAC die Konstante für die Hardware
                cur.execute("""
                    INSERT INTO devices (mac, hostname, vendor, last_seen)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (mac) DO UPDATE
                    SET hostname = CASE 
                        WHEN EXCLUDED.hostname != '' THEN EXCLUDED.hostname 
                        ELSE devices.hostname 
                    END,
                    last_seen = EXCLUDED.last_seen
                    RETURNING id;
                """, (mac, hostname, vendor, scan_start_time))
                
                device_id = cur.fetchone()[0]

                # 2. IP-Adresse zuordnen (device_id + ip ist der Key)
                # Hier wird nun auch für die Keepalived-IP (.10) der korrekte Status gesetzt,
                # egal welche MAC (.246 oder .247) sie gerade "besitzt".
                cur.execute("""
                    INSERT INTO ip_addresses (device_id, ip, state, last_seen)
                    VALUES (%s, %s, 'up', %s)
                    ON CONFLICT (device_id, ip) DO UPDATE
                    SET state = 'up',
                        last_seen = EXCLUDED.last_seen;
                """, (device_id, ip, scan_start_time))

            conn.commit()
            print(f"Netz {net} verarbeitet.")

        # --- Offline-Bereinigung ---
        # Alle IPs, die in diesem Scan-Zyklus nicht aktualisiert wurden, sind 'down'
        offline_cutoff = scan_start_time - timedelta(seconds=10) # Puffer
        
        cur.execute("""
            UPDATE ip_addresses
            SET state = 'down'
            WHERE last_seen < %s AND state = 'up';
        """, (offline_cutoff,))
        
        down_count = cur.rowcount
        conn.commit()
        if down_count > 0:
            print(f"{down_count} IPs wurden als 'down' markiert.")

        # Historie-Snapshot
        cur.execute("""
            INSERT INTO nmap_history (online_count)
            SELECT COUNT(DISTINCT device_id)
            FROM ip_addresses
            WHERE state = 'up';
        """)
        conn.commit()

        cur.close()
        conn.close()
        print("Scan erfolgreich beendet.")

    except Exception as e:
        print(f"Fehler im Scan-Skript: {e}", file=sys.stderr)

if __name__ == "__main__":
    run_scan()
