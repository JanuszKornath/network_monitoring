import subprocess
import psycopg2
import xml.etree.ElementTree as ET
import sys

# --- KONFIGURATION ---
DB_PARAMS = {
    "host": "localhost",
    "database": "nmapdb",
    "user": "nmapuser",
    "password": "nmap123"
}

TARGET_NETS = [
    "192.168.178.0/24",
    "10.8.0.0/24",
    "192.168.179.1/24"
]

def run_scan():
    try:
        conn = psycopg2.connect(**DB_PARAMS)
        cur = conn.cursor()

        for net in TARGET_NETS:
            print(f"Scanne Netzwerk: {net}...")

            # 1. Alle im Subnetz auf 'down' setzen (Casting auf INET)
            cur.execute("UPDATE nmap_results SET state = 'down' WHERE ip << inet %s", (net,))

            # 2. Nmap Scan ausführen
            cmd = ["nmap", "-sn", "-PS22,80,443,445,3389", "--script", "nbstat", "--min-parallelism", "10", "-oX", "-", net]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            root = ET.fromstring(result.stdout)
            found_count = 0

            for host in root.findall('host'):
                addr_elem = host.find("address[@addrtype='ipv4']")
                if addr_elem is None: continue

                ip = addr_elem.get('addr')
                state = host.find('status').get('state') # Das ist 'up'

                hostname = ""
                hostnames_elem = host.find('hostnames')
                if hostnames_elem is not None:
                    name_tag = hostnames_elem.find('hostname')
                    if name_tag is not None:
                        hostname = name_tag.get('name')

                # 3. Den Status für gefundene Geräte wieder auf 'up' setzen (Upsert)
                cur.execute("""
                    INSERT INTO nmap_results (ip, hostname, state, first_seen, last_scan)
                    VALUES (%s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    ON CONFLICT (ip) DO UPDATE
                    SET hostname = CASE WHEN EXCLUDED.hostname != '' THEN EXCLUDED.hostname ELSE nmap_results.hostname END,
                        state = EXCLUDED.state,
                        last_scan = EXCLUDED.last_scan;
                """, (ip, hostname, state))

                found_count += 1

            conn.commit()
            print(f"Netz {net} fertig: {found_count} Hosts online gefunden.")

# Snapshot für den Verlauf speichern
        cur.execute("""
            INSERT INTO nmap_history (online_count)
            SELECT COUNT(*) FROM nmap_results WHERE state = 'up';
        """)
        conn.commit()

        cur.close()
        conn.close()
        print("Bereinigter Scan erfolgreich beendet.")

    except Exception as e:
        print(f"Fehler: {e}", file=sys.stderr)

if __name__ == "__main__":
    run_scan()
