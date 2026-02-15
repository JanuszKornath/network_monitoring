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

OFFLINE_THRESHOLD_MINUTES = 5

def run_scan():
    try:
        conn = psycopg2.connect(**DB_PARAMS)
        cur = conn.cursor()

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

            scanned_device_ids = []

            for host in root.findall('host'):
                ipv4_elem = host.find("address[@addrtype='ipv4']")
                if ipv4_elem is None:
                    continue

                ip = ipv4_elem.get('addr')
                state = host.find('status').get('state')  # 'up'

                hostname = ""
                hostnames_elem = host.find('hostnames')
                if hostnames_elem is not None:
                    name_tag = hostnames_elem.find('hostname')
                    if name_tag is not None:
                        hostname = name_tag.get('name')

                mac_elem = host.find("address[@addrtype='mac']")
                if mac_elem is not None:
                    mac = mac_elem.get('addr')
                    vendor = mac_elem.get('vendor')
                else:
                    # MAC fehlt → IP als Platzhalter
                    mac = ip
                    vendor = "unknown"

                # --- Gerät upserten / MAC ersetzen falls vorher nur IP-Platzhalter ---
                cur.execute("""
                    INSERT INTO devices (mac, hostname, vendor, last_seen)
                    VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT (mac) DO UPDATE
                    SET hostname = CASE
                        WHEN EXCLUDED.hostname != '' THEN EXCLUDED.hostname
                        ELSE devices.hostname
                    END,
                        last_seen = CURRENT_TIMESTAMP
                    RETURNING id;
                """, (mac, hostname, vendor))
                device_id = cur.fetchone()[0]

                # Falls Gerät zuvor nur IP-Platzhalter war, ersetzen wir die MAC
                if mac_elem is not None:
                    cur.execute("""
                        UPDATE devices
                        SET mac = %s
                        WHERE mac = %s AND mac != %s;
                    """, (mac, ip, mac))

                scanned_device_ids.append(device_id)

                # --- IP zu Gerät ---
                cur.execute("""
                    INSERT INTO ip_addresses (device_id, ip, state, last_seen)
                    VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT (device_id, ip) DO UPDATE
                    SET state = EXCLUDED.state,
                        last_seen = CURRENT_TIMESTAMP;
                """, (device_id, ip, state))

            conn.commit()
            print(f"Netz {net} fertig. {len(scanned_device_ids)} Geräte gefunden.")

            # --- Offline-Geräte auf 'down' setzen ---
            offline_cutoff = datetime.now() - timedelta(minutes=OFFLINE_THRESHOLD_MINUTES)
            cur.execute("""
                UPDATE ip_addresses
                SET state = 'down'
                WHERE last_seen < %s;
            """, (offline_cutoff,))
            conn.commit()

        # --- Snapshot ---
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
        print(f"Fehler: {e}", file=sys.stderr)


if __name__ == "__main__":
    run_scan()
