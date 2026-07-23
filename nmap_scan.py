import os
import subprocess
import psycopg2
import xml.etree.ElementTree as ET
import sys
import ipaddress
from datetime import datetime, timedelta, timezone

DB_PARAMS = {
    "host": os.environ.get("NMAPDB_HOST", "localhost"),
    "database": os.environ.get("NMAPDB_NAME", "nmapdb"),
    "user": os.environ.get("NMAPDB_USER", "nmapuser"),
    # Kein Default: muss per Umgebungsvariable gesetzt sein (oder via ~/.pgpass)
    "password": os.environ.get("NMAPDB_PASSWORD")
}

# Alle zu ueberwachenden Netze. Einfach eintragen - mehr ist nicht noetig.
TARGET_NETS = [
    "192.168.178.0/24",
    "10.8.0.0/24",
    "192.168.179.0/24",
]

# Optionale Zusatzquelle: FritzBox per TR-064 abfragen.
# Nuetzlich fuer Netze, die per Firewall isoliert sind (z. B. das Gastnetz),
# in denen nmap deshalb nichts sieht. Aktiviert sich automatisch, sobald
# FRITZ_PASSWORD gesetzt ist; ohne die Variable laeuft das Skript als
# reines nmap-Skript.
FRITZ_ADDRESS = os.environ.get("FRITZ_ADDRESS", "192.168.178.1")
FRITZ_USER = os.environ.get("FRITZ_USER", "nmapscan")
FRITZ_PASSWORD = os.environ.get("FRITZ_PASSWORD")

# Zeitfenster, nach dem eine IP als 'down' markiert wird
OFFLINE_THRESHOLD_MINUTES = 15


def scan_net(net):
    """Scannt ein einzelnes Netz und liefert das geparste XML-Root-Element."""
    cmd = [
        "nmap", "-sn",
        "-PS22,80,443,445,3389",
        "--script", "nbstat",
        "--min-parallelism", "10",
        "-oX", "-", net
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return ET.fromstring(result.stdout)


def upsert_host(cur, mac, hostname, vendor, ip, seen_time):
    """Upsertet ein Geraet und seine IP-Adresse (gemeinsame Logik fuer nmap & TR-064)."""
    cur.execute("""
        INSERT INTO devices (mac, hostname, vendor, last_seen)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (mac) DO UPDATE
        SET hostname = CASE
                WHEN EXCLUDED.hostname != '' THEN EXCLUDED.hostname
                ELSE devices.hostname
            END,
            vendor = CASE
                WHEN EXCLUDED.vendor NOT IN ('unknown', 'unknown (TR-064)')
                    THEN EXCLUDED.vendor
                ELSE devices.vendor
            END,
            last_seen = EXCLUDED.last_seen
        RETURNING id;
    """, (mac, hostname, vendor, seen_time))
    device_id = cur.fetchone()[0]

    cur.execute("""
        INSERT INTO ip_addresses (device_id, ip, state, last_seen)
        VALUES (%s, %s, 'up', %s)
        ON CONFLICT (device_id, ip) DO UPDATE
        SET state = 'up',
            last_seen = EXCLUDED.last_seen;
    """, (device_id, ip, seen_time))


def process_nmap_net(cur, net, scan_start_time):
    """Scannt ein Netz per nmap und schreibt die Ergebnisse in die DB."""
    root = scan_net(net)

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
                hostname = name_tag.get('name') or ""

        # MAC & Vendor
        mac_elem = host.find("address[@addrtype='mac']")
        if mac_elem is not None:
            mac = mac_elem.get('addr')
            vendor = mac_elem.get('vendor') or "unknown"
        else:
            # Spezialfall Localhost oder L3-Hops
            mac = f"IP-{ip}"
            vendor = "L3-Hop/Internal"

        upsert_host(cur, mac, hostname, vendor, ip, scan_start_time)


def process_fritzbox(cur, scan_start_time):
    """Ergaenzt die nmap-Ergebnisse um die Host-Liste der FritzBox (TR-064).

    Uebernommen wird jedes aktive Geraet, dessen IP in eines der TARGET_NETS
    faellt. Damit werden auch Geraete erfasst, die nmap nicht erreichen kann
    (z. B. im firewall-isolierten Gastnetz). Doppelte Treffer sind unkritisch:
    das Upsert dedupliziert ueber die MAC-Adresse.
    """
    from fritzconnection.lib.fritzhosts import FritzHosts

    target_networks = [ipaddress.ip_network(n) for n in TARGET_NETS]

    fh = FritzHosts(address=FRITZ_ADDRESS, user=FRITZ_USER, password=FRITZ_PASSWORD)

    count = 0
    for host in fh.get_hosts_attributes():
        ip = host.get("IPAddress") or ""
        mac = host.get("MACAddress") or ""
        if not ip or not mac:
            continue

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not any(addr in net for net in target_networks):
            continue

        # Nur aktuell aktive Geraete als 'up' werten
        active = host.get("Active")
        if not (active is True or str(active) == "1"):
            continue

        hostname = host.get("HostName") or ""
        vendor = "unknown (TR-064)"

        upsert_host(cur, mac, hostname, vendor, ip, scan_start_time)
        count += 1

    print(f"FritzBox (TR-064): {count} aktive Geraete ergaenzt.")


def run_scan():
    try:
        conn = psycopg2.connect(**DB_PARAMS)
    except Exception as e:
        print(f"Keine Datenbankverbindung: {e}", file=sys.stderr)
        sys.exit(1)

    failed_nets = []
    try:
        cur = conn.cursor()

        # Startzeitpunkt fixieren fuer diesen Durchlauf (jetzt mit Zeitzone UTC)
        scan_start_time = datetime.now(timezone.utc)
        print(f"Scan gestartet um (UTC): {scan_start_time}")

        for net in TARGET_NETS:
            print(f"Scanne Netzwerk: {net}...")
            try:
                process_nmap_net(cur, net, scan_start_time)
            except subprocess.CalledProcessError as e:
                print(f"nmap-Scan fuer {net} fehlgeschlagen: {e.stderr}", file=sys.stderr)
                failed_nets.append(net)
                continue
            except ET.ParseError as e:
                print(f"Ungueltige nmap-Ausgabe fuer {net}: {e}", file=sys.stderr)
                failed_nets.append(net)
                continue

            conn.commit()
            print(f"Netz {net} verarbeitet.")

        # --- Optionale Zusatzquelle: FritzBox TR-064 ---
        if FRITZ_PASSWORD:
            try:
                process_fritzbox(cur, scan_start_time)
                conn.commit()
            except Exception as e:
                print(f"FritzBox-Abfrage fehlgeschlagen: {e}", file=sys.stderr)
                conn.rollback()
                failed_nets.append("fritzbox-tr064")

        # --- Offline-Bereinigung ---
        offline_cutoff = scan_start_time - timedelta(minutes=OFFLINE_THRESHOLD_MINUTES)
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

    except Exception as e:
        print(f"Fehler im Scan-Skript: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        conn.close()

    if failed_nets:
        print(f"Scan beendet, aber fehlgeschlagene Netze: {', '.join(failed_nets)}", file=sys.stderr)
        sys.exit(1)

    print("Scan erfolgreich beendet.")


if __name__ == "__main__":
    run_scan()
