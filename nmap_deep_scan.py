#!/usr/bin/env python3
"""Deep-Scan-Ergaenzung zu nmap_scan.py.

Waehrend nmap_scan.py alle 15 Minuten einen reinen Discovery-Sweep (-sn) ueber
die TARGET_NETS faehrt, nimmt dieses Skript die Ziel-IPs *aus der Datenbank*
und scannt nur die Hosts, die zuletzt online waren -- dafuer mit Port-,
Service- und OS-Erkennung. Das spart die ~200 toten IPs pro /24 und macht den
teuren Scan ueberhaupt erst praktikabel.

Laufzeit-Groessenordnung: ~40 aktive Hosts, Top-1000-Ports, -sV -O
=> 5 bis 15 Minuten. Gehoert in einen naechtlichen Cron-Job, nicht in den
15-Minuten-Takt.

Braucht Root (-sS und -O sind Raw-Socket-Operationen).
"""

import ipaddress
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

import psycopg2

DB_PARAMS = {
    "host": os.environ.get("NMAPDB_HOST", "localhost"),
    "database": os.environ.get("NMAPDB_NAME", "nmapdb"),
    "user": os.environ.get("NMAPDB_USER", "nmapuser"),
    # Kein Default: muss per Umgebungsvariable gesetzt sein (oder via ~/.pgpass)
    "password": os.environ.get("NMAPDB_PASSWORD"),
}

# Netze, die per Firewall nicht erreichbar sind. Geraete dort stehen zwar per
# TR-064 als 'up' in der DB, nmap kommt aber nicht hin -- sie hier zu scannen
# kostet nur Timeouts.
EXCLUDE_NETS = [
    "192.168.179.0/24",
]

# Einzelne Hosts ueberspringen (IP-Strings), z. B. empfindliche Geraete.
EXCLUDE_HOSTS = []

# Nur Hosts scannen, die der Discovery-Scan in diesem Zeitfenster gesehen hat.
TARGET_MAX_AGE_HOURS = 24

# Ports, die beim Version-Scan nicht angefasst werden.
# 9100 = RAW/JetDirect: Netzwerkdrucker drucken bei Banner-Probes gern
# Zeichensalat aus. Der Port wird dadurch auch nicht als offen erfasst.
EXCLUDE_PORTS = "9100"

NMAP_OPTS = [
    "-sS",                      # SYN-Scan
    "-sV",                      # Service-/Versionserkennung
    "--version-intensity", "4",  # Default ist 7; 4 ist spuerbar schneller
    "-O",                       # OS-Erkennung
    "--osscan-limit",           # OS nur bei 1 offenem + 1 geschlossenen Port
    "--top-ports", "1000",
    "-T4",
    "--max-retries", "2",
    "--host-timeout", "300s",
    "--exclude-ports", EXCLUDE_PORTS,
    "-oX", "-",
]

# Nur diese Port-Zustaende werden gespeichert.
INTERESTING_STATES = ("open", "open|filtered")


def fetch_targets(cur, cutoff):
    """Liefert {ip: device_id} fuer alle zuletzt online gesehenen Hosts."""
    cur.execute(
        """
        SELECT DISTINCT ON (host(ip.ip))
               host(ip.ip) AS ip, ip.device_id
        FROM ip_addresses ip
        WHERE ip.state = 'up'
          AND ip.last_seen >= %s
        ORDER BY host(ip.ip), ip.last_seen DESC;
        """,
        (cutoff,),
    )

    excluded = [ipaddress.ip_network(n) for n in EXCLUDE_NETS]
    targets = {}

    for ip, device_id in cur.fetchall():
        if ip in EXCLUDE_HOSTS:
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if any(addr in net for net in excluded):
            continue
        targets[ip] = device_id

    return targets


def run_nmap(targets):
    """Scannt alle Ziele in einem Lauf und liefert das XML-Root-Element."""
    cmd = ["nmap"] + NMAP_OPTS + sorted(targets)
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return ET.fromstring(result.stdout)


def _attr(elem, name):
    """Attribut als String, nie None."""
    if elem is None:
        return ""
    return elem.get(name) or ""


def _cpes(elem):
    if elem is None:
        return ""
    return ",".join(c.text for c in elem.findall("cpe") if c.text)


def upsert_port(cur, device_id, port_elem, seen_time):
    """Schreibt einen offenen Port samt Dienst in die DB."""
    state_elem = port_elem.find("state")
    state = _attr(state_elem, "state")
    if state not in INTERESTING_STATES:
        return False

    protocol = _attr(port_elem, "protocol")
    port = int(port_elem.get("portid"))
    svc = port_elem.find("service")

    cur.execute(
        """
        INSERT INTO ports (device_id, port, protocol, state, service, product,
                           version, extrainfo, cpe, first_seen, last_seen)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (device_id, port, protocol) DO UPDATE
        SET state     = EXCLUDED.state,
            -- leere Werte eines schwachen Scans duerfen gute Daten
            -- aus einem frueheren Lauf nicht ueberschreiben
            service   = CASE WHEN EXCLUDED.service   != '' THEN EXCLUDED.service
                             ELSE ports.service   END,
            product   = CASE WHEN EXCLUDED.product   != '' THEN EXCLUDED.product
                             ELSE ports.product   END,
            version   = CASE WHEN EXCLUDED.version   != '' THEN EXCLUDED.version
                             ELSE ports.version   END,
            extrainfo = CASE WHEN EXCLUDED.extrainfo != '' THEN EXCLUDED.extrainfo
                             ELSE ports.extrainfo END,
            cpe       = CASE WHEN EXCLUDED.cpe       != '' THEN EXCLUDED.cpe
                             ELSE ports.cpe       END,
            last_seen = EXCLUDED.last_seen;
        """,
        (
            device_id, port, protocol, state,
            _attr(svc, "name"), _attr(svc, "product"), _attr(svc, "version"),
            _attr(svc, "extrainfo"), _cpes(svc),
            seen_time, seen_time,
        ),
    )
    return True


def write_os(cur, device_id, os_name, os_family, os_gen, os_vendor,
             accuracy, cpe, source, evidence, seen_time):
    """Schreibt eine OS-Angabe.

    Die WHERE-Klausel am Ende regelt den Vorrang: ein echter Fingerprint
    ueberschreibt alles, eine aus Bannern abgeleitete Angabe aber nur eine
    andere abgeleitete. Ein Host, der heute zugefirewallt ist, letzte Woche
    aber einen sauberen Fingerprint geliefert hat, behaelt ihn deshalb --
    inklusive seines alten last_seen, das damit ehrlich sagt, wann die
    Angabe zuletzt wirklich belegt war.
    """
    cur.execute(
        """
        INSERT INTO os_matches (device_id, os_name, os_family, os_gen,
                                os_vendor, accuracy, cpe, source, evidence,
                                last_seen)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (device_id) DO UPDATE
        SET os_name   = EXCLUDED.os_name,
            os_family = EXCLUDED.os_family,
            os_gen    = EXCLUDED.os_gen,
            os_vendor = EXCLUDED.os_vendor,
            accuracy  = EXCLUDED.accuracy,
            cpe       = EXCLUDED.cpe,
            source    = EXCLUDED.source,
            evidence  = EXCLUDED.evidence,
            last_seen = EXCLUDED.last_seen
        WHERE os_matches.source = 'service'
           OR EXCLUDED.source   = 'fingerprint';
        """,
        (device_id, os_name, os_family, os_gen, os_vendor,
         accuracy, cpe, source, evidence, seen_time),
    )


def upsert_os_fingerprint(cur, device_id, host_elem, seen_time):
    """Speichert den besten OS-Fingerprint. accuracy wird bewusst mitgefuehrt:
    unter ~90 Prozent ist das Raterei und gehoert im Dashboard ausgegraut.

    Liefert False, wenn nmap keinen Treffer hatte -- dann greift der
    Banner-Fallback.
    """
    os_elem = host_elem.find("os")
    if os_elem is None:
        return False

    matches = os_elem.findall("osmatch")
    if not matches:
        return False

    best = max(matches, key=lambda m: int(m.get("accuracy") or 0))
    osclass = best.find("osclass")

    write_os(
        cur, device_id,
        os_name=_attr(best, "name"),
        os_family=_attr(osclass, "osfamily"),
        os_gen=_attr(osclass, "osgen"),
        os_vendor=_attr(osclass, "vendor"),
        accuracy=int(best.get("accuracy") or 0),
        cpe=_cpes(osclass),
        source="fingerprint",
        evidence="",
        seen_time=seen_time,
    )
    return True


def upsert_os_from_services(cur, device_id, host_elem, seen_time):
    """Fallback fuer Hosts ohne verwertbaren Fingerprint.

    Wo eine Firewall alles Nichtbenoetigte verwirft statt zurueckzuweisen,
    fehlt nmap der geschlossene Referenzport und die OS-Erkennung scheitert.
    Die Service-Erkennung laeuft aber weiter und leitet aus den Bannern ein
    ostype ab (die 'Service Info'-Zeile der Textausgabe). Weniger praezise
    als ein Fingerprint, aber oft die einzige verfuegbare Information -- und
    bei Debian-Bannern wie 'OpenSSH 10.0p2 Debian 7+deb13u4' sogar genauer.

    accuracy bleibt 0; die Unterscheidung traegt die Spalte source.
    """
    ports_elem = host_elem.find("ports")
    if ports_elem is None:
        return False

    candidates = {}

    for port_elem in ports_elem.findall("port"):
        state_elem = port_elem.find("state")
        if _attr(state_elem, "state") not in INTERESTING_STATES:
            continue

        svc = port_elem.find("service")
        ostype = _attr(svc, "ostype")
        if not ostype:
            continue

        os_cpe = next(
            (c.text for c in svc.findall("cpe")
             if c.text and c.text.startswith("cpe:/o:")),
            "",
        )

        banner = " ".join(
            x for x in (_attr(svc, "product"), _attr(svc, "version"),
                        _attr(svc, "extrainfo")) if x
        )
        evidence = f"{port_elem.get('portid')}/{_attr(svc, 'name')}: {banner}".strip()

        entry = candidates.setdefault(ostype, {"count": 0, "cpe": "", "evidence": ""})
        entry["count"] += 1
        if os_cpe and not entry["cpe"]:
            entry["cpe"] = os_cpe
        # Laengstes Banner gewinnt: es traegt in der Regel die Distribution
        if len(evidence) > len(entry["evidence"]):
            entry["evidence"] = evidence

    if not candidates:
        return False

    # Haeufigstes ostype ueber alle offenen Ports des Hosts
    ostype, data = max(candidates.items(), key=lambda kv: kv[1]["count"])

    write_os(
        cur, device_id,
        os_name=ostype,
        os_family=ostype,
        os_gen="",
        os_vendor="",
        accuracy=0,
        cpe=data["cpe"],
        source="service",
        evidence=data["evidence"],
        seen_time=seen_time,
    )
    return True


def close_stale_ports(cur, device_ids, run_start):
    """Ports, die bei einem erfolgreich gescannten Host diesmal nicht mehr
    offen waren, auf 'closed' setzen. Ohne diesen Schritt wuerde die Tabelle
    nur wachsen und laengst geschlossene Ports ewig als offen anzeigen."""
    if not device_ids:
        return 0
    cur.execute(
        """
        UPDATE ports
        SET state = 'closed'
        WHERE device_id = ANY(%s)
          AND last_seen < %s
          AND state <> 'closed';
        """,
        (list(device_ids), run_start),
    )
    return cur.rowcount


def run_deep_scan():
    try:
        conn = psycopg2.connect(**DB_PARAMS)
    except Exception as e:
        print(f"Keine Datenbankverbindung: {e}", file=sys.stderr)
        sys.exit(1)

    run_start = datetime.now(timezone.utc)
    run_id = None

    try:
        cur = conn.cursor()

        cutoff = run_start - timedelta(hours=TARGET_MAX_AGE_HOURS)
        targets = fetch_targets(cur, cutoff)

        cur.execute(
            """
            INSERT INTO deep_scan_runs (started_at, target_count)
            VALUES (%s, %s) RETURNING id;
            """,
            (run_start, len(targets)),
        )
        run_id = cur.fetchone()[0]
        conn.commit()

        if not targets:
            print("Keine Ziele gefunden - laeuft der Discovery-Scan noch?",
                  file=sys.stderr)
            sys.exit(1)

        print(f"Deep Scan gestartet um (UTC): {run_start}")
        print(f"{len(targets)} Ziele aus der Datenbank.")

        try:
            root = run_nmap(targets)
        except subprocess.CalledProcessError as e:
            print(f"nmap fehlgeschlagen: {e.stderr}", file=sys.stderr)
            sys.exit(1)
        except ET.ParseError as e:
            print(f"Ungueltige nmap-Ausgabe: {e}", file=sys.stderr)
            sys.exit(1)

        scanned_devices = set()
        port_count = 0
        fingerprint_count = 0
        banner_os_count = 0

        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue

            ipv4 = host.find("address[@addrtype='ipv4']")
            if ipv4 is None:
                continue

            device_id = targets.get(ipv4.get("addr"))
            if device_id is None:
                continue

            scanned_devices.add(device_id)

            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    if upsert_port(cur, device_id, port_elem, run_start):
                        port_count += 1

            if upsert_os_fingerprint(cur, device_id, host, run_start):
                fingerprint_count += 1
            elif upsert_os_from_services(cur, device_id, host, run_start):
                banner_os_count += 1

        closed = close_stale_ports(cur, scanned_devices, run_start)

        finished = datetime.now(timezone.utc)
        cur.execute(
            """
            UPDATE deep_scan_runs
            SET finished_at = %s, host_count = %s, port_count = %s, ok = TRUE
            WHERE id = %s;
            """,
            (finished, len(scanned_devices), port_count, run_id),
        )
        conn.commit()

        print(f"{len(scanned_devices)} Hosts, {port_count} offene Ports erfasst.")
        print(f"OS: {fingerprint_count} per Fingerprint, "
              f"{banner_os_count} aus Service-Bannern.")
        if closed:
            print(f"{closed} Ports wurden als 'closed' markiert.")
        print(f"Deep Scan beendet, Dauer: {finished - run_start}")

    except Exception as e:
        conn.rollback()
        print(f"Fehler im Deep-Scan-Skript: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        conn.close()


if __name__ == "__main__":
    run_deep_scan()
