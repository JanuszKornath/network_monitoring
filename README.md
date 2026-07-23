# network_monitoring

Ein Python-Skript, das per `nmap` konfigurierte Netzwerke scannt und die
gefundenen Geräte (MAC, Hostname, Vendor, IP-Adressen) in einer
PostgreSQL-Datenbank pflegt. Optional wird zusätzlich die Host-Liste einer
FritzBox per TR-064 abgefragt, um auch Geräte zu erfassen, die nmap nicht
erreichen kann (z. B. im firewall-isolierten Gastnetz). IPs, die länger als
15 Minuten nicht mehr gesehen wurden, werden als `down` markiert; zusätzlich
wird pro Lauf ein Historie-Snapshot der Online-Geräte geschrieben.

## Voraussetzungen

- Python 3 mit `psycopg2` (`pip install psycopg2-binary`)
- `nmap` (für MAC-Erkennung im lokalen Netz mit Root-Rechten ausführen)
- PostgreSQL mit den Tabellen `devices`, `ip_addresses` und `nmap_history`
- Optional: `fritzconnection` (`pip install fritzconnection`) — nur nötig,
  wenn die FritzBox-Abfrage per TR-064 genutzt wird

## Konfiguration

Die Datenbankverbindung wird über Umgebungsvariablen konfiguriert.
**Das Passwort steht nicht mehr im Code** und muss auf einem der beiden
folgenden Wege mitgegeben werden.

### Variante 1: Umgebungsvariablen

| Variable          | Default     | Beschreibung        |
|-------------------|-------------|---------------------|
| `NMAPDB_HOST`     | `localhost` | Datenbank-Host      |
| `NMAPDB_NAME`     | `nmapdb`    | Datenbankname       |
| `NMAPDB_USER`     | `nmapuser`  | Datenbankbenutzer   |
| `NMAPDB_PASSWORD` | *(keiner)*  | Datenbankpasswort   |

```bash
export NMAPDB_PASSWORD='geheimes-passwort'
python3 nmap_scan.py
```

### Variante 2: `~/.pgpass`

Ist `NMAPDB_PASSWORD` nicht gesetzt, greifen die libpq-Standardmechanismen,
z. B. die Passwortdatei `~/.pgpass` des Benutzers, der das Skript ausführt:

```
# Format: host:port:datenbank:benutzer:passwort
localhost:5432:nmapdb:nmapuser:geheimes-passwort
```

Die Datei muss auf Modus `0600` stehen (`chmod 600 ~/.pgpass`), sonst
ignoriert libpq sie. Auch die Standardvariable `PGPASSWORD` funktioniert.

### Beispiel: Cron mit systemd oder crontab

Bei Cron-Betrieb die Variable in der Crontab bzw. Unit setzen — oder
`~/.pgpass` des Cron-Benutzers verwenden, dann ist keine Variable nötig:

```cron
NMAPDB_PASSWORD=geheimes-passwort
*/5 * * * * /usr/bin/python3 /pfad/zu/nmap_scan.py
```

Das Skript beendet sich bei Fehlern (auch bei einzelnen fehlgeschlagenen
Netzen oder einer fehlgeschlagenen FritzBox-Abfrage) mit Exit-Code 1,
sodass Cron/Monitoring Fehlschläge erkennen kann.

## Optionale Zusatzquelle: FritzBox (TR-064)

Zusätzlich zu den nmap-Scans kann das Skript die Host-Liste einer FritzBox
per TR-064 abfragen. Das ist nützlich für Netze, die per Firewall isoliert
sind (z. B. das Gastnetz) und in denen nmap deshalb nichts sieht.

Die Abfrage aktiviert sich automatisch, sobald `FRITZ_PASSWORD` gesetzt
ist; ohne die Variable läuft das Skript als reines nmap-Skript.

| Variable         | Default         | Beschreibung                        |
|------------------|-----------------|-------------------------------------|
| `FRITZ_ADDRESS`  | `192.168.178.1` | Adresse der FritzBox                |
| `FRITZ_USER`     | `nmapscan`      | FritzBox-Benutzer für TR-064        |
| `FRITZ_PASSWORD` | *(keiner)*      | Passwort; aktiviert die Abfrage     |

Übernommen wird jedes aktive Gerät, dessen IP in eines der `TARGET_NETS`
fällt. Doppelte Treffer mit nmap sind unkritisch: Die Ergebnisse werden
über die MAC-Adresse dedupliziert. Für Geräte, die nur per TR-064 gesehen
wurden, wird der Vendor als `unknown (TR-064)` eingetragen und später
durch echte nmap-Daten überschrieben, sobald verfügbar.

## Gescannte Netze und Offline-Schwelle

Die Zielnetze (`TARGET_NETS`) und die Offline-Schwelle
(`OFFLINE_THRESHOLD_MINUTES`, Standard: 15 Minuten) werden direkt am
Anfang von `nmap_scan.py` konfiguriert.
