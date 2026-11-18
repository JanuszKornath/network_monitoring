# network_monitoring

Zwei Python-Skripte, die per `nmap` konfigurierte Netzwerke scannen und die
gefundenen Geräte in einer PostgreSQL-Datenbank pflegen.

* **`nmap_scan.py`** — Discovery. Erfasst MAC, Hostname, Vendor und
  IP-Adressen. IPs, die länger als 15 Minuten nicht mehr gesehen wurden,
  werden als `down` markiert; zusätzlich wird pro Lauf ein Historie-Snapshot
  der Online-Geräte geschrieben. Läuft in kurzen Intervallen.
* **`nmap_deep_scan.py`** — Bestandsaufnahme. Nimmt die zuletzt online
  gesehenen Hosts *aus der Datenbank* und scannt nur diese, dafür mit Port-,
  Service- und OS-Erkennung. Läuft einmal nachts.

Die Trennung ist Absicht: ein Discovery-Sweep ist in Sekunden durch, ein
Scan mit `-sS -sV -O` braucht Minuten. Beides im selben Job würde entweder
den Takt sprengen oder die Tiefe kosten.

## Voraussetzungen

* Python 3 mit `psycopg2` (`pip install psycopg2-binary`)
* `nmap` (für MAC-Erkennung im lokalen Netz mit Root-Rechten ausführen)
* PostgreSQL — das vollständige Schema liegt in
  [`sql/schema.sql`](sql/schema.sql)
* Optional `fritzconnection` für die TR-064-Zusatzquelle
  (`pip install fritzconnection`)

### Datenbank einrichten

```
createdb nmapdb
psql nmapdb -c "CREATE USER nmapuser WITH PASSWORD 'geheimes-passwort';"
psql nmapdb -f sql/schema.sql
```

`sql/schema.sql` lässt sich gefahrlos mehrfach einspielen: fehlende
Tabellen und Indizes werden angelegt, bestehende bleiben unberührt. Fehlende
Spalten in bestehenden Tabellen ergänzt `CREATE TABLE IF NOT EXISTS` dagegen
nicht; das Schema enthält dafür nur für `os_matches.source` und
`os_matches.evidence` ein `ALTER TABLE … ADD COLUMN IF NOT EXISTS`. Kommen
später weitere Spalten hinzu, brauchen sie eine eigene solche Anweisung.

Die Datenbank muss auf UTC stehen. Beide Skripte schreiben zeitzonenbewusste
UTC-Werte in `timestamp`-Spalten ohne Zeitzone; PostgreSQL castet die anhand
der Session-Zeitzone. Prüfen mit `SHOW timezone;`.

## Konfiguration

Die Datenbankverbindung wird über Umgebungsvariablen konfiguriert. **Das
Passwort steht nicht im Code** und muss auf einem der beiden folgenden Wege
mitgegeben werden.

### Variante 1: Umgebungsvariablen

| Variable          | Default     | Beschreibung      |
| ----------------- | ----------- | ----------------- |
| `NMAPDB_HOST`     | `localhost` | Datenbank-Host    |
| `NMAPDB_NAME`     | `nmapdb`    | Datenbankname     |
| `NMAPDB_USER`     | `nmapuser`  | Datenbankbenutzer |
| `NMAPDB_PASSWORD` | *(keiner)*  | Datenbankpasswort |

```
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

## FritzBox als Zusatzquelle (TR-064)

Netze, die per Firewall isoliert sind, sieht `nmap` nicht — das klassische
Beispiel ist das FritzBox-Gastnetz, in das die Box keinen Verkehr aus dem
Heimnetz durchlässt. Die FritzBox selbst kennt ihre Clients aber alle.

`nmap_scan.py` fragt deshalb optional die Host-Liste per TR-064 ab und
übernimmt jedes aktive Gerät, dessen IP in eines der `TARGET_NETS` fällt.
Die Deduplizierung läuft über die MAC-Adresse, ein echter von `nmap`
ermittelter Vendor wird dabei nie vom generischen `unknown (TR-064)`
überschrieben.

| Variable         | Default           | Beschreibung                    |
| ---------------- | ----------------- | ------------------------------- |
| `FRITZ_ADDRESS`  | `192.168.178.1`   | Adresse der FritzBox            |
| `FRITZ_USER`     | `nmapscan`        | TR-064-Benutzer                 |
| `FRITZ_PASSWORD` | *(keiner)*        | Passwort dieses Benutzers       |

Die Quelle aktiviert sich automatisch, sobald `FRITZ_PASSWORD` gesetzt ist;
ohne die Variable läuft das Skript als reines nmap-Skript. Voraussetzung ist,
dass TR-064 in der FritzBox aktiviert ist und ein eigener Benutzer dafür
angelegt wurde.

Die Variablen werden wie bei der Datenbank als Umgebungsvariablen
mitgegeben, z. B. beim manuellen Aufruf:

```bash
export FRITZ_PASSWORD='fritzbox-passwort'
# Nur nötig, wenn die Defaults nicht passen:
export FRITZ_ADDRESS='192.168.178.1'
export FRITZ_USER='nmapscan'
python3 nmap_scan.py
```

Die Herkunft eines Geräts (nmap oder TR-064) wird nicht gespeichert. Der
Deep Scan überspringt deshalb nur, was in `EXCLUDE_NETS` oder
`EXCLUDE_HOSTS` steht (siehe [Deep Scan](#deep-scan)); für das Gastnetz
`192.168.179.0/24` ist das voreingestellt. Ein Gerät, das nur per TR-064
sichtbar ist, aber in einem gescannten Netz liegt, wird trotzdem tief
gescannt; liefert nmap dafür nichts, bleibt es ohne Ports und OS-Angabe.

## Gescannte Netze und Offline-Schwelle

Die Zielnetze (`TARGET_NETS`) und die Offline-Schwelle
(`OFFLINE_THRESHOLD_MINUTES`, Standard: 15 Minuten) werden direkt am Anfang
von `nmap_scan.py` konfiguriert. `TARGET_NETS` ist die einzige Liste, die
gepflegt werden muss — eine Unterscheidung nach Gast- oder
FritzBox-verwalteten Netzen ist nicht nötig.

## Deep Scan

`nmap_deep_scan.py` scannt keine Netze, sondern Hosts: es holt alle IPs mit
`state = 'up'` aus den letzten `TARGET_MAX_AGE_HOURS` Stunden aus der
Datenbank und übergibt genau diese an `nmap`. Damit entfallen die rund 200
toten Adressen eines /24.

### Konfiguration

Am Anfang von `nmap_deep_scan.py`:

| Konstante              | Bedeutung                                                |
| ---------------------- | -------------------------------------------------------- |
| `EXCLUDE_NETS`         | Netze, die nicht erreichbar sind (z. B. das Gastnetz)     |
| `EXCLUDE_HOSTS`        | Einzelne IPs überspringen                                 |
| `TARGET_MAX_AGE_HOURS` | Wie weit zurück ein Host online gewesen sein darf         |
| `EXCLUDE_PORTS`        | Ports, die der Version-Scan nicht anfasst                 |
| `NMAP_OPTS`            | Die nmap-Aufrufparameter                                  |

`EXCLUDE_PORTS` steht standardmäßig auf `9100`. Netzwerkdrucker antworten auf
Banner-Probes an diesem RAW/JetDirect-Port gern mit einer ausgedruckten Seite
Zeichensalat.

### Was erfasst wird

**Ports** landen in `ports`, ein Eintrag pro Gerät, Port und Protokoll.
`first_seen` und `last_seen` machen die Historie auswertbar — ein Port, der
heute offen ist und gestern nicht, ist die eigentlich interessante Information.
Ports, die bei einem erfolgreich gescannten Host nicht mehr offen sind, werden
auf `state = 'closed'` gesetzt statt gelöscht. Hosts, die beim Lauf offline
waren, bleiben unangetastet.

**Das Betriebssystem** landet in `os_matches`, mit zwei möglichen Herkünften:

* `source = 'fingerprint'` — echter nmap-OS-Fingerprint. `accuracy` ist
  aussagekräftig; unter etwa 90 Prozent ist die Angabe unsicher.
* `source = 'service'` — aus den Service-Bannern abgeleitet, `accuracy = 0`.

Der zweite Fall greift, wo eine Firewall alles Nichtbenötigte verwirft statt
zurückzuweisen: `nmap` fehlt dann der geschlossene Referenzport und die
OS-Erkennung scheitert, auch mit `--osscan-guess`. Die Service-Erkennung läuft
aber weiter und leitet aus den Bannern ein `ostype` ab. Weniger präzise als
ein Fingerprint — bei Bannern wie `OpenSSH 10.0p2 Debian 7+deb13u4` dafür
genauer, weil sie die Distribution direkt nennen. Das ausgewertete Banner
steht in `evidence`.

Ein Fingerprint überschreibt immer eine abgeleitete Angabe, umgekehrt nie. Ein
Host, der heute zugefirewallt ist, letzte Woche aber einen sauberen
Fingerprint geliefert hat, behält ihn — samt seines alten `last_seen`, das
damit sagt, wann die Angabe zuletzt wirklich belegt war.

**Jeder Lauf** wird in `deep_scan_runs` protokolliert. Ein ausgefallener
nächtlicher Job fällt sonst erst auf, wenn die Daten alt sind.

## Installation

Cron und systemd erwarten die Skripte unter `/usr/local/bin` und die
Zugangsdaten in `/etc/nmap_scan.env`:

```bash
install -m 755 nmap_scan.py nmap_deep_scan.py /usr/local/bin/
install -m 600 -o root -g root /dev/null /etc/nmap_scan.env
```

Danach `/etc/nmap_scan.env` mit den Variablen aus
[Konfiguration](#konfiguration) und [FritzBox](#fritzbox-als-zusatzquelle-tr-064)
füllen, z. B.:

```
NMAPDB_PASSWORD='geheimes-passwort'
FRITZ_PASSWORD='fritzbox-passwort'
```

## Cron

Beide Skripte brauchen Root. `nmap_scan.py` benötigt es für die
ARP/MAC-Erkennung im lokalen Netz und die SYN-Pings (`-PS`), der Deep Scan
für `-sS` und `-O`. Das sind Raw-Socket-Operationen; ohne Root fällt `nmap`
still auf einen TCP-Connect-Scan ohne MAC- und OS-Erkennung zurück.

```
MAILTO=""

# Discovery, alle 15 Minuten
*/15 * * * * /bin/sh -c 'set -a; . /etc/nmap_scan.env; set +a; /usr/bin/python3 /usr/local/bin/nmap_scan.py' >> /var/log/nmap_scan.log 2>&1

# Deep Scan, nachts
7 3 * * * /bin/sh -c 'set -a; . /etc/nmap_scan.env; set +a; /usr/bin/python3 /usr/local/bin/nmap_deep_scan.py' >> /var/log/nmap_deep_scan.log 2>&1
```

Drei Fallstricke, jeder davon schon einmal aufgetreten:

**`set -a` ist Pflicht.** Ohne exportiert `.` die Variablen nicht an den
Python-Prozess, die Datenbankverbindung scheitert und Cron schluckt es
kommentarlos. Ein `. /etc/nmap_scan.env && python3 …` reicht nicht.

**Nicht nach `/dev/null` umleiten.** Sonst merkt man einen Fehlschlag am
Ausbleiben der Daten statt an der Ursache.

**Die Startzeiten nicht kollidieren lassen.** Der Deep Scan braucht einige
Minuten; startet er zur vollen Stunde, läuft ein Discovery-Scan gleichzeitig
gegen dieselben Hosts.

Die Umgebungsdatei `/etc/nmap_scan.env` (Modus `0600`) enthält die
Datenbank- und FritzBox-Zugangsdaten. Werte mit Shell-Sonderzeichen gehören
dort in einfache Anführungszeichen.

Bei Betrieb als systemd-Timer entfällt das Sourcen — dort genügt im
`[Service]`-Block:

```ini
EnvironmentFile=/etc/nmap_scan.env
ExecStart=/usr/bin/python3 /usr/local/bin/nmap_scan.py
```

## Fehlerverhalten

Beide Skripte beenden sich bei Fehlern mit Exit-Code 1, sodass Cron und
Monitoring Fehlschläge erkennen können. Das gilt auch, wenn

* bei `nmap_scan.py` nur einzelne Netze oder nur die FritzBox-Abfrage
  (TR-064) fehlgeschlagen sind,
* `nmap_deep_scan.py` keine Ziele in der Datenbank findet (läuft der
  Discovery-Scan?).

Ein abgebrochener Deep Scan bleibt in `deep_scan_runs` mit `ok = FALSE`
stehen, bekommt aber ein `finished_at`. Ein Eintrag mit `finished_at IS
NULL` ist damit ein Lauf, der gerade läuft (oder dessen Prozess hart
beendet wurde).
