-- network_monitoring: vollstaendiges Datenbankschema
--
-- Idempotent: laesst sich auf einer leeren Datenbank genauso einspielen wie
-- auf einer bestehenden Installation. Bestehende Tabellen bleiben unberuehrt,
-- fehlende Spalten werden ergaenzt.
--
--   createdb nmapdb
--   psql nmapdb -f sql/schema.sql
--
-- Zeittyp ist durchgaengig 'timestamp without time zone'. Beide Skripte
-- schreiben zeitzonenbewusste UTC-Werte, die PostgreSQL beim Insert anhand
-- der Session-Zeitzone castet -- die Datenbank muss deshalb auf UTC stehen:
--
--   SHOW timezone;    -- erwartet: UTC oder Etc/UTC

-- ===========================================================================
-- Discovery (nmap_scan.py)
-- ===========================================================================

-- Ein Geraet, identifiziert ueber seine MAC-Adresse. Die MAC ist der stabile
-- Anker: IP-Adressen und Hostnamen aendern sich, die MAC bleibt. Geraete ohne
-- erreichbare MAC (L3-Hops, Localhost) bekommen den Platzhalter 'IP-<adresse>'.
CREATE TABLE IF NOT EXISTS devices (
    id         SERIAL    PRIMARY KEY,
    mac        TEXT      NOT NULL UNIQUE,
    hostname   TEXT,
    vendor     TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Ein Geraet kann mehrere IPs haben (mehrere Netze, VPN, Adresswechsel).
-- state ist 'up' oder 'down'; die Offline-Bereinigung setzt 'down', wenn eine
-- IP laenger als OFFLINE_THRESHOLD_MINUTES nicht mehr gesehen wurde.
CREATE TABLE IF NOT EXISTS ip_addresses (
    id         SERIAL    PRIMARY KEY,
    device_id  INTEGER   REFERENCES devices(id) ON DELETE CASCADE,
    ip         INET      NOT NULL,
    state      TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (device_id, ip)
);

-- Ein Zaehlerstand pro Discovery-Lauf, fuer den Zeitverlauf im Dashboard.
CREATE TABLE IF NOT EXISTS nmap_history (
    "time"       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    online_count INTEGER
);

-- ===========================================================================
-- Deep Scan (nmap_deep_scan.py)
-- ===========================================================================

-- Offene Ports und die darauf erkannten Dienste, ein Eintrag pro Geraet,
-- Port und Protokoll.
--
-- first_seen traegt den eigentlichen Mehrwert: ein Port, der heute offen ist
-- und gestern nicht, ist die sicherheitsrelevante Information -- eine reine
-- Portliste ist nur Inventar.
--
-- Ports, die bei einem erfolgreich gescannten Host nicht mehr offen sind,
-- bekommen state = 'closed' statt geloescht zu werden. Hosts, die beim Lauf
-- offline waren, bleiben unangetastet.
CREATE TABLE IF NOT EXISTS ports (
    device_id  INTEGER   NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    port       INTEGER   NOT NULL,
    protocol   TEXT      NOT NULL,
    state      TEXT      NOT NULL DEFAULT 'open',
    service    TEXT      NOT NULL DEFAULT '',
    product    TEXT      NOT NULL DEFAULT '',
    version    TEXT      NOT NULL DEFAULT '',
    extrainfo  TEXT      NOT NULL DEFAULT '',
    cpe        TEXT      NOT NULL DEFAULT '',
    first_seen TIMESTAMP NOT NULL,
    last_seen  TIMESTAMP NOT NULL,
    PRIMARY KEY (device_id, port, protocol)
);

CREATE INDEX IF NOT EXISTS ports_first_seen_idx ON ports (first_seen DESC);
CREATE INDEX IF NOT EXISTS ports_last_seen_idx  ON ports (last_seen DESC);
CREATE INDEX IF NOT EXISTS ports_state_idx      ON ports (state);

-- Erkanntes Betriebssystem, ein Eintrag pro Geraet.
CREATE TABLE IF NOT EXISTS os_matches (
    device_id INTEGER   PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    os_name   TEXT      NOT NULL DEFAULT '',
    os_family TEXT      NOT NULL DEFAULT '',
    os_gen    TEXT      NOT NULL DEFAULT '',
    os_vendor TEXT      NOT NULL DEFAULT '',
    accuracy  INTEGER   NOT NULL DEFAULT 0,
    cpe       TEXT      NOT NULL DEFAULT '',
    last_seen TIMESTAMP NOT NULL
);

-- Herkunft der OS-Angabe:
--   'fingerprint' -> echter nmap-OS-Fingerprint, accuracy aussagekraeftig
--   'service'     -> aus den Service-Bannern abgeleitet, accuracy = 0
--
-- evidence haelt das Banner, auf dem eine abgeleitete Angabe beruht, damit
-- im Dashboard nachvollziehbar bleibt, worauf sie sich stuetzt -- statt eine
-- Vermutung als Tatsache anzuzeigen.
ALTER TABLE os_matches
    ADD COLUMN IF NOT EXISTS source   TEXT NOT NULL DEFAULT 'fingerprint';
ALTER TABLE os_matches
    ADD COLUMN IF NOT EXISTS evidence TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS os_matches_source_idx ON os_matches (source);

-- Lauf-Protokoll des Deep Scans.
--
-- Ein ausgefallener 15-Minuten-Job faellt schnell auf, ein naechtlicher nicht.
-- Diese Tabelle macht im Dashboard sichtbar, ob der Deep Scan noch laeuft.
CREATE TABLE IF NOT EXISTS deep_scan_runs (
    id           BIGSERIAL PRIMARY KEY,
    started_at   TIMESTAMP NOT NULL,
    finished_at  TIMESTAMP,
    target_count INTEGER   NOT NULL DEFAULT 0,
    host_count   INTEGER   NOT NULL DEFAULT 0,
    port_count   INTEGER   NOT NULL DEFAULT 0,
    ok           BOOLEAN   NOT NULL DEFAULT FALSE
);

-- ===========================================================================
-- Rechte fuer den Skript-Benutzer
--
-- Der Benutzer wird vorher angelegt:
--   CREATE USER nmapuser WITH PASSWORD 'geheimes-passwort';
-- ===========================================================================

GRANT SELECT, INSERT, UPDATE
    ON devices, ip_addresses, nmap_history, ports, os_matches, deep_scan_runs
    TO nmapuser;

GRANT USAGE, SELECT ON SEQUENCE
    devices_id_seq, ip_addresses_id_seq, deep_scan_runs_id_seq
    TO nmapuser;
