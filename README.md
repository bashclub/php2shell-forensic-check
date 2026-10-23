# php2shell-forensic-check

Ein leichtgewichtiger, nicht-invasiver Bash-Triage-Scanner zur schnellen Erkennung von Angriffsspuren, Exploit-Artefakten und unvollständigen Patch-Ständen rund um die **PHP2Shell**-Schwachstellen (**CVE-2026-109618** und **CVE-2026-109619**).

Entwickelt für den automatisierten Rollout über RMM-Systeme (Tactical RMM, Datto, NinjaOne) sowie für Ad-hoc-Prüfungen auf Single- und Multi-Tenant-Linux-Servern.

---

## Funktionsumfang & Prüfschritte

Das Skript führt in Sekundenbruchteilen eine mehrstufige Vorfall- und Härtungsanalyse durch, ohne laufende Dienste zu beeinträchtigen:

1. **Runtime- & Patch-Audit (In-Memory vs. Disk):**
   * Erkennt CLI-Binaries und laufende `php-fpm`-Master- und Worker-Prozesse über `/proc/<pid>/exe`.
   * **In-Memory-Erkennung:** Schlägt Alarm, wenn Pakete zwar aktualisiert wurden, der FPM-Worker im RAM aber noch den alten Code ausführt (`(deleted)`-Marker).
   * **Sury-Backport-Validierung:** Erkennt offizielle Minimal-Backports für EOL-Versionen (PHP 7.4, 8.0, 8.1) anhand des Release-Datums (`>= 20261021`) via `dpkg-query` und Build-Header.
   * **Container-Auditing:** Iteriert Docker-Container (Mailcow, Nextcloud, WordPress etc.) und prüft PHP-Stände direkt in den Containern (ohne Fehlalarme bei PHP-freien Containern wie Redis oder Postfix).

2. **Härtungs-Check (Advisory Alignment):**
   * Liest aktive INI-Direktiven aus (`session.upload_progress.enabled`, `memory_limit`, `post_max_size`, `fatal_error_backtraces`).
   * Bewertet Konfigurationen gegen die offiziellen Empfehlungen des PHP-Security-Teams.

3. **Session-Storage & Injection-Scan:**
   * Rekursive Durchsuchung aktiver Session-Pfade (`/var/lib/php/sessions`, PHP-Save-Paths, `/tmp`, Docker-Session-Volumes).
   * Gezielte Payload-Suche nach PHP-Tags (`<?php`, `<?=`), serialisierten Objekten und manipulierten `upload_progress`-Feldern in `sess_*`-Dateien.

4. **Dateisystem- & Executable-Audit:**
   * Identifiziert neu erstellte/modifizierte PHP-Dateien in Web-Roots (`/var/www`, `/home`, Mailcow-Webroot, Piler) unter Ausschluss legitimer Cache- und Log-Pfade.
   * Scannt flüchtige Pfade (`/tmp`, `/dev/shm`, `/var/tmp`) nach unerwarteten Executables, Shared Objects (`.so`) und Skripten.

5. **Prozessbaum-Analyse:**
   * Filtert nach interaktiven Shells (`sh`, `bash`, `dash`) und Netzwerk-Tools (`curl`, `wget`, `nc`, `socat`), die von Webserver-/FPM-Benutzern (`www-data`, `nginx`, ISPConfig-Web-Usern, `clp`, Plesk-Systemkonten) gespawnt wurden.

6. **I/O-geschützte Log-Analyse:**
   * Durchsucht Access- und Error-Logs der letzten 7 Tage.
   * Erkennt FPM-Worker-Crashes, Segmentation Faults und OOM-Abbrüche (Indikatoren für Heap-Korruption bei CVE-2026-109618).
   * Identifiziert extreme POST-Anfragefluten auf PHP-Endpunkte (ASLR-Brute-Force-Muster) unter Ausschluss bekannter Tracking-/Cron-Endpunkte.

7. **Docker Rootfs Diffs:**
   * Überprüft aktive Container via `docker diff` auf Dateisystem-Mutationen im Container-Layer außerhalb persistierter Volumes.

---

## Unterstützte Umgebungen & Stacks

* **Betriebssysteme:** Debian 11 / 12 / 13, Ubuntu 20.04 / 22.04 / 24.04 (Baremetal, KVM & Proxmox LXC).
* **Control Panels & Host-Umgebungen:**
  * **ISPConfig:** Berücksichtigt dynamische User (`web[0-9]+`), Web-Roots (`/var/www/clients/...`) und CLI-Cronjobs.
  * **Plesk:** Unterstützt `psacln`/`psaserv`-User und blendet APT-GPG-Hooks (`/tmp/apt-key-gpghome.*`) aus.
  * **CloudPanel:** Audit der Host-PHP-Pools bei gleichzeitiger Möglichkeit zur Isolation des internen Panel-Backends.
* **Container-Stacks:**
  * **Mailcow (dockerized):** Scannt gezielt den `php-fpm-mailcow`-Container; toleriert IAM-Sync-Locks und interne Pipes.
  * **Nextcloud & Moodle:** Whitelisting für CLI-Cronjobs (`admin/cli/cron.php`, `occ`) und Daemon-Prozesse (`notify_push`).
  * **Piler (Mailarchiv):** Erfasst Web-UI-Roots und vermeidet Kollisionen mit Manticore-/Sphinx-Daemons.

---

## Whitelisting & False-Positive-Unterdrückung

Um "Alert Fatigue" in Monitoring-Dashboards zu verhindern, enthält der Scanner präzise Ausnahmen für legitime Dienste:

* **Daemons & Hintergrunddienste:** `notify_push` (Nextcloud), `olefy.py` (Mailcow ClamAV-Bridge), `coolwsd` / Collabora Office AppImages, Dovecot/Postfix-Binaries.
* **Cron- & Wartungs-Runner:** `admin/cli/cron.php` (Moodle), `wp-cron.php` (WordPress), Nextcloud `occ`, Laravel `artisan`, Symfony `bin/console`.
* **Lock-Dateien & Caches:** Matomo `climulti`-Caches, Mailcow `iam-sync.lock`, Systemd PrivateTmp-Verzeichnisse, Plesk/APT-Update-Artefakte.
* **Traffic-Ausnahmen:** `matomo.php` und `piwik.php` sind von Brute-Force-POST-Spike-Alarmen ausgenommen.

---

## Installation & Ausführung

### Schnellstart (Ad-hoc CLI)

```bash
# Herunterladen und Ausführungsrechte vergeben
curl -fsSL [https://raw.githubusercontent.com/dein-repo/php2shell-forensic-check/main/php2shell-forensic-check](https://raw.githubusercontent.com/dein-repo/php2shell-forensic-check/main/php2shell-forensic-check) -o php2shell-forensic-check
chmod +x php2shell-forensic-check

# Direkt ausführen (Root-Rechte erforderlich)
sudo ./php2shell-forensic-check