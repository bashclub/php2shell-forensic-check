# php2shell-forensic-check

Schneller, nicht-invasiver Triage-Scanner zur Erkennung von Angriffsspuren und Artefakten rund um die PHP2Shell-Sicherheitslücken (**CVE-2026-109618** & **CVE-2026-109619**).

* **Unterstützte Umgebungen:** Debian/Ubuntu (Baremetal & LXC), Docker Stacks (Mailcow, Nextcloud, Piler, ISPConfig, CloudPanel).
* **RMM-kompatibel:** Saubere Exit-Codes (`0` = OK, `1` = Critical) und Whitelisting für Standard-Daemons (`notify_push`, `olefy`, Dovecot).
* **Fokus:** Session-Injections, ASLR-Brute-Force-Muster in Access-Logs, OOM/FPM-Crashes, flüchtige Binaries (`/tmp`, `/dev/shm`) und RootFS-Diffs.