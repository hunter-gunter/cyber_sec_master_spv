#!/bin/bash
echo "[*] Lancement de nmap_vuln.sh..."
/scripts/sys/nmap_vuln.sh

echo "[*] Lancement de wpscan.sh..."
/scripts/sys/wpscan.sh

echo "[*] Lancement de rr_flood.sh..."
/scripts/exploits/rr_flood.sh

echo "[+] Tous les scripts ont été exécutés. Vous pouvez retrouver les résultat dans le dossier scripts/sys/logs."

# Optionnel : garder le conteneur en vie pour debug
tail -f /dev/null