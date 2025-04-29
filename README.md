# Cours Pentest Docker Dynamique : Sécurisation et Exploitation Avancées
## Résultat
### Le projet mener est le suivant : 
Conteneur apache-waf comprenant la dernière verion d'apache et un WAF (modsecurity) activable dans la variable d'environnement MODSEC_RULE_ENGINE ("on" pour activer le WAF "off" pour le désactiver), le modsecurity est désactivé dans le fichier docker-compose.yaml mais il est à activer pour voir la différence avec et sans le WAF au niveau de l'examen des failles de sécurité.
Un Conteneur Fail2Ban qui va tout simplement DROP l'IP qui spam au bout de 20 requêtes par secondes pour une durée de 1 minutes (pour des raisons de tests)
La partie la plus intéressante est le conteneur Damn Vulnerable Wordpress fait par https://github.com/vavkamil/dvwp où ce docker à plusieurs vulnérabilités ainsi que des fichiers habituellements utilisé pour accéder à la BDD depuis le site web ce qui ouvre à des failles de sécurité, toutes les infos de vulnérabillités sont sur son github. Ce conteneur est "répliqué" 5 fois pour supporter la charge et ne pas avoir d'interruption et donc avoir du load balancing.
Enfin il y a le conteneur attaquant basé sur kali linux avec quelques scripts démarré automatiquement lorsque le conteneur est démarré.

## Ce qu'il faut faire pour le premier démarrage des conteneurs
Après avoir fait la commande `docker compose up -d --build` il faut faire la commande `docker-compose run --rm wp-cli install-wp` afin que la wordpress soit correctement installé. Il ne devrait pas y avoir d'erreur, s'il y en a, c'est sûrement dû à des problèmes de droits sur les fichiers qu'il faut corriger (même si ce n'est pas idéal, faire un `chmod 777` pour ne pas se casser la tête)
On peut redémarrer le conteneur attaquant pour redémarrer les scripts automatisés de la kali linux

## Ce qu'il se passe lors du démarrage du conteneur Kali
### Plusieurs scripts seront démarrer :
- /scripts/sys/nmap_vuln.sh     | Pour la recherche de CVE avec nmap
- /scripts/sys/wpscan.sh        | Pour scanner les informations du Wordpress
- /scripts/exploits/rr_flood.sh | Pour simuler une grande vague de DDoS de 20 000requêtes par secondes ce qui va déclancher Fail2Ban et bloquer l'IP pendant une durée de 60 secondes 