#!/bin/sh
# Ce script necessite un access a la socket docker

echo "Lancement de l'analyse de faille et indice des containers deployer ..." 

docker run -it --net host --pid host --userns host --cap-add audit_control \
    -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
    -v /etc:/etc:ro \
    -v /usr/bin/containerd:/usr/bin/containerd:ro \
    -v /usr/bin/runc:/usr/bin/runc:ro \
    -v /usr/lib/systemd:/usr/lib/systemd:ro \
    -v /var/lib:/var/lib:ro \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    --label docker_bench_security \
    docker/docker-bench-security >> ./rapport/running-container-vuln.txt 2>/dev/null

echo "Fichier generer: rapport/running-container-vuln.txt"