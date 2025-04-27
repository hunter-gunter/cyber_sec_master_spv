#!/bin/sh
# Ce script necessite un access a la socket docker

mkdir -p ./rapport

echo "Creation du rapport de vulnerabilité via trivy ..."

for image in $(grep -E '^\s*image:' docker-compose.yml | awk '{print $2}'); do
    docker run -w /app/src -v ./:/app/src:ro aquasec/trivy image $image;
done >> ./rapport/docker-compose-images-vuln.txt 2>/dev/null