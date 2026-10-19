#!/usr/bin/env bash
# Build/import artifacts locally. Never uploads images to a registry.
set -euo pipefail
cd "$(dirname "$0")/.."
app_image=localhost/wazuh-security-reports-app:0.4.3
proxy_image=localhost/wazuh-security-reports-proxy:0.4.3
artifact_dir=output/containers
mkdir -p "$artifact_dir"
docker build -t "$app_image" -f Dockerfile .
docker build -t "$proxy_image" -f deploy/Dockerfile.proxy .
archive="$artifact_dir/wazuh-security-reports-0.4.3-$(docker image inspect "$app_image" --format '{{.Architecture}}').tar.gz"
temporary_archive=$(mktemp "$artifact_dir/.images.XXXXXX")
trap 'rm -f "$temporary_archive"' EXIT
docker save "$app_image" "$proxy_image" | gzip -1 > "$temporary_archive"
mv -- "$temporary_archive" "$archive"
(cd "$artifact_dir" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
printf 'Importe este arquivo em Portainer > Images > Import: %s\n' "$archive"
printf 'Use compose.portainer.yaml (80/443) ou compose.portainer.ip.yaml (8083/8443). Desative Re-pull/Always pull images.\n'
