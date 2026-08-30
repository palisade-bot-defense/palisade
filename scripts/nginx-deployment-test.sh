#!/bin/sh
set -eu

repository_root=$(git rev-parse --show-toplevel)
cd "$repository_root"

nginx_image='nginx@sha256:db35bfc6b2951e7f8a72db5db120288c127ffaeeb4a6d4b95a26fead017d5913'
compose_file='deployments/nginx/compose.yaml'

if [ "${1:-}" = "--plan" ]; then
	[ "$#" -eq 1 ] || {
		echo "nginx-deployment-test: --plan accepts no additional arguments" >&2
		exit 2
	}
	printf '%s\n' '{"schema_version":"palisade.nginx-deployment-plan.v1","synthetic_only":true,"raw_deployment_records_used":false,"network_scope":"internal_docker_network_only","host_ports_published":false,"proxy_image":"nginx@sha256:db35bfc6b2951e7f8a72db5db120288c127ffaeeb4a6d4b95a26fead017d5913","profiles":["trusted_nginx_http2_tls","direct_header_spoof"],"limitations":["single local Docker engine and one pinned nginx build","ephemeral self-signed fixture certificate; not public PKI","nginx to origin uses HTTP/1.1 on an internal synthetic network","not a CDN, HTTP/3, multi-replica, capacity or detection-efficacy claim"]}'
	exit 0
fi

[ "$#" -eq 0 ] || {
	echo "usage: scripts/nginx-deployment-test.sh [--plan]" >&2
	exit 2
}

command -v docker >/dev/null 2>&1 || {
	echo "nginx-deployment-test: docker is required" >&2
	exit 1
}
docker compose version >/dev/null 2>&1 || {
	echo "nginx-deployment-test: docker compose v2 is required" >&2
	exit 1
}
docker image inspect "$nginx_image" >/dev/null 2>&1 || {
	echo "nginx-deployment-test: pinned nginx image is absent; pull the exact digest explicitly before running" >&2
	exit 1
}

project="palisade-nginx-test-$$"
cleanup() {
	docker compose --project-name "$project" --file "$compose_file" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

docker compose --project-name "$project" --file "$compose_file" config --quiet
docker compose --project-name "$project" --file "$compose_file" up \
	--build --pull never --abort-on-container-exit --exit-code-from verifier
