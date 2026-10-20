#!/usr/bin/env bash
# Run from a clone of the private repository on the target Ubuntu host.
set -Eeuo pipefail
umask 077
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

usage() {
    cat <<'HELP'
Usage: ./deploy/deploy_ubuntu.sh [options]
  --install-docker       Install Docker Engine and Compose from Docker's APT repo
  --host HOST            Application IP or DNS (no scheme or port)
  --indexer URL          Indexer HTTPS URL (https://IP:port)
  --username USER        Create/reset a portal account (password prompted securely)
  --admin                Administrator account; all customers by default
  --customer CUSTOMER    Authorize this exact customer; may be repeated
  --all, --all-customers Explicitly authorize every customer for this account
  --skip-account         Update services without creating/resetting an account
  --help                Show this help

Existing .env values and project 'reports' volumes are preserved on reruns.
An account is prompted on each run unless --skip-account is specified.
Ports: HTTP 8083 redirects to HTTPS 8443. No passwords in command arguments.
Set INDEXER_USER and INDEXER_PASSWORD in .env before deployment.
HELP
}
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
install_docker=0 skip_account=0 all_customers=0 admin=0
report_host='' indexer_urls='' username=''
customers=()
while (($#)); do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --install-docker) install_docker=1; shift ;;
        --skip-account) skip_account=1; shift ;;
        --all|--all-customers) all_customers=1; shift ;;
        --admin) admin=1; shift ;;
        --host|--indexer|--username|--customer)
            (($# >= 2)) && [[ -n $2 && $2 != --* ]] || die "Missing value for $1"
            case "$1" in
                --host) report_host=$2 ;;
                --indexer) indexer_urls=$2 ;;
                --username) username=$2 ;;
                --customer) customers+=("$2") ;;
            esac
            shift 2 ;;
        *) die "Unknown option: $1 (see --help)" ;;
    esac
done
(( !all_customers || ${#customers[@]} == 0 )) || die 'Choose --customer or --all-customers.'
(( !admin || ${#customers[@]} == 0 )) || die 'Administrators have access to all customers; omit --customer.'
if ((skip_account)) && [[ -n $username || ${#customers[@]} -gt 0 || $all_customers == 1 || $admin == 1 ]]; then
    die '--skip-account cannot be combined with account options.'
fi
[[ -r /etc/os-release ]] || die 'Cannot identify operating system.'
# shellcheck disable=SC1091
. /etc/os-release
[[ ${ID:-} == ubuntu ]] || die 'This deployment script requires Ubuntu.'
sudo_cmd=()
if ((EUID != 0)); then
    command -v sudo >/dev/null || die 'sudo is required for installation or Docker access.'
    sudo_cmd=(sudo)
fi

if ((install_docker)); then
    # Never silently uninstall an existing container runtime or conflicting packages.
    conflicts=()
    for package in docker.io docker-compose docker-compose-v2 docker-doc docker-buildx podman-docker containerd runc; do
        if [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true) == 'install ok installed' ]]; then
            conflicts+=("$package")
        fi
    done
    ((${#conflicts[@]} == 0)) || die "Conflicting packages: ${conflicts[*]}. Review the Docker Ubuntu installation guide before replacing them."
    codename=${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}
    [[ $codename =~ ^[a-z]+$ ]] || die 'Cannot identify Ubuntu codename.'
    "${sudo_cmd[@]}" apt-get update
    "${sudo_cmd[@]}" apt-get install -y ca-certificates curl python3
    "${sudo_cmd[@]}" install -m 0755 -d /etc/apt/keyrings
    "${sudo_cmd[@]}" curl --fail --silent --show-error --location https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    "${sudo_cmd[@]}" chmod a+r /etc/apt/keyrings/docker.asc
    "${sudo_cmd[@]}" tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $codename
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
    "${sudo_cmd[@]}" apt-get update
    "${sudo_cmd[@]}" apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    "${sudo_cmd[@]}" systemctl enable --now docker
fi
command -v python3 >/dev/null || die 'Install python3 first (sudo apt-get install python3).'
command -v docker >/dev/null || die 'Docker is missing. Rerun with --install-docker.'
docker_cmd=(docker)
if ! docker info >/dev/null 2>&1; then
    docker_cmd=("${sudo_cmd[@]}" docker)
    "${docker_cmd[@]}" info >/dev/null || die 'Docker Engine is unavailable. Check systemctl status docker.'
fi
"${docker_cmd[@]}" compose version >/dev/null || die 'Docker Compose plugin is missing. Install docker-compose-plugin.'
"${docker_cmd[@]}" compose up --help | grep -q -- '--wait-timeout' || die 'Update the Compose plugin: --wait-timeout is required.'

# Read only the two simple settings; never source a deployment .env as shell code.
env_value() {
    python3 - "$1" <<'PY'
import pathlib, sys
path = pathlib.Path('.env')
if path.exists():
    for line in path.read_text().splitlines():
        key, sep, value = line.partition('=')
        if sep and key.strip() == sys.argv[1]:
            print(value.strip().strip('\"\''))
            break
PY
}
report_host=${report_host:-$(env_value REPORT_DOMAIN)}
if [[ -z $indexer_urls ]]; then
    configured_ip=$(env_value INDEXER_IP)
    configured_port=$(env_value INDEXER_PORT)
    if [[ -n $configured_ip ]]; then
        # Bracket IPv6 when constructing a URL for validation.
        [[ $configured_ip != *:* ]] || configured_ip="[$configured_ip]"
        indexer_urls="https://$configured_ip:${configured_port:-9200}"
    fi
fi
prompt() {
    [[ -t 0 ]] || die "Missing $1; provide the corresponding flag for noninteractive use."
    read -r -p "$1: " "$2"
}
[[ -n $report_host ]] || prompt 'Application IP or DNS' report_host
[[ -n $indexer_urls ]] || prompt 'Indexer HTTPS URL (https://IP:port)' indexer_urls

python3 - "$report_host" "$indexer_urls" <<'PY'
import ipaddress, os, pathlib, re, sys, tempfile
from urllib.parse import urlsplit
host, endpoints = sys.argv[1:]
# IPv4 or DNS; the existing Compose origin/Host configuration expects no IPv6 brackets.
if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?', host):
    sys.exit('Invalid application host: use an IPv4 address or DNS name without protocol/port.')
try:
    ipaddress.IPv4Address(host)
except ValueError:
    if re.fullmatch(r'[0-9.]+', host) or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in host.split('.')):
        sys.exit('Invalid application IP or DNS name.')
urls = [endpoints]
for endpoint in urls:
    try:
        url = urlsplit(endpoint)
        ipaddress.ip_address(url.hostname)
        valid = (url.scheme == 'https' and url.port is not None and 1 <= url.port <= 65535
                 and not url.username and not url.password and not url.path
                 and not url.query and not url.fragment and not re.search(r'\s|[,$#\'"\\]', endpoint))
    except (ValueError, TypeError):
        valid = False
    if not valid:
        sys.exit('Invalid indexer URL: expected one https://IP:port, without credentials.')
path = pathlib.Path('.env')
if path.is_symlink():
    sys.exit('Refusing to replace a symlink at .env.')
text = path.read_text() if path.exists() else pathlib.Path('deploy/env.example').read_text()
for key, value in {'REPORT_DOMAIN': host, 'INDEXER_IP': url.hostname, 'INDEXER_PORT': str(url.port)}.items():
    pattern = rf'(?m)^{key}=.*$'
    text = re.sub(pattern, f'{key}={value}', text) if re.search(pattern, text) else text.rstrip() + f'\n{key}={value}\n'
fd, temporary = tempfile.mkstemp(prefix='.env.deploy-', dir='.')
try:
    with os.fdopen(fd, 'w') as stream:
        stream.write(text)
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY

# These values must match the validated file even if the caller exported old ones.
export REPORT_DOMAIN="$report_host" INDEXER_IP="$(env_value INDEXER_IP)" INDEXER_PORT="$(env_value INDEXER_PORT)"
# Pin the files/project even if the caller has COMPOSE_FILE or COMPOSE_PROJECT_NAME set.
compose=("${docker_cmd[@]}" compose --project-directory "$ROOT" --env-file "$ROOT/.env" -f "$ROOT/compose.yaml" -p reports)
if [[ -f "$ROOT/compose.indexer-ca.yaml" ]]; then
    compose+=(-f "$ROOT/compose.indexer-ca.yaml")
fi
"${compose[@]}" config --quiet
if ((!skip_account)); then
    [[ -t 0 && -t 1 ]] || die 'Account creation needs an interactive terminal for its hidden password prompt. Use --skip-account for updates.'
    [[ -n $username ]] || prompt 'Portal username' username
    if ((!admin && !all_customers && ${#customers[@]} == 0)); then
        prompt 'Authorized customers (comma-separated agent.labels.customer values)' customer_input
        [[ -n $customer_input && $customer_input != ,* && $customer_input != *, && $customer_input != *,,* ]] || die 'Customer list cannot contain empty values.'
        IFS=',' read -r -a prompted_customers <<< "$customer_input"
        for customer in "${prompted_customers[@]}"; do
            # Strip surrounding whitespace; preserve the exact value within each item.
            customer="${customer#"${customer%%[![:space:]]*}"}"
            customer="${customer%"${customer##*[![:space:]]}"}"
            [[ -n $customer ]] || die 'Customer cannot be empty.'
            customers+=("$customer")
        done
    fi
fi
# Separate exports reduce simultaneous writes to the local containerd image store.
# A persistent containerd lock still requires host-side diagnosis.
"${compose[@]}" build app
"${compose[@]}" build proxy
if ((!skip_account)); then
    account=(flask --app web.app:create_app user-set "$username")
    if ((admin)); then
        account+=(--admin)
    elif ((all_customers)); then
        account+=(--all-customers)
    else
        for customer in "${customers[@]}"; do account+=(--customer "$customer"); done
    fi
    "${compose[@]}" run --rm --no-deps app "${account[@]}"
fi
if ! "${compose[@]}" up -d --wait --wait-timeout 180; then
    "${compose[@]}" ps >&2
    printf 'Deployment failed. Inspect: docker compose -p reports logs --tail=100 app proxy\n' >&2
    exit 1
fi
"${compose[@]}" ps

# Export only the PUBLIC CA certificate, never the private signing key.
mkdir -p output/deployment
certificate=$(mktemp output/deployment/.root-ca.XXXXXX)
trap 'rm -f "$certificate"' EXIT
for attempt in {1..30}; do
    if "${compose[@]}" exec -T proxy cat /data/caddy/pki/authorities/local/root.crt > "$certificate" 2>/dev/null && grep -q 'BEGIN CERTIFICATE' "$certificate"; then
        mv -- "$certificate" output/deployment/reports-root-ca.crt
        printf 'Internal CA certificate: %s/output/deployment/reports-root-ca.crt\nInstall it in authorized clients before signing in.\n' "$ROOT"
        break
    fi
    sleep 1
done
if [[ -f $certificate ]]; then
    printf 'No internal CA exported. Public DNS may use a public CA; for internal TLS inspect proxy logs.\n' >&2
fi
printf '\nPortal: https://%s:8443/\nHTTP redirect: http://%s:8083/\n' "$report_host" "$report_host"
printf 'Persistent volumes kept under project reports. Updates: rerun with --skip-account.\n'
