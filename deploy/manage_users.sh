#!/usr/bin/env bash
# Account administration on the Docker Compose host. No host Python/pip needed.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
usage() {
    cat <<'HELP'
Usage: ./deploy/manage_users.sh COMMAND [USERNAME] [OPTIONS]
  list                              Show accounts, status and customer permissions
  add USER --customer NAME [...]    Create a new account; prompt for password
  add USER --all                     Create an account with access to all customers
  add-admin USER                     Create administrator (all customers by default)
  promote USER                       Promote existing user to administrator
  permissions USER --customer NAME  Replace the complete list (repeat --customer)
  permissions USER --all            Authorize every customer
  password USER                     Reset password, preserving permissions/status
  disable USER                      Disable account and revoke sessions
  enable USER                       Enable account and revoke sessions

--all-customers is an alias for --all. Customer values are exact labels; repeat
--customer for separate clients. Permission changes revoke existing sessions.
Commands run against the running 'app' service of the 'reports' Compose project.
HELP
}
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
[[ ${1:-} != --help && ${1:-} != -h && $# -gt 0 ]] || { usage; exit 0; }
action=$1; shift
case "$action" in list|add|add-admin|promote|permissions|password|disable|enable) ;; *) die 'Unknown command (see --help).' ;; esac
username=''
if [[ $action != list ]]; then
    [[ $# -gt 0 && $1 != -* ]] || die 'Username is required.'
    username=$1; shift
fi
all=0
customers=()
while (($#)); do
    case "$1" in
        --all|--all-customers) all=1; shift ;;
        --customer)
            [[ $# -ge 2 && -n $2 && $2 != --* ]] || die 'Missing --customer value.'
            customers+=("$2"); shift 2 ;;
        *) die "Unknown option: $1" ;;
    esac
done
if [[ $action == add || $action == permissions ]]; then
    if ((all)); then
        ((${#customers[@]} == 0)) || die 'Choose --all or --customer.'
        permissions=(--all-customers)
    else
        ((${#customers[@]} > 0)) || die 'Specify --all or at least one --customer.'
        permissions=()
        for customer in "${customers[@]}"; do permissions+=(--customer "$customer"); done
    fi
else
    ((all == 0 && ${#customers[@]} == 0)) || die 'Permission options only apply to add/permissions.'
fi
case "$action" in
    list) command_args=(user-list) ;;
    add) command_args=(user-set "$username" --create-only "${permissions[@]}") ;;
    add-admin) command_args=(user-set "$username" --create-only --admin) ;;
    promote) command_args=(user-role "$username" --admin) ;;
    permissions) command_args=(user-permissions "$username" "${permissions[@]}") ;;
    password) command_args=(user-password "$username") ;;
    disable) command_args=(user-disable "$username") ;;
    enable) command_args=(user-enable "$username") ;;
esac
terminal=(-T)
if [[ $action == add || $action == add-admin || $action == password ]]; then
    [[ -t 0 && -t 1 ]] || die 'Password entry requires an interactive terminal.'
    terminal=()
fi
cd "$ROOT"
[[ -f .env ]] || die 'Missing .env. Run deploy_ubuntu.sh first.'
command -v docker >/dev/null || die 'Docker is not installed.'
docker_cmd=(docker)
if ! docker info >/dev/null 2>&1; then
    command -v sudo >/dev/null || die 'Docker is unavailable; check daemon/access permissions.'
    docker_cmd=(sudo docker)
    "${docker_cmd[@]}" info >/dev/null || die 'Docker Engine is unavailable.'
fi
compose=("${docker_cmd[@]}" compose --project-directory "$ROOT" --env-file "$ROOT/.env" -f "$ROOT/compose.yaml" -p reports)
if [[ -f "$ROOT/compose.indexer-ca.yaml" ]]; then
    compose+=(-f "$ROOT/compose.indexer-ca.yaml")
fi
exec "${compose[@]}" exec "${terminal[@]}" app flask --app web.app:create_app "${command_args[@]}"
