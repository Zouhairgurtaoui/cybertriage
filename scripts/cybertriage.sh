#!/usr/bin/env bash
# Linux Docker Engine launcher; never source configuration as shell code.
set +x
set -Eeuo pipefail
umask 077

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
environment_path="$project_root/.env.docker.local"
action="${1:-}"
graph=false
if (($#)); then shift; fi
for option in "$@"; do
    case "$option" in
        --graph) graph=true ;;
        *) printf 'Unknown option: %s\n' "$option" >&2; exit 2 ;;
    esac
done
fail() { printf '%s\n' "$*" >&2; exit 1; }
random_hex() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }

write_secret_once() {
    local path="$1" prompt="$2" generate="${3:-false}" value
    [[ ! -L "$path" ]] || fail "Secret paths must not be symbolic links."
    if [[ -e "$path" ]]; then
        [[ -f "$path" && -s "$path" ]] || fail "Existing secret is not a nonempty file: $path"
        chmod 644 -- "$path"
        printf 'Keeping existing secret: %s\n' "${path##*/}"
        return
    fi
    if [[ "$generate" == true ]]; then value="$(random_hex)";
    else
        read -r -s -p "$prompt: " value || fail 'Credential input cancelled.'
        printf '\n'
    fi
    [[ -n "$value" && ${#value} -le 4096 && ! "$value" =~ [[:cntrl:]] ]] || fail 'A nonempty single-line credential is required.'
    if [[ "$path" == */ingestion.token ]]; then
        LC_ALL=C
        [[ ${#value} -ge 32 && ${#value} -le 512 && ! "$value" =~ [^!-~] ]] || fail 'Ingestion token must contain 32-512 non-whitespace ASCII characters.'
    fi
    (set -o noclobber; printf '%s' "$value" > "$path")
    # Compose bind-mounts individual files. Host directory stays private (0700).
    chmod 644 -- "$path"
    unset value
}

if [[ "$action" == configure ]]; then
    [[ ! -L "$project_root/config" ]] || fail 'Configuration directory must not be a symbolic link.'
    [[ ! -L "$environment_path" ]] || fail 'Environment file must not be a symbolic link.'
    if [[ ! -e "$environment_path" ]]; then
        sed 's|http://host.docker.internal:11434|http://127.0.0.1:11434|' \
            "$project_root/.env.docker.example" > "$environment_path"
    fi
    secrets_directory="$project_root/config/secrets"
    [[ ! -L "$project_root/config" && ! -L "$secrets_directory" ]] || fail 'Configuration directories must not be symbolic links.'
    mkdir -p -- "$secrets_directory" "$project_root/config/certs"
    chmod 700 -- "$secrets_directory"
    write_secret_once "$secrets_directory/ingestion.token" 'Existing Wazuh ingestion token'
    write_secret_once "$secrets_directory/indexer.password" 'Read-only Indexer password'
    write_secret_once "$secrets_directory/neo4j.password" '' true
    analyst_path="$project_root/config/analysts.local.yaml"
    [[ ! -L "$analyst_path" ]] || fail 'Analyst configuration must not be a symbolic link.'
    if [[ ! -e "$analyst_path" ]]; then
        token="$(random_hex)"
        digest="$(printf '%s' "$token" | sha256sum)"; digest="${digest%% *}"
        expiry="$(date -u -d '+30 days' '+%Y-%m-%dT%H:%M:%SZ')"
        (set -o noclobber; cat > "$analyst_path" <<EOF
schema_version: 1
principals:
  - id: local-analyst
    token_sha256: "$digest"
    permissions: ["cases:read", "cases:write", "cases:review", "investigations:request", "reports:read_all", "triage:review"]
    case_ids: ["*"]
    expires_at: "$expiry"
EOF
        )
        chmod 644 -- "$analyst_path"
        printf 'New analyst token (shown once; expires %s):\n%s\n' "$expiry" "$token"
        unset token digest
    fi
    [[ -f "$analyst_path" ]] || fail 'Analyst configuration must be a regular file.'
    chmod 644 -- "$analyst_path"
    printf '%s\n' 'Configuration ready. Existing credentials were retained.' \
        'Edit .env.docker.local and copy the public Indexer CA to config/certs/indexer-ca.pem.'
    exit 0
fi

case "$action" in build|import-data|knowledge|start|stop|status|logs) ;; *)
    printf 'Usage: bash scripts/cybertriage.sh {configure|build|import-data|knowledge|start|stop|status|logs} [--graph]\n' >&2; exit 2 ;;
esac
command -v docker >/dev/null || fail 'Docker Engine with the Compose plugin is required.'
[[ -f "$environment_path" ]] || fail 'Run configure first.'
compose=(docker compose --env-file "$environment_path" -f "$project_root/compose.yaml" -f "$project_root/compose.linux.yaml")
if [[ "$graph" == true || "$action" =~ ^(stop|status|logs)$ ]]; then compose+=(--profile graph); fi
cd -- "$project_root"
case "$action" in
    build) "${compose[@]}" build ;;
    import-data)
        "${compose[@]}" run --rm --no-deps bootstrap
        "${compose[@]}" --profile maintenance run --rm --no-deps import-data ;;
    knowledge)
        "${compose[@]}" run --rm --no-deps bootstrap
        "${compose[@]}" run --rm --no-deps worker catalog-update
        "${compose[@]}" run --rm --no-deps worker ingest --source mitre
        "${compose[@]}" run --rm --no-deps worker ingest --source microsoft ;;
    start)
        "${compose[@]}" up --build -d --wait --wait-timeout 300
        printf '%s\n' 'CyberTriage started. Open http://127.0.0.1:5173 (or your configured web port).' ;;
    stop) "${compose[@]}" down --timeout 210 ;;
    status) "${compose[@]}" ps --all ;;
    logs) "${compose[@]}" logs --tail 100 --follow ;;
esac
