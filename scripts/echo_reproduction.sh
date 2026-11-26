#!/usr/bin/env bash
#
# Reproduces the Echo censorship measurements for one country vantage point.
#
#   1. Deploys the probe scanner (apps/) and both Echo servers to the country vantage point (/root/echo)
#   2. Deploys the probe scanner to the reference server if it is not there yet (/root/echo)
#   3. "Existing":    country vantage point -> reference server, without -echo
#   4. "Echo":        reference server -> Echo servers on the country vantage point, -echo
#   5. "Echo_Mimick": like 4., additionally -mimicClientPort
#
# For every scan, both sides are captured with tcpdump and the console output of the scanning machine is kept.
# Results are written to data/echo-reproduction/<Country>VM_<timestamp>/.
#
# All remote processes run detached (setsid nohup), so a lost connection to this machine does not interrupt them;
# this script retries SSH until the connection is back. Run this script itself inside tmux if this machine may
# go to sleep.
#
# Example (Kazakhstan):
#   scripts/echo_reproduction.sh --reference-ip 10.10.10.1 --country-ssh Kazakhstan-VM --country Kazakhstan \
#       --hostname www.kavkazcenter.com --path www.kavkazcenter.com --dns-hostname www.kavkazcenter.com \
#       --censored-ip 91.218.214.111 --wait 5

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPS_DIR="$REPO_DIR/apps"
JAR_NAME="censor-probescanner-1.1.0-SNAPSHOT.jar"
REMOTE_DIR="/root/echo"
REF_SERVER_UNITS=(tcp_server udp_server)
REF_RESOLVER_UNIT=systemd-resolved
SSH_RETRIES=240
POLL_SECONDS=15

usage() {
    cat <<EOF
Usage: $0 --reference-ip IP --country-ssh HOST --hostname NAME --path PATH --dns-hostname NAME --censored-ip IP [options]

Required:
  --reference-ip IP      Public IP of the reference server, reached via SSH as root@IP
  --country-ssh HOST     SSH host of the vantage point in the country (e.g. Kazakhstan-VM)
  --hostname NAME        -hostname of the probe scanner
  --path PATH            -path of the probe scanner
  --dns-hostname NAME    -dnsHostname of the probe scanner
  --censored-ip IP       -censoredIp of the probe scanner

Optional:
  --quic-hostname NAME   -quicHostname of the probe scanner (default: --hostname)
  --wait SECONDS         -wait of the probe scanner for all scans (default: 0)
  --wait-existing SECONDS, --wait-echo SECONDS, --wait-mimick SECONDS
                         -wait for the Existing, Echo or Echo_Mimick scan only (default: --wait)
  --wait-esni SECONDS    -waitEsni of the probe scanner for all scans (default: the wait of each scan)
  --country NAME         Country name for file names (default: SSH host without "-VM")
  --country-ip IP        Public IP of the vantage point (default: resolved from the SSH config)
EOF
    exit 1
}

log() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }
q() { printf '%q' "$1"; }

REF_IP="" COUNTRY_SSH="" HOSTNAME_ARG="" PATH_ARG="" DNS_HOSTNAME="" QUIC_HOSTNAME="" CENSORED_IP="" WAIT=0 WAIT_EXISTING="" WAIT_ECHO="" WAIT_MIMICK="" WAIT_ESNI="" COUNTRY="" COUNTRY_IP=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --reference-ip) REF_IP="$2"; shift 2 ;;
        --country-ssh) COUNTRY_SSH="$2"; shift 2 ;;
        --hostname) HOSTNAME_ARG="$2"; shift 2 ;;
        --path) PATH_ARG="$2"; shift 2 ;;
        --dns-hostname) DNS_HOSTNAME="$2"; shift 2 ;;
        --quic-hostname) QUIC_HOSTNAME="$2"; shift 2 ;;
        --censored-ip) CENSORED_IP="$2"; shift 2 ;;
        --wait) WAIT="$2"; shift 2 ;;
        --wait-existing) WAIT_EXISTING="$2"; shift 2 ;;
        --wait-echo) WAIT_ECHO="$2"; shift 2 ;;
        --wait-mimick) WAIT_MIMICK="$2"; shift 2 ;;
        --wait-esni) WAIT_ESNI="$2"; shift 2 ;;
        --country) COUNTRY="$2"; shift 2 ;;
        --country-ip) COUNTRY_IP="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown argument: $1" >&2; usage ;;
    esac
done
[[ -n "$REF_IP" && -n "$COUNTRY_SSH" && -n "$HOSTNAME_ARG" && -n "$PATH_ARG" && -n "$DNS_HOSTNAME" && -n "$CENSORED_IP" ]] || usage
[[ "$WAIT" =~ ^[0-9]+$ ]] || die "--wait must be a non-negative integer"
WAIT_EXISTING="${WAIT_EXISTING:-$WAIT}" WAIT_ECHO="${WAIT_ECHO:-$WAIT}" WAIT_MIMICK="${WAIT_MIMICK:-$WAIT}"
for w in "$WAIT_EXISTING" "$WAIT_ECHO" "$WAIT_MIMICK" ${WAIT_ESNI:+"$WAIT_ESNI"}; do
    [[ "$w" =~ ^[0-9]+$ ]] || die "wait values must be non-negative integers"
done
[[ "$REF_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "--reference-ip must be an IPv4 address"
REF_SSH="root@$REF_IP"
[[ -n "$COUNTRY" ]] || COUNTRY="${COUNTRY_SSH%-VM}"
if [[ -z "$COUNTRY_IP" ]]; then
    COUNTRY_IP="$(ssh -G "$COUNTRY_SSH" 2>/dev/null | awk '$1 == "hostname" {print $2}')"
    [[ "$COUNTRY_IP" =~ ^[0-9.]+$ ]] || COUNTRY_IP="$(getent ahostsv4 "$COUNTRY_IP" | awk 'NR == 1 {print $1}')"
fi
[[ "$COUNTRY_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Could not determine the IPv4 address of $COUNTRY_SSH, use --country-ip"

PREFIX="${COUNTRY}VM"
RUN_ID="${PREFIX}_$(date '+%Y-%m-%d_%H-%M-%S')"
REMOTE_RUN="$REMOTE_DIR/reproduction/$RUN_ID"
LOCAL_RUN="$REPO_DIR/data/echo-reproduction/$RUN_ID"

# --- SSH helpers that survive connection loss ---------------------------------------------------------------------

rssh() {
    local host="$1"; shift
    local attempt=1 rc
    while true; do
        rc=0
        ssh -T -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=4 "$host" "$@" || rc=$?
        [[ $rc -ne 255 ]] && return $rc
        [[ $attempt -ge $SSH_RETRIES ]] && die "SSH to $host failed $attempt times"
        log "SSH to $host failed, retrying in $POLL_SECONDS s ($attempt/$SSH_RETRIES)" >&2
        sleep "$POLL_SECONDS"
        attempt=$((attempt + 1))
    done
}

rsync_retry() {
    local attempt=1
    until rsync -az -e "ssh -T -o BatchMode=yes -o ConnectTimeout=15" "$@"; do
        [[ $attempt -ge $SSH_RETRIES ]] && die "rsync failed $attempt times"
        log "rsync failed, retrying in $POLL_SECONDS s ($attempt/$SSH_RETRIES)" >&2
        sleep "$POLL_SECONDS"
        attempt=$((attempt + 1))
    done
}

# Starts a detached job on a host (idempotent). Output goes to $REMOTE_RUN/<name>.log, the exit code to <name>.exit.
job_start() {
    local host="$1" name="$2" cmd="$3"
    local base="$REMOTE_RUN/$name"
    local inner="( $cmd ); echo \$? > $(q "$base.exit")"
    rssh "$host" "mkdir -p $(q "$REMOTE_RUN") && cd $(q "$REMOTE_DIR") && \
        if [ -f $(q "$base.exit") ] || { [ -f $(q "$base.pid") ] && kill -0 \$(cat $(q "$base.pid")) 2>/dev/null; }; then :; \
        else setsid nohup bash -c $(q "$inner") > $(q "$base.log") 2>&1 < /dev/null & echo \$! > $(q "$base.pid"); fi"
    RUNNING_JOBS+=("$host|$name")
}

# Stops a detached job (its whole process group) and waits until it is gone.
job_stop() {
    local host="$1" name="$2" signal="${3:-TERM}"
    local pid_file="$REMOTE_RUN/$name.pid"
    rssh "$host" "if [ -f $(q "$pid_file") ]; then pid=\$(cat $(q "$pid_file")); kill -$signal -- -\$pid 2>/dev/null; \
        for i in \$(seq 1 100); do kill -0 \$pid 2>/dev/null || break; sleep 0.2; done; \
        kill -0 \$pid 2>/dev/null && { kill -KILL -- -\$pid 2>/dev/null; sleep 1; }; fi" || true
    local entry rest=()
    for entry in "${RUNNING_JOBS[@]}"; do [[ "$entry" == "$host|$name" ]] || rest+=("$entry"); done
    RUNNING_JOBS=("${rest[@]}")
}

# Waits for a detached job to finish and shows its latest console line. Returns the job's exit code.
job_wait() {
    local host="$1" name="$2"
    local base="$REMOTE_RUN/$name" last="" status line
    while true; do
        status="$(rssh "$host" "if kill -0 \$(cat $(q "$base.pid") 2>/dev/null) 2>/dev/null; then echo RUNNING; \
            elif [ -f $(q "$base.exit") ]; then echo \"DONE \$(cat $(q "$base.exit"))\"; else echo LOST; fi; \
            tail -c 4000 $(q "$base.log") 2>/dev/null | tr '\r' '\n' | grep -v '^[[:space:]]*$' | tail -n 1")"
        line="$(sed -n '2p' <<< "$status")"
        if [[ -n "$line" && "$line" != "$last" ]]; then log "  $line"; last="$line"; fi
        case "$(sed -n '1p' <<< "$status")" in
            DONE*) local rc="${status%%$'\n'*}"; rc="${rc#DONE }"
                   local entry rest=()
                   for entry in "${RUNNING_JOBS[@]}"; do [[ "$entry" == "$host|$name" ]] || rest+=("$entry"); done
                   RUNNING_JOBS=("${rest[@]}")
                   return "$rc" ;;
            LOST) die "Job $name on $host stopped without exit code, see $base.log" ;;
        esac
        sleep "$POLL_SECONDS"
    done
}

# --- Captures, servers -------------------------------------------------------------------------------------------

capture_start() {
    local host="$1" name="$2" peer="$3"
    job_start "$host" "$name.tcpdump" "exec tcpdump -i any -U -n -s 0 -w $(q "$REMOTE_RUN/$name.pcap") host $(q "$peer")"
    sleep 3
    rssh "$host" "grep -q 'listening on' $(q "$REMOTE_RUN/$name.tcpdump.log")" \
        || die "tcpdump on $host did not start, see $REMOTE_RUN/$name.tcpdump.log"
}

capture_stop() {
    sleep 3
    job_stop "$1" "$2.tcpdump" INT
}

listening() {
    local host="$1" proto="$2" port="$3"
    rssh "$host" "ss -Hln$proto | awk '{print \$4}' | grep -qE '^(0\\.0\\.0\\.0|\\*|\\[::\\]):$port\$'"
}

# Any socket on the port, including ones bound to a single address such as the systemd-resolved stub on 127.0.0.53
port_bound() {
    local host="$1" proto="$2" port="$3"
    rssh "$host" "ss -Hln$proto | awk '{print \$4}' | grep -qE ':$port\$'"
}

wait_listening() {
    local host="$1" proto="$2" port="$3" want="$4" i
    for i in $(seq 1 30); do
        if listening "$host" "$proto" "$port"; then [[ "$want" == yes ]] && return 0
        else [[ "$want" == no ]] && return 0; fi
        sleep 1
    done
    return 1
}

ref_units_start() {
    log "Starting ${REF_SERVER_UNITS[*]} on the reference server"
    rssh "$REF_SSH" "systemctl start ${REF_SERVER_UNITS[*]}"
    wait_listening "$REF_SSH" t 80 yes && wait_listening "$REF_SSH" t 443 yes \
        && wait_listening "$REF_SSH" u 53 yes && wait_listening "$REF_SSH" u 443 yes \
        || die "Reference servers do not listen on TCP 80/443 and UDP 53/443"
}

ref_units_stop() {
    log "Stopping ${REF_SERVER_UNITS[*]} on the reference server (systemd would restart killed servers)"
    rssh "$REF_SSH" "systemctl stop ${REF_SERVER_UNITS[*]}"
    if rssh "$REF_SSH" "systemctl is-active --quiet $REF_RESOLVER_UNIT"; then
        log "Stopping $REF_RESOLVER_UNIT on the reference server (its stub listener occupies UDP/TCP 53)"
        RESOLVER_STOPPED=1
        rssh "$REF_SSH" "systemctl stop $REF_RESOLVER_UNIT"
    fi
    port_bound "$REF_SSH" u 53 && die "UDP 53 is still in use on the reference server, -mimicClientPort cannot bind it"
    wait_listening "$REF_SSH" t 80 no && wait_listening "$REF_SSH" t 443 no && wait_listening "$REF_SSH" u 53 no && wait_listening "$REF_SSH" u 443 no \
        || die "TCP 80, TCP 443, UDP 53 or UDP 443 are still in use on the reference server, -mimicClientPort cannot bind them"
}

# Closed connections whose FIN is dropped by the censor would otherwise block the mimicked 4-tuple for minutes
orphan_retries_lower() {
    COUNTRY_ORPHAN_RETRIES="$(rssh "$COUNTRY_SSH" "sysctl -n net.ipv4.tcp_orphan_retries")"
    REF_ORPHAN_RETRIES="$(rssh "$REF_SSH" "sysctl -n net.ipv4.tcp_orphan_retries")"
    log "Setting net.ipv4.tcp_orphan_retries=1 on $COUNTRY_SSH (was $COUNTRY_ORPHAN_RETRIES) and $REF_SSH (was $REF_ORPHAN_RETRIES)"
    rssh "$COUNTRY_SSH" "sysctl -qw net.ipv4.tcp_orphan_retries=1"
    rssh "$REF_SSH" "sysctl -qw net.ipv4.tcp_orphan_retries=1"
}

orphan_retries_restore() {
    if [[ -n "$COUNTRY_ORPHAN_RETRIES" ]]; then
        log "Restoring net.ipv4.tcp_orphan_retries=$COUNTRY_ORPHAN_RETRIES on $COUNTRY_SSH"
        rssh "$COUNTRY_SSH" "sysctl -qw net.ipv4.tcp_orphan_retries=$COUNTRY_ORPHAN_RETRIES"
        COUNTRY_ORPHAN_RETRIES=""
    fi
    if [[ -n "$REF_ORPHAN_RETRIES" ]]; then
        log "Restoring net.ipv4.tcp_orphan_retries=$REF_ORPHAN_RETRIES on $REF_SSH"
        rssh "$REF_SSH" "sysctl -qw net.ipv4.tcp_orphan_retries=$REF_ORPHAN_RETRIES"
        REF_ORPHAN_RETRIES=""
    fi
}

# Neither side may answer late packets of closed connections with RSTs; pre-existing rules stay untouched
rst_drop_rule() {
    echo "OUTPUT -d $1 -p tcp --tcp-flags RST RST -m comment --comment echo_reproduction -j DROP"
}

rst_drop_add() {
    log "Dropping outgoing RSTs on $COUNTRY_SSH and $REF_SSH towards each other"
    RST_DROP_ADDED=1
    rssh "$COUNTRY_SSH" "iptables -C $(rst_drop_rule "$REF_IP") > /dev/null 2>&1 || iptables -I $(rst_drop_rule "$REF_IP")"
    rssh "$REF_SSH" "iptables -C $(rst_drop_rule "$COUNTRY_IP") > /dev/null 2>&1 || iptables -I $(rst_drop_rule "$COUNTRY_IP")"
}

rst_drop_remove() {
    [[ "$RST_DROP_ADDED" == 1 ]] || return 0
    log "Removing the RST drop rules on $COUNTRY_SSH and $REF_SSH"
    rssh "$COUNTRY_SSH" "while iptables -C $(rst_drop_rule "$REF_IP") > /dev/null 2>&1; do iptables -D $(rst_drop_rule "$REF_IP"); done"
    rssh "$REF_SSH" "while iptables -C $(rst_drop_rule "$COUNTRY_IP") > /dev/null 2>&1; do iptables -D $(rst_drop_rule "$COUNTRY_IP"); done"
    RST_DROP_ADDED=0
}

echo_servers_start() {
    if listening "$COUNTRY_SSH" t 7 || listening "$COUNTRY_SSH" u 7; then
        die "Port 7 is already in use on $COUNTRY_SSH"
    fi
    log "Starting Echo servers (TCP/UDP 7) on $COUNTRY_SSH"
    job_start "$COUNTRY_SSH" echo_tcp_server "exec python3 -u echo_tcp.py"
    job_start "$COUNTRY_SSH" echo_udp_server "exec python3 -u echo_udp.py"
    ECHO_SERVERS_STARTED=1
    wait_listening "$COUNTRY_SSH" t 7 yes && wait_listening "$COUNTRY_SSH" u 7 yes \
        || die "Echo servers on $COUNTRY_SSH do not listen on TCP/UDP 7"
}

echo_servers_stop() {
    log "Stopping Echo servers on $COUNTRY_SSH"
    job_stop "$COUNTRY_SSH" echo_tcp_server
    job_stop "$COUNTRY_SSH" echo_udp_server
    ECHO_SERVERS_STARTED=0
}

cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    local entry
    for entry in "${RUNNING_JOBS[@]}"; do
        log "Cleanup: stopping ${entry#*|} on ${entry%%|*}"
        job_stop "${entry%%|*}" "${entry#*|}" INT
    done
    [[ "$ECHO_SERVERS_STARTED" == 1 ]] && echo_servers_stop
    orphan_retries_restore
    rst_drop_remove
    ref_units_restore
    exit $rc
}

ref_units_restore() {
    if [[ "$RESOLVER_STOPPED" == 1 ]]; then
        log "Starting $REF_RESOLVER_UNIT on the reference server again"
        rssh "$REF_SSH" "systemctl start $REF_RESOLVER_UNIT"
        RESOLVER_STOPPED=0
    fi
    [[ -n "$REF_UNITS_WERE_ACTIVE" ]] || return 0
    if [[ "$REF_UNITS_WERE_ACTIVE" == 1 ]]; then
        rssh "$REF_SSH" "systemctl is-active --quiet ${REF_SERVER_UNITS[*]}" || ref_units_start
    else
        log "Stopping ${REF_SERVER_UNITS[*]} again, they were not running before"
        rssh "$REF_SSH" "systemctl stop ${REF_SERVER_UNITS[*]}"
    fi
}

# --- Scans -------------------------------------------------------------------------------------------------------

scanner_cmd() {
    local args=(-hostname "$HOSTNAME_ARG" -path "$PATH_ARG" -dnsHostname "$DNS_HOSTNAME" -quicHostname "${QUIC_HOSTNAME:-$HOSTNAME_ARG}" -censoredIp "$CENSORED_IP" "$@")
    printf 'java -jar %q' "$REMOTE_DIR/$JAR_NAME"
    printf ' %q' "${args[@]}"
}

# run_scan <scan name> <wait> <scanning host> <other host> <IP of other host as seen by scanning host> <IP of scanning host> <scanner args...>
run_scan() {
    local scan="$1" wait="$2" client="$3" server="$4" server_ip="$5" client_ip="$6"; shift 6
    local name="${PREFIX}_$scan"
    log "=== Scan $scan (wait $wait s): $client -> $server ($server_ip)"
    capture_start "$client" "${name}_Client" "$server_ip"
    capture_start "$server" "${name}_Server" "$client_ip"
    job_start "$client" "${name}_console" "$(scanner_cmd -ip "$server_ip" -wait "$wait" -waitEsni "${WAIT_ESNI:-$wait}" "$@")"
    local rc=0
    job_wait "$client" "${name}_console" || rc=$?
    capture_stop "$client" "${name}_Client"
    capture_stop "$server" "${name}_Server"
    [[ $rc -eq 0 ]] || log "WARNING: scanner exited with code $rc, see ${name}_console.log"
    SCAN_HOSTS+=("$client" "$server")
}

fetch_results() {
    mkdir -p "$LOCAL_RUN"
    local host
    for host in "$COUNTRY_SSH" "$REF_SSH"; do
        rsync_retry --include='*.pcap' --include='*_console.log' --exclude='*' "$host:$REMOTE_RUN/" "$LOCAL_RUN/"
    done
    local pcap
    for pcap in "$LOCAL_RUN"/*.pcap; do
        editcap -F pcapng "$pcap" "${pcap%.pcap}.pcapng" && rm "$pcap"
    done
}

main() {
    RUNNING_JOBS=() SCAN_HOSTS=()
    ECHO_SERVERS_STARTED=0 REF_UNITS_WERE_ACTIVE="" RESOLVER_STOPPED=0 COUNTRY_ORPHAN_RETRIES="" REF_ORPHAN_RETRIES="" RST_DROP_ADDED=0

    [[ -f "$APPS_DIR/$JAR_NAME" && -d "$APPS_DIR/lib" ]] || die "$APPS_DIR/$JAR_NAME not found, build the probe scanner first"
    command -v editcap > /dev/null || die "editcap (Wireshark) is required to convert the captures to pcapng"

    log "Run $RUN_ID: $COUNTRY_SSH ($COUNTRY_IP) <-> reference $REF_SSH"
    local host
    for host in "$COUNTRY_SSH" "$REF_SSH"; do
        rssh "$host" "[ \$(id -u) -eq 0 ] && command -v java && command -v tcpdump && command -v python3" > /dev/null \
            || die "$host needs root, java, tcpdump and python3"
    done

    trap cleanup EXIT INT TERM

    log "Deploying probe scanner and Echo servers to $COUNTRY_SSH:$REMOTE_DIR"
    rssh "$COUNTRY_SSH" "mkdir -p $(q "$REMOTE_DIR")"
    rsync_retry "$APPS_DIR/$JAR_NAME" "$APPS_DIR/lib" "$REPO_DIR/python_util/echo_tcp.py" "$REPO_DIR/python_util/echo_udp.py" \
        "$COUNTRY_SSH:$REMOTE_DIR/"

    local local_sha remote_sha
    local_sha="$(sha256sum "$APPS_DIR/$JAR_NAME" | cut -d' ' -f1)"
    remote_sha="$(rssh "$REF_SSH" "sha256sum $(q "$REMOTE_DIR/$JAR_NAME") 2>/dev/null | cut -d' ' -f1")" || true
    if [[ -z "$remote_sha" ]]; then
        log "Deploying probe scanner to $REF_SSH:$REMOTE_DIR"
        rssh "$REF_SSH" "mkdir -p $(q "$REMOTE_DIR")"
        rsync_retry "$APPS_DIR/$JAR_NAME" "$APPS_DIR/lib" "$REF_SSH:$REMOTE_DIR/"
    elif [[ "$remote_sha" != "$local_sha" ]]; then
        log "WARNING: the probe scanner on the reference server differs from $APPS_DIR/$JAR_NAME and is not replaced"
    fi

    if rssh "$REF_SSH" "systemctl is-active --quiet ${REF_SERVER_UNITS[*]}"; then
        REF_UNITS_WERE_ACTIVE=1
    else
        REF_UNITS_WERE_ACTIVE=0
        ref_units_start
    fi

    mkdir -p "$LOCAL_RUN"
    {
        echo "run_id=$RUN_ID"
        echo "started=$(date --iso-8601=seconds)"
        echo "country_ssh=$COUNTRY_SSH"
        echo "country_ip=$COUNTRY_IP"
        echo "reference_ip=$REF_IP"
        echo "hostname=$HOSTNAME_ARG"
        echo "path=$PATH_ARG"
        echo "dns_hostname=$DNS_HOSTNAME"
        echo "quic_hostname=${QUIC_HOSTNAME:-$HOSTNAME_ARG}"
        echo "censored_ip=$CENSORED_IP"
        echo "wait_existing=$WAIT_EXISTING"
        echo "wait_echo=$WAIT_ECHO"
        echo "wait_mimick=$WAIT_MIMICK"
        echo "wait_esni=${WAIT_ESNI:-per scan wait}"
        echo "jar_sha256=$local_sha"
    } > "$LOCAL_RUN/run_info.txt"

    rst_drop_add
    run_scan Existing "$WAIT_EXISTING" "$COUNTRY_SSH" "$REF_SSH" "$REF_IP" "$COUNTRY_IP"

    echo_servers_start
    run_scan Echo "$WAIT_ECHO" "$REF_SSH" "$COUNTRY_SSH" "$COUNTRY_IP" "$REF_IP" -echo
    ref_units_stop
    orphan_retries_lower
    run_scan Echo_Mimick "$WAIT_MIMICK" "$REF_SSH" "$COUNTRY_SSH" "$COUNTRY_IP" "$REF_IP" -echo -mimicClientPort
    orphan_retries_restore
    echo_servers_stop
    rst_drop_remove
    ref_units_restore

    log "Fetching results to $LOCAL_RUN"
    fetch_results
    echo "finished=$(date --iso-8601=seconds)" >> "$LOCAL_RUN/run_info.txt"
    log "Done: $LOCAL_RUN"
    ls -1 "$LOCAL_RUN"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main
fi
