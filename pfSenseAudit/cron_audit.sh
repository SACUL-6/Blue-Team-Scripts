#!/bin/sh
# cron_audit.sh - full scheduled-task audit for pfSense (FreeBSD /bin/sh)
#
# Usage: sh cron_audit.sh [-b] [-i] [-h]
#   (no flags)  audit everything, then diff against the baseline if one exists
#   -b          save a known-good BASELINE snapshot and exit (do this at minute zero)
#   -i          interactive cleanup: offer to quarantine / comment out bad entries
#   -h          help
#
# Env overrides (testing off-box): MASTER CRONTAB CONFIG TABDIR ATDIR BASEDIR QDIR LOG
#   DRYRUN=1 (print actions, do nothing)  ANSWERS=<file> (canned answers for -i)
#
# What it covers
#   1. /etc/crontab (system crontab). pfSense REGENERATES this file from the <cron>
#      section of config.xml, so a line here that is not in config.xml is a hand edit.
#   2. <cron> items in config.xml (the persistent source of truth)
#   3. per-user crontabs in /var/cron/tabs, including orphans (owner not in passwd)
#   4. /etc/cron.d and /usr/local/etc/cron.d
#   5. at(1) jobs
#   6. periodic(8): rc.periodic, periodic.inc, /etc/periodic, /usr/local/etc/periodic,
#      *.local hooks, periodic.conf*
#   7. related boot persistence: <shellcmd>/<earlyshellcmd> in config.xml, rc.d scripts
#   8. diff against baseline
#
# Out of scope and skipped (rules 6/14): whiteteam, DataDog (dd-agent, ddagentuser,
# anything named datadog). syslog-ng is analysed but never offered for cleanup.

CRONTAB="${CRONTAB:-/etc/crontab}"
MASTER="${MASTER:-/etc/master.passwd}"
CONFIG="${CONFIG:-/cf/conf/config.xml}"
TABDIR="${TABDIR:-/var/cron/tabs}"
ATDIR="${ATDIR:-/var/at/jobs}"
CROND_DIRS="${CROND_DIRS:-/etc/cron.d /usr/local/etc/cron.d}"
PERIODIC_LOCAL="${PERIODIC_LOCAL:-/usr/local/etc/periodic}"
PERIODIC_BASE="${PERIODIC_BASE:-/etc/periodic}"
RCD_DIR="${RCD_DIR:-/usr/local/etc/rc.d}"
BASEDIR="${BASEDIR:-/root/cron_baseline}"
QDIR="${QDIR:-/root/cron_quarantine}"
LOG="${LOG:-/root/cron_audit.log}"
DRYRUN="${DRYRUN:-0}"
RECENT_DAYS="${RECENT_DAYS:-1}"

MODE_BASE=0; INTERACTIVE=0
for _a in "$@"; do
  case "$_a" in
    -b) MODE_BASE=1;; -i) INTERACTIVE=1;;
    -h|--help) sed -n '2,13p' "$0"; exit 0;;
    *) echo "unknown option $_a"; exit 1;;
  esac
done

# Stock FreeBSD entries as seen on a clean 2.7.2 box:  sched|who|command
STOCK="*/11 * * * *|operator|/usr/libexec/save-entropy
0 * * * *|root|newsyslog
1 3 * * *|root|periodic daily
15 4 * * 6|root|periodic weekly
30 5 1 * *|root|periodic monthly
1,31 0-5 * * *|root|adjkerntz -a"

OOS_RE='whiteteam|datadog|dd-agent|ddagentuser'
PROT_RE='syslog-ng'

# reverse shells / obvious backdoors -> CRITICAL
CRIT_RE='/dev/(tcp|udp)/|mkfifo|(^|[^[:alnum:]_])(bash|sh|zsh|ksh) +-i|(^|[^[:alnum:]_])(nc|ncat|netcat) +[^;|&]*-[a-z]*e |socat .*(exec|system):|python[0-9.]* +-c .*socket|perl +-e .*socket|php +-r .*(fsockopen|socket)|ruby +-rsocket'
# suspicious in a cron command -> SUSPICIOUS
SUS_RE='(^|[^[:alnum:]_])(nc|ncat|netcat|socat|telnet)([^[:alnum:]_]|$)|(^|[^[:alnum:]_])(curl|wget|fetch|ftp|tftp)([^[:alnum:]_]|$)|base64|openssl +s_client|/tmp/|/var/tmp/|/dev/shm|/\.[A-Za-z0-9_]|authorized_keys|(^|[^[:alnum:]_])pw +(user|group)|useradd|usermod|chmod +([ugoa]*\+s|[0-7]*[2467][0-7]{3}|777)|(^|[^[:alnum:]_])(python[0-9.]*|perl|ruby)( |$)|\| *(sh|bash)|eval |nohup'
# account / key / sudo tampering inside scripts -> SUSPICIOUS
PERSIST_RE='authorized_keys|pw +(useradd|usermod|user)|useradd|NOPASSWD|/etc/sudoers'

# ---------- colors ----------
if [ -t 1 ]; then
  RED=$(printf '\033[31m'); YEL=$(printf '\033[33m'); GRN=$(printf '\033[32m')
  CYN=$(printf '\033[36m'); BLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); RST=$(printf '\033[0m')
else RED=; YEL=; GRN=; CYN=; BLD=; DIM=; RST=; fi

# ---------- helpers ----------
log()      { echo "$(date '+%F %T') $*" >> "$LOG" 2>/dev/null; }
sevname()  { case "$1" in 3) echo CRITICAL;; 2) echo SUSPICIOUS;; 1) echo REVIEW;; *) echo OK;; esac; }
sevcolor() { case "$1" in 3) printf '%s' "$RED";; 2) printf '%s' "$YEL";; 1) printf '%s' "$CYN";; *) printf '%s' "$GRN";; esac; }
sec()      { echo; echo "${BLD}=== $* ===${RST}"; }
hash_file() { if command -v sha256 >/dev/null 2>&1; then sha256 -r "$1"; else sha256sum "$1"; fi; }

SEV=0; REASONS=""; TINFO=""; XSEV=""; XMSG=""
IS_STOCK=0; IN_CFG=0; PROT=0
N0=0; N1=0; N2=0; N3=0; TOTAL=0

flag() {  # flag <1-3> <message>
  [ "$1" -gt "$SEV" ] && SEV=$1
  REASONS="${REASONS}      $(sevcolor "$1")[$(sevname "$1")]${RST} $2
"
}

ask() {  # ask <prompt>  (answers come from fd 4)
  printf '%s' "$1"
  read -r _ans <&4 || _ans=n
  echo "$_ans"
  case "$_ans" in y|Y|yes|YES) return 0;; esac
  return 1
}

hup_cron() { killall -HUP cron 2>/dev/null || pkill -HUP -x cron 2>/dev/null; }

quarantine() {  # quarantine <file>  (copy to evidence dir, then remove original)
  if [ "$DRYRUN" = "1" ]; then echo "  [dry-run] copy $1 -> $QDIR/ and remove it"; return; fi
  mkdir -p "$QDIR" && chmod 700 "$QDIR"
  _q="$QDIR/$(echo "$1" | tr '/' '_').$(date +%s)"
  if cp -p "$1" "$_q" && rm -f "$1"; then
    echo "  ${GRN}Quarantined -> $_q${RST}"; log "QUARANTINED $1 -> $_q"; hup_cron
  else echo "  ${RED}Failed to quarantine $1${RST}"; log "FAILED quarantine $1"; fi
}

disable_line() {  # disable_line <file> <lineno>
  if [ "$DRYRUN" = "1" ]; then echo "  [dry-run] comment out line $2 of $1"; return; fi
  mkdir -p "$QDIR" && chmod 700 "$QDIR"
  cp -p "$1" "$QDIR/crontab.bak.$(date +%s)"
  awk -v n="$2" 'NR==n{print "#DISABLED-BY-AUDIT# " $0; next}{print}' "$1" > "$TMP/ct.new" \
    && cat "$TMP/ct.new" > "$1" \
    && { echo "  ${GRN}Line $2 commented out (backup in $QDIR).${RST}"; log "COMMENTED $1:$2"; hup_cron; }
}

# ---------- parsers ----------
# emit_entries <file> <sys|user>  ->  "E|lineno|sched|who|cmd"  and  "V|lineno|VAR=value"
emit_entries() {
  awk -v mode="$2" '
    { line=$0; sub(/^[ \t]+/, "", line) }
    line == "" || line ~ /^#/ { next }
    line ~ /^[A-Za-z_][A-Za-z0-9_]*[ \t]*=/ { print "V|" NR "|" line; next }
    {
      n = split(line, f, /[ \t]+/)
      if (f[1] ~ /^@/) { sched = f[1]; st = 2 }
      else { sched = f[1] " " f[2] " " f[3] " " f[4] " " f[5]; st = 6 }
      who = ""
      if (mode == "sys") { who = f[st]; st++ }
      cmd = ""
      for (i = st; i <= n; i++) cmd = cmd (i > st ? " " : "") f[i]
      print "E|" NR "|" sched "|" who "|" cmd
    }' "$1"
}

# emit_config -> "C|sched|who|cmd" for every <cron><item> in config.xml
emit_config() {
  [ -r "$CONFIG" ] || return 0
  awk '
    function val(s, t,   a) {
      if (index(s, "<" t "/>")) return ""
      if (!match(s, "<" t ">")) return ""
      a = substr(s, RSTART + RLENGTH); sub("</" t ">.*", "", a); return a
    }
    /<cron>/   { c = 1; next }
    /<\/cron>/ { c = 0 }
    c && /<item>/ { it = 1; mi = ho = md = mo = wd = who = cmd = ""; next }
    c && /<\/item>/ {
      if (it) {
        gsub(/[ \t]+/, " ", cmd); sub(/^ /, "", cmd); sub(/ $/, "", cmd)
        print "C|" mi " " ho " " md " " mo " " wd "|" who "|" cmd
      }
      it = 0; next
    }
    c && it {
      if ($0 ~ /<minute/)  mi  = val($0, "minute")
      if ($0 ~ /<hour/)    ho  = val($0, "hour")
      if ($0 ~ /<mday/)    md  = val($0, "mday")
      if ($0 ~ /<month/)   mo  = val($0, "month")
      if ($0 ~ /<wday/)    wd  = val($0, "wday")
      if ($0 ~ /<who/)     who = val($0, "who")
      if ($0 ~ /<command/) cmd = val($0, "command")
    }' "$CONFIG" | sed -e 's/<!\[CDATA\[//g' -e 's/\]\]>//g' -e 's/&lt;/</g' \
                       -e 's/&gt;/>/g' -e 's/&quot;/"/g' -e 's/&amp;/\&/g'
}

# ---------- analysis ----------
# analyze <sched> <who> <cmd> <kind: SYS|USER|CROND|CFG>
analyze() {
  _sched=$1; _who=$2; _cmd=$3; _kind=$4
  SEV=0; REASONS=""; TINFO=""; IS_STOCK=0; IN_CFG=0; PROT=0; _alt=""
  echo "$_who $_cmd" | grep -Eiq "$PROT_RE" && PROT=1
  _key="$_sched|$_who|$_cmd"

  if [ "$_kind" = SYS ] || [ "$_kind" = CROND ]; then
    printf '%s\n' "$STOCK"   | grep -Fxq -- "$_key" && IS_STOCK=1
    printf '%s\n' "$CFG_SET" | grep -Fxq -- "$_key" && IN_CFG=1
    if [ $IS_STOCK -eq 0 ]; then
      _alt=$(printf '%s\n' "$STOCK" | awk -F'|' -v w="$_who" -v c="$_cmd" '$2==w && $3==c {print $1}')
      [ -n "$_alt" ] && flag 2 "stock entry ALTERED: schedule is '$_sched', stock is '$_alt'"
    fi
  fi
  [ "$_kind" = CFG ] && IN_CFG=1

  # who
  if [ -n "$_who" ]; then
    _u=$(awk -F: -v u="$_who" '$1==u {print $3}' "$MASTER" 2>/dev/null | head -1)
    if [ -z "$_u" ]; then flag 2 "runs as '$_who', which is not in $MASTER"
    elif [ "$_u" = "0" ] && [ "$_who" != "root" ]; then flag 2 "runs as '$_who' (UID 0)"
    elif [ "$_who" != "root" ] && [ $IS_STOCK -eq 0 ]; then flag 1 "runs as non-root user '$_who'"; fi
  fi

  # command content
  if printf '%s' "$_cmd" | grep -Eiq "$CRIT_RE"; then flag 3 "reverse-shell/backdoor pattern in command"; fi
  if [ $IS_STOCK -eq 0 ] && printf '%s' "$_cmd" | grep -Eiq "$SUS_RE"; then
    flag 2 "suspicious pattern in command: $(printf '%s' "$_cmd" | grep -Eio "$SUS_RE" | head -1)"
  fi

  # schedule
  case "$_sched" in
    "* * * * *"|"*/1 * * * *")
      if [ $IS_STOCK -eq 0 ]; then
        if [ $IN_CFG -eq 1 ]; then flag 1 "runs every minute"; else flag 2 "runs every minute"; fi
      fi;;
    @reboot) flag 1 "@reboot: runs at every boot (persistence)";;
    @*)      flag 1 "special schedule $_sched";;
  esac

  # drift: active in /etc/crontab but not in config.xml
  if [ "$_kind" = SYS ] && [ $IS_STOCK -eq 0 ] && [ $IN_CFG -eq 0 ] && [ -z "$_alt" ] && [ $CFG_OK -eq 1 ]; then
    flag 2 "active in $CRONTAB but NOT in config.xml (hand-edited? pfSense regenerates this file)"
  fi
  [ "$_kind" = USER ] && flag 1 "per-user crontab entry (pfSense normally keeps cron jobs in config.xml)"
  [ "$_kind" = CROND ] && [ $IS_STOCK -eq 0 ] && flag 1 "entry from a cron.d file"

  # targets referenced by the command
  set -f
  for _tok in $_cmd; do
    _tok=${_tok%;}
    case "$_tok" in /dev/*|/proc/*|/dev) continue;; /*) ;; *) continue;; esac
    [ -f "$_tok" ] || continue
    _ls=$(ls -ld "$_tok" 2>/dev/null)
    set -- $_ls; _perm=$1; _own=$3
    case "$_perm" in l*) continue;; esac
    TINFO="${TINFO}      target: $_ls
"
    case "$_perm" in ????????w*) flag 2 "target $_tok is WORLD-WRITABLE";; esac
    [ "$_own" != "root" ] && flag 2 "target $_tok is owned by '$_own', not root"
    if find "$_tok" -type f -mtime -"$RECENT_DAYS" 2>/dev/null | grep -q .; then
      flag 1 "target $_tok modified in the last ${RECENT_DAYS}d"
    fi
    grep -IEiq "$CRIT_RE" "$_tok" 2>/dev/null && flag 3 "target $_tok contains a reverse-shell/backdoor pattern"
    grep -IEiq "$PERSIST_RE" "$_tok" 2>/dev/null && flag 2 "target $_tok manipulates accounts/SSH keys/sudoers"
  done
  set +f

  [ -n "$XMSG" ] && { flag "$XSEV" "$XMSG"; XMSG=""; XSEV=""; }
}

emit_result() {  # emit_result <label> <detail>
  TOTAL=$((TOTAL+1))
  case $SEV in 3) N3=$((N3+1));; 2) N2=$((N2+1));; 1) N1=$((N1+1));; *) N0=$((N0+1));; esac
  printf '  %s[%s]%s %s  %s\n' "$(sevcolor "$SEV")" "$(sevname "$SEV")" "$RST" "$1" "$2"
  [ -n "$REASONS" ] && printf '%s' "$REASONS"
  [ "$SEV" -ge 2 ] && [ -n "$TINFO" ] && printf '%s' "$TINFO"
  [ "$SEV" -ge 1 ] && log "FLAG sev=$(sevname "$SEV") $1 :: $2"
}

report_entry() {  # report_entry <label> <sched> <who> <cmd> <kind>
  if echo "$1 $2 $3 $4" | grep -Eiq "$OOS_RE"; then
    echo "  ${DIM}[skip] $1 (out of scope: whiteteam/DataDog)${RST}"
    SEV=-1; PROT=1; IS_STOCK=1; IN_CFG=1; return
  fi
  analyze "$2" "$3" "$4" "$5"
  _note=""
  [ $IS_STOCK -eq 1 ] && _note="(stock)"
  [ "$SEV" -eq 0 ] && [ $IN_CFG -eq 1 ] && _note="(pfSense-managed, in config.xml)"
  emit_result "$1" "$2 | ${3:--} | $4 $_note"
}

report_file() {  # report_file <path> <label> <basesev> <basemsg>
  SEV=0; REASONS=""; TINFO=""; PROT=0
  if echo "$1" | grep -Eiq "$OOS_RE"; then
    echo "  ${DIM}[skip] $1 (out of scope)${RST}"; SEV=-1; PROT=1; return
  fi
  echo "$1" | grep -Eiq "$PROT_RE" && PROT=1
  [ -n "$3" ] && [ "$3" -gt 0 ] && flag "$3" "$4"
  grep -IEiq "$CRIT_RE"    "$1" 2>/dev/null && flag 3 "reverse-shell/backdoor pattern inside file"
  grep -IEiq "$PERSIST_RE" "$1" 2>/dev/null && flag 2 "account / SSH-key / sudoers manipulation pattern inside file"
  emit_result "$2" "$(ls -ld "$1" 2>/dev/null | awk '{print $1, $3, $6, $7, $8}')"
}

report_var() {  # report_var <lineno> <VAR=value>
  SEV=0; REASONS=""
  case "$2" in
    LD_*|BASH_ENV=*|ENV=*|*LD_PRELOAD*) flag 3 "linker / shell-init variable set in crontab (hijack)";;
    SHELL=*)  [ "${2#SHELL=}" = "/bin/sh" ] || flag 2 "SHELL is not /bin/sh";;
    PATH=*)   case "$2" in *=.:*|*:.|*:.:*|*::*|*:/tmp*|*=/tmp*|*:/var/tmp*) flag 2 "PATH contains an unsafe entry";; esac;;
    MAILTO=*) flag 1 "MAILTO set: cron output is mailed to that address";;
  esac
  emit_result "$CRONTAB:$1" "variable: $2"
}

# ---------- snapshot (baseline / compare) ----------
snapshot() {  # snapshot <dir>
  _d=$1; mkdir -p "$_d"
  emit_entries "$CRONTAB" sys 2>/dev/null | grep -Eiv "$OOS_RE" | sed -E 's/^([EV])\|[0-9]+\|/\1|/' | LC_ALL=C sort > "$_d/sys_crontab.norm"
  emit_config | LC_ALL=C sort > "$_d/config_cron.norm"
  : > "$_d/user_tabs.norm"
  if [ -d "$TABDIR" ]; then
    ls -A "$TABDIR" 2>/dev/null | grep -Eiv "$OOS_RE" | while read -r _t; do
      [ -f "$TABDIR/$_t" ] && emit_entries "$TABDIR/$_t" user | sed -E 's/^([EV])\|[0-9]+\|/\1|/' | sed "s|^|$_t: |"
    done | LC_ALL=C sort > "$_d/user_tabs.norm"
  fi
  [ -r "$CONFIG" ] && grep -E '<(earlyshellcmd|shellcmd)>' "$CONFIG" | sed 's/^[[:space:]]*//' | LC_ALL=C sort > "$_d/shellcmd.norm"
  [ -f "$_d/shellcmd.norm" ] || : > "$_d/shellcmd.norm"
  {
    for _p in /etc/rc.periodic /etc/inc/periodic.inc /etc/daily.local /etc/weekly.local /etc/monthly.local /etc/periodic.conf /etc/periodic.conf.local; do
      [ -f "$_p" ] && echo "$_p"
    done
    for _dd in $PERIODIC_BASE $PERIODIC_LOCAL $CROND_DIRS $TABDIR $ATDIR $RCD_DIR; do
      [ -d "$_dd" ] && find "$_dd" -type f 2>/dev/null
    done
  } | grep -Eiv "$OOS_RE" | LC_ALL=C sort -u | while read -r _p; do hash_file "$_p"; done > "$_d/files.sha"
}

# ================= main =================
[ -r "$CRONTAB" ] || { echo "Cannot read $CRONTAB"; exit 1; }
[ "$(id -u)" -eq 0 ] || echo "${YEL}Warning: not root - some files may be unreadable.${RST}"
TMP=$(mktemp -d /tmp/cron_audit.XXXXXX) || exit 1
trap 'rm -rf "$TMP"' EXIT

if [ $MODE_BASE -eq 1 ]; then
  snapshot "$BASEDIR" && chmod -R go-rwx "$BASEDIR" 2>/dev/null
  echo "Baseline saved to $BASEDIR  (re-run without -b to audit and diff against it)"
  log "BASELINE saved to $BASEDIR"; exit 0
fi

if [ $INTERACTIVE -eq 1 ]; then
  _src="${ANSWERS:-/dev/tty}"
  [ -r "$_src" ] || { echo "No terminal for -i"; exit 1; }
  exec 4<"$_src"
fi

CFG_OK=0; [ -r "$CONFIG" ] && CFG_OK=1
CFG_SET=$(emit_config | sed -n 's/^C|//p')
ACTIVE_SET=$(emit_entries "$CRONTAB" sys | sed -n 's/^E|[0-9]*|//p')
[ $CFG_OK -eq 0 ] && echo "${YEL}Warning: cannot read $CONFIG - drift checks disabled.${RST}"
log "=== cron audit start ==="
echo "${BLD}pfSense cron / scheduled-task audit${RST}"

# --- 0. daemon ---
sec "cron daemon"
_c=$(ps -ax -o pid,user,command 2>/dev/null | grep '[c]ron' | grep -v cron_audit)
if [ -n "$_c" ]; then echo "$_c" | sed 's/^/  /'; else echo "  ${YEL}cron does not appear to be running${RST}"; fi

# --- 1. /etc/crontab ---
sec "1. System crontab ($CRONTAB)"
emit_entries "$CRONTAB" sys > "$TMP/sys"
while IFS='|' read -r typ n sched who cmd; do
  case "$typ" in
    V) report_var "$n" "$sched";;
    E) report_entry "$CRONTAB:$n" "$sched" "$who" "$cmd" SYS
       if [ "$SEV" -ge 1 ] && [ $PROT -eq 0 ]; then
         if [ $IS_STOCK -eq 0 ] && [ $IN_CFG -eq 0 ] && [ $CFG_OK -eq 1 ]; then
           [ $INTERACTIVE -eq 1 ] && ask "  Comment out this line in $CRONTAB? [y/N] " && disable_line "$CRONTAB" "$n"
         elif [ "$SEV" -ge 2 ] && [ $IN_CFG -eq 1 ]; then
           echo "      Note: this entry is generated from config.xml. Removing it from $CRONTAB alone is undone when pfSense regenerates the file;"
           echo "      remove it at the source (cron package page, or restore a clean config)."
         fi
       fi;;
  esac
done < "$TMP/sys"

# --- 2. config.xml items not active ---
sec "2. config.xml <cron> items not present in $CRONTAB"
if [ $CFG_OK -eq 1 ]; then
  emit_config > "$TMP/cfg"; _any=0
  while IFS='|' read -r typ sched who cmd; do
    printf '%s\n' "$ACTIVE_SET" | grep -Fxq -- "$sched|$who|$cmd" && continue
    _any=1; XSEV=1; XMSG="in config.xml but not (yet) active in $CRONTAB"
    report_entry "config.xml" "$sched" "$who" "$cmd" CFG
  done < "$TMP/cfg"
  [ $_any -eq 0 ] && echo "  (none - every config.xml item is active)"
  echo "  config.xml has $(grep -c '^C|' "$TMP/cfg") cron item(s) in total."
else echo "  skipped (config.xml unreadable)"; fi

# --- 3. per-user crontabs ---
sec "3. Per-user crontabs ($TABDIR)"
if [ -d "$TABDIR" ]; then
  ls -A "$TABDIR" > "$TMP/tabs" 2>/dev/null; _any=0
  while read -r t; do
    [ -f "$TABDIR/$t" ] || continue
    _any=1
    if echo "$t" | grep -Eiq "$OOS_RE"; then echo "  ${DIM}[skip] $t (out of scope)${RST}"; continue; fi
    echo "  ${BLD}crontab file: $t${RST}"
    if ! awk -F: -v u="$t" '$1==u {f=1} END {exit !f}' "$MASTER" 2>/dev/null; then
      SEV=0; REASONS=""; flag 2 "ORPHAN crontab: owner '$t' does not exist in $MASTER"
      emit_result "$TABDIR/$t" "orphan"
    fi
    emit_entries "$TABDIR/$t" user > "$TMP/ut"
    if ! grep -q '^E|' "$TMP/ut"; then echo "    (no entries)"; fi
    while IFS='|' read -r typ n sched who cmd; do
      case "$typ" in
        V) report_var "$n" "$sched";;
        E) report_entry "$TABDIR/$t:$n" "$sched" "$t" "$cmd" USER;;
      esac
    done < "$TMP/ut"
    if [ $INTERACTIVE -eq 1 ] && ! echo "$t" | grep -Eiq "$PROT_RE"; then
      ask "  Quarantine and remove crontab file '$t'? [y/N] " && quarantine "$TABDIR/$t"
    fi
  done < "$TMP/tabs"
  [ $_any -eq 0 ] && echo "  (no per-user crontabs)"
else echo "  $TABDIR not found"; fi

# --- 4. cron.d ---
sec "4. cron.d directories"
_any=0
for _dd in $CROND_DIRS; do
  [ -d "$_dd" ] || continue
  ls -A "$_dd" > "$TMP/cd" 2>/dev/null
  while read -r f; do
    [ -f "$_dd/$f" ] || continue
    _any=1
    report_file "$_dd/$f" "$_dd/$f" 1 "file present in a cron.d directory (pfSense does not normally use these)"
    emit_entries "$_dd/$f" sys > "$TMP/cdf"
    while IFS='|' read -r typ n sched who cmd; do
      [ "$typ" = E ] && report_entry "$_dd/$f:$n" "$sched" "$who" "$cmd" CROND
    done < "$TMP/cdf"
    if [ $INTERACTIVE -eq 1 ] && [ "$SEV" -ge 0 ] && ! echo "$_dd/$f" | grep -Eiq "$OOS_RE|$PROT_RE"; then
      ask "  Quarantine and remove $_dd/$f? [y/N] " && quarantine "$_dd/$f"
    fi
  done < "$TMP/cd"
done
[ $_any -eq 0 ] && echo "  (no cron.d files)"

# --- 5. at jobs ---
sec "5. at(1) jobs ($ATDIR)"
_any=0
if [ -d "$ATDIR" ]; then
  ls "$ATDIR" > "$TMP/at" 2>/dev/null
  while read -r f; do
    [ -f "$ATDIR/$f" ] || continue
    _any=1
    report_file "$ATDIR/$f" "at job $f" 1 "scheduled at(1) job"
    echo "      last lines of job:"; tail -n 4 "$ATDIR/$f" | sed 's/^/        /'
    if [ $INTERACTIVE -eq 1 ] && ! echo "$ATDIR/$f" | grep -Eiq "$OOS_RE"; then
      ask "  Quarantine and remove at job $f? [y/N] " && quarantine "$ATDIR/$f"
    fi
  done < "$TMP/at"
fi
[ $_any -eq 0 ] && echo "  (no at jobs)"

# --- 6. periodic ---
sec "6. periodic(8) and its hooks"
for p in /etc/rc.periodic /etc/inc/periodic.inc; do
  [ -f "$p" ] && report_file "$p" "$p" 0 ""
done
for p in /etc/daily.local /etc/weekly.local /etc/monthly.local; do
  [ -f "$p" ] && report_file "$p" "$p" 2 "legacy periodic .local hook exists (runs as root from cron)"
done
for p in /etc/periodic.conf /etc/periodic.conf.local; do
  if [ -f "$p" ]; then
    SEV=0; REASONS=""
    grep -Eq '^[[:space:]]*[a-z_]*_local[[:space:]]*=' "$p" && flag 2 "sets a *_local hook (runs extra scripts from periodic)"
    emit_result "$p" "$(grep -Ev '^[[:space:]]*(#|$)' "$p" | tr '\n' ' ')"
  fi
done
if [ -d "$PERIODIC_LOCAL" ]; then
  find "$PERIODIC_LOCAL" -type f > "$TMP/pl" 2>/dev/null; _any=0
  while read -r f; do
    _any=1
    report_file "$f" "$f" 1 "script in the local periodic directory (runs as root from cron)"
    if [ $INTERACTIVE -eq 1 ] && [ "$SEV" -ge 0 ] && ! echo "$f" | grep -Eiq "$OOS_RE|$PROT_RE"; then
      ask "  Quarantine and remove $f? [y/N] " && quarantine "$f"
    fi
  done < "$TMP/pl"
  [ $_any -eq 0 ] && echo "  ($PERIODIC_LOCAL is empty)"
else echo "  ($PERIODIC_LOCAL does not exist)"; fi
if [ -d "$PERIODIC_BASE" ]; then
  _cnt=0; _bad=0
  find "$PERIODIC_BASE" -type f > "$TMP/pb" 2>/dev/null
  while read -r f; do
    _cnt=$((_cnt+1))
    if grep -IEiq "$CRIT_RE|$PERSIST_RE" "$f" 2>/dev/null; then _bad=1; report_file "$f" "$f" 0 ""; fi
  done < "$TMP/pb"
  [ $_bad -eq 0 ] && echo "  scanned $_cnt file(s) in $PERIODIC_BASE: no backdoor/persistence patterns (use the baseline diff for tampering)"
fi

# --- 7. related boot persistence ---
sec "7. Related boot persistence"
if [ $CFG_OK -eq 1 ]; then
  grep -E '<(earlyshellcmd|shellcmd)>' "$CONFIG" > "$TMP/sc" 2>/dev/null
  if [ -s "$TMP/sc" ]; then
    while read -r l; do
      SEV=0; REASONS=""; flag 2 "shellcmd entry in config.xml (runs a command at boot)"
      printf '%s' "$l" | grep -Eiq "$CRIT_RE" && flag 3 "reverse-shell/backdoor pattern"
      emit_result "config.xml" "$l"
    done < "$TMP/sc"
  else echo "  no <shellcmd>/<earlyshellcmd> entries in config.xml"; fi
fi
if [ -d "$RCD_DIR" ]; then
  ls -A "$RCD_DIR" > "$TMP/rc" 2>/dev/null; _cnt=0; _bad=0
  while read -r f; do
    [ -f "$RCD_DIR/$f" ] || continue
    _cnt=$((_cnt+1))
    echo "$RCD_DIR/$f" | grep -Eiq "$OOS_RE" && continue
    if grep -IEiq "$CRIT_RE|$PERSIST_RE" "$RCD_DIR/$f" 2>/dev/null; then _bad=1; report_file "$RCD_DIR/$f" "$RCD_DIR/$f" 0 ""; fi
  done < "$TMP/rc"
  [ $_bad -eq 0 ] && echo "  scanned $_cnt rc.d script(s) in $RCD_DIR: no backdoor/persistence patterns"
fi

# --- 8. baseline diff ---
sec "8. Diff against baseline ($BASEDIR)"
if [ -d "$BASEDIR" ]; then
  snapshot "$TMP/now"; _chg=0
  for f in sys_crontab.norm config_cron.norm user_tabs.norm shellcmd.norm files.sha; do
    if [ -f "$BASEDIR/$f" ] && ! diff -q "$BASEDIR/$f" "$TMP/now/$f" >/dev/null 2>&1; then
      _chg=$((_chg+1))
      echo "  ${YEL}CHANGED since baseline: $f${RST}"
      diff -u "$BASEDIR/$f" "$TMP/now/$f" | sed '1,2d' | sed 's/^/    /'
      log "BASELINE-DIFF $f changed"
    fi
  done
  [ $_chg -eq 0 ] && echo "  ${GRN}No changes since baseline.${RST}"
else
  echo "  No baseline yet. Run 'sh $0 -b' on a known-good system to create one."
fi

# ---------- summary ----------
sec "Summary"
echo "  Items reviewed: $TOTAL   ${RED}CRITICAL: $N3${RST}   ${YEL}SUSPICIOUS: $N2${RST}   ${CYN}REVIEW: $N1${RST}   ${GRN}OK: $N0${RST}"
echo "  Log (evidence for the IR report): $LOG"
[ $INTERACTIVE -eq 1 ] && echo "  Quarantined files are copied to $QDIR"
log "=== cron audit end: crit=$N3 susp=$N2 review=$N1 ok=$N0 ==="
[ $N3 -gt 0 ] && exit 2
[ $N2 -gt 0 ] && exit 1
exit 0