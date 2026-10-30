#!/bin/sh
# pf_user_audit.sh - interactive local-account audit for pfSense (FreeBSD /bin/sh)
#
# Usage:  sh pf_user_audit.sh [-a]
#   -a   prompt for EVERY account (except protected ones), not just flagged ones
#
# Env overrides (for testing off-box):
#   MASTER, GROUPF, CONFIG, LOG, DRYRUN=1 (print the pw commands instead of running them)
#
# Notes:
#  * Reads /etc/master.passwd (has the password-hash field; /etc/passwd does not).
#  * "Disable" = pw lock + set shell to /usr/sbin/nologin. Nothing is deleted.
#  * Keep-list (packet) users are treated as non-suspicious, EXCEPT for the
#    critical checks (UID 0, empty password), which always apply.
#  * whiteteam is out of scope (rule 6/14): skipped entirely, never prompted.
#  * root and admin are protected: shown, but never offered for disabling.

MASTER="${MASTER:-/etc/master.passwd}"
GROUPF="${GROUPF:-/etc/group}"
CONFIG="${CONFIG:-/cf/conf/config.xml}"
LOG="${LOG:-/root/user_audit.log}"
DRYRUN="${DRYRUN:-0}"
ASK_ALL=0
[ "$1" = "-a" ] && ASK_ALL=1

# Users from the competition packet (domain + local) = "keep" list
KEEP="principal sportingdir chiefeng strategist pitcrew mechanic analyst driver tireman fuelman
scrutineer techdirector crewchief firecrew jackcrew garagecrew celebrity pitlaner reserve gunners"

PROTECTED="root admin"

# Default pfSense 2.7.2 accounts, from a known-good box:  name:uid:shell
NL=/usr/sbin/nologin
BASELINE="root:0:/bin/sh
toor:0:
daemon:1:$NL
operator:2:$NL
bin:3:$NL
tty:4:$NL
kmem:5:$NL
games:7:$NL
news:8:$NL
man:9:$NL
sshd:22:$NL
smmsp:25:$NL
mailnull:26:$NL
bind:53:$NL
unbound:59:$NL
proxy:62:$NL
_pflogd:64:$NL
_dhcp:65:$NL
uucp:66:/usr/local/libexec/uucp/uucico
pop:68:$NL
auditdistd:78:$NL
www:80:$NL
ntpd:123:$NL
_ypldap:160:$NL
hast:845:$NL
tests:977:$NL
nobody:65534:$NL
cyrus:60:$NL
messagebus:556:$NL
openvpn:301:$NL
dhcpd:136:$NL
admin:0:/etc/rc.initial"

# ---------- colors ----------
if [ -t 1 ]; then
  RED=$(printf '\033[31m'); YEL=$(printf '\033[33m'); GRN=$(printf '\033[32m')
  CYN=$(printf '\033[36m'); BLD=$(printf '\033[1m'); RST=$(printf '\033[0m')
else
  RED=; YEL=; GRN=; CYN=; BLD=; RST=
fi

# ---------- helpers ----------
log()  { echo "$(date '+%F %T') $*" >> "$LOG" 2>/dev/null; }
in_list() { for _i in $2; do [ "$_i" = "$1" ] && return 0; done; return 1; }
in_group() { grep "^$2:" "$GROUPF" 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep -qx "$1"; }
sevname() { case "$1" in 3) echo CRITICAL;; 2) echo SUSPICIOUS;; 1) echo REVIEW;; *) echo OK;; esac; }
sevcolor() { case "$1" in 3) printf '%s' "$RED";; 2) printf '%s' "$YEL";; 1) printf '%s' "$CYN";; *) printf '%s' "$GRN";; esac; }

SEV=0; REASONS=""
flag() {  # flag <severity 1-3> <message>
  [ "$1" -gt "$SEV" ] && SEV=$1
  REASONS="${REASONS}    $(sevcolor "$1")[$(sevname "$1")]${RST} $2
"
}

BACKED_UP=0
backup_once() {
  [ "$BACKED_UP" -eq 1 ] && return
  [ "$DRYRUN" = "1" ] && return
  _b="/root/master.passwd.bak.$(date +%s)"
  cp -p /etc/master.passwd "$_b" && echo "  (backup saved: $_b)" && log "BACKUP $_b"
  BACKED_UP=1
}

disable_user() {
  if [ "$DRYRUN" = "1" ]; then
    echo "  [dry-run] pw lock $1 ; pw usermod $1 -s $NL"
    return
  fi
  backup_once
  if pw lock "$1" && pw usermod "$1" -s "$NL"; then
    echo "  ${GRN}Login disabled for $1 (locked + nologin).${RST}"
    log "DISABLED $1 (pw lock + nologin)"
    DISABLED=$((DISABLED+1))
  else
    echo "  ${RED}pw failed for $1 - check manually.${RST}"
    log "FAILED to disable $1"
  fi
}

show_home() {  # show_home <home>
  if [ -z "$1" ] || [ "$1" = "/" ] || [ ! -d "$1" ]; then
    echo "  Home: ${1:-<none>} (no private home directory to inspect)"
    return
  fi
  echo "  ls -la $1"
  ls -la "$1" | sed 's/^/    /'
  if [ -d "$1/.ssh" ]; then
    echo "  ls -la $1/.ssh"
    ls -la "$1/.ssh" | sed 's/^/    /'
  fi
}

# ---------- preflight ----------
[ -r "$MASTER" ] || { echo "Cannot read $MASTER"; exit 1; }
[ "$(id -u)" -eq 0 ] || echo "${YEL}Warning: not running as root; disabling will fail.${RST}"

GUI_OK=0; GUI_USERS=""
if [ -r "$CONFIG" ]; then
  GUI_OK=1
  GUI_USERS=$(awk '/<user>/{u=1} u && /<name>/{gsub(/.*<name>|<\/name>.*/,""); print; u=0}' "$CONFIG")
else
  echo "${YEL}Warning: cannot read $CONFIG - skipping webConfigurator comparison.${RST}"
fi

# UIDs (other than 0) used by more than one account
DUP_UIDS=$(awk -F: '!/^#/ && NF>=3 && $3!=0 {c[$3]++} END{for(u in c) if(c[u]>1) print u}' "$MASTER")

TOTAL=0; FLAGGED=0; DISABLED=0
log "=== audit start ==="
echo "${BLD}pfSense account audit${RST}  (source: $MASTER)"
echo

# ---------- main loop (file on fd 3 so prompts can use stdin) ----------
while IFS=: read -r name pw uid gid class chg exp gecos home shell <&3; do
  case "$name" in ""|\#*) continue;; esac

  if [ "$name" = "whiteteam" ]; then
    echo "${BLD}whiteteam${RST}: out of scope (rules 6/14) - skipped."
    echo; continue
  fi

  TOTAL=$((TOTAL+1))
  SEV=0; REASONS=""

  is_keep=0;  in_list "$name" "$KEEP" && is_keep=1
  bentry=$(echo "$BASELINE" | grep "^${name}:" | head -1)
  in_gui=0;   [ -n "$GUI_USERS" ] && echo "$GUI_USERS" | grep -qx "$name" && in_gui=1
  login_shell=1; case "$shell" in */nologin|*/false) login_shell=0;; esac  # empty shell = /bin/sh

  # ---- critical checks: always apply, even to keep-list users ----
  if [ "$uid" = "0" ] && [ -z "$bentry" ]; then
    flag 3 "UID 0 (root-equivalent) and not root/toor/admin"
  fi
  if [ -z "$pw" ]; then
    flag 3 "EMPTY password field - login possible without a password"
  fi

  # ---- classification ----
  if [ $is_keep -eq 1 ]; then
    :
  elif [ -n "$bentry" ]; then
    b_uid=$(echo "$bentry" | cut -d: -f2)
    b_shell=$(echo "$bentry" | cut -d: -f3)
    [ "$uid" != "$b_uid" ]     && flag 2 "default account altered: UID is $uid, expected $b_uid"
    [ "$shell" != "$b_shell" ] && flag 2 "default account altered: shell is '${shell:-<empty>}', expected '${b_shell:-<empty>}'"
    case "$name" in
      root|toor|admin) ;;
      *) case "$pw" in \**|\!*) ;; *) [ -n "$pw" ] && flag 2 "default service account has a usable password hash";; esac ;;
    esac
  else
    if [ $in_gui -eq 1 ]; then
      flag 1 "GUI-managed user (in config.xml) but not in the packet list"
    elif [ $GUI_OK -eq 1 ]; then
      flag 2 "Unknown account: not a pfSense default, not in packet list, NOT in webConfigurator"
    else
      flag 2 "Unknown account: not a pfSense default, not in packet list"
    fi
    if [ $in_gui -eq 0 ]; then
      [ $login_shell -eq 1 ] && flag 2 "has a login shell: ${shell:-/bin/sh (default)}"
      case "$pw" in \**|\!*) ;; *) [ -n "$pw" ] && flag 2 "has a usable password hash";; esac
      in_group "$name" wheel  && flag 2 "member of group wheel"
      in_group "$name" admins && flag 2 "member of group admins (GUI admin group)"
    fi
    [ "$gid" = "0" ] && flag 2 "primary group is wheel (gid 0)"
    case "$home" in
      /tmp*|/var/tmp*|/dev/*|/var/run*) flag 2 "home directory in a world-writable/volatile location: $home";;
    esac
  fi

  if [ $is_keep -eq 0 ]; then
    echo "$DUP_UIDS" | grep -qx "$uid" && flag 2 "UID $uid shared with another account"
    if [ -s "$home/.ssh/authorized_keys" ]; then
      if [ -n "$bentry" ]; then flag 1 "has ~/.ssh/authorized_keys (verify the keys)"
      else flag 2 "has ~/.ssh/authorized_keys (possible SSH backdoor)"; fi
    fi
  fi

  # ---- report ----
  echo "${BLD}$name${RST}  uid=$uid gid=$gid shell=${shell:-<empty>} home=${home:-<none>}"
  if [ $SEV -eq 0 ]; then
    if [ $is_keep -eq 1 ]; then echo "  ${GRN}[OK]${RST} in packet keep list"
    else echo "  ${GRN}[OK]${RST} matches default pfSense account"; fi
  else
    FLAGGED=$((FLAGGED+1))
    printf '%s' "$REASONS"
    log "FLAG $name sev=$(sevname $SEV) uid=$uid shell=$shell home=$home"
  fi

  # ---- prompt ----
  if in_list "$name" "$PROTECTED"; then
    [ $SEV -ge 1 ] && echo "  ${YEL}Protected account (disabling would lock you out) - not offered. Review manually.${RST}"
    echo; continue
  fi
  if [ $SEV -ge 1 ] || [ $ASK_ALL -eq 1 ]; then
    show_home "$home"
    _procs=$(ps -U "$name" -o pid,etime,command 2>/dev/null | sed 1d)
    if [ -n "$_procs" ]; then
      echo "  Running processes:"; echo "$_procs" | sed 's/^/    /'
    fi
    [ $in_gui -eq 1 ] && echo "  ${CYN}Note: this is a webConfigurator user; pfSense may re-sync it from config.xml. Also disable it in System > User Manager.${RST}"
    printf "  Disable login for '%s'? [y/N] " "$name"
    read -r ans
    case "$ans" in
      y|Y|yes|YES)
        disable_user "$name"
        if [ -n "$_procs" ]; then
          printf "  Kill its running processes? [y/N] "
          read -r kans
          case "$kans" in
            y|Y) if [ "$DRYRUN" = "1" ]; then echo "  [dry-run] pkill -KILL -u $name"; else pkill -KILL -u "$name"; log "KILLED procs of $name"; fi;;
          esac
        fi ;;
      *) echo "  Left unchanged."; log "SKIPPED $name (left unchanged)";;
    esac
  fi
  echo
done 3< "$MASTER"

echo "${BLD}Done.${RST} Accounts reviewed: $TOTAL | flagged: $FLAGGED | disabled: $DISABLED"
echo "Log (use for your IR report): $LOG"
log "=== audit end: reviewed=$TOTAL flagged=$FLAGGED disabled=$DISABLED ===