#!/bin/sh
# pf_user_audit.sh - interactive local-account audit for pfSense (FreeBSD /bin/sh)
#
# Usage:  sh pf_user_audit.sh [-a] [-k] [-r <user>] [-e] [-h]
#   -a   prompt for EVERY account (except protected), not just flagged ones
#   -k   also audit KEEP-list (packet) users (they are normally low-risk but still
#        prompt-able for disable/re-enable; -a includes them)
#   -r <user>  re-enable a previously-disabled account (pw unlock + restore shell)
#   -e   enable shell history for all users (create ~/.history 600 + set histfile
#        in ~/.cshrc / ~/.profile if missing; DRYRUN=1 previews)
#   -h   help
#
# Env overrides (for testing off-box):
#   MASTER, GROUPF, CONFIG, LOG, DRYRUN=1 (print the pw commands instead of running them)
#
# Notes:
#  * Reads /etc/master.passwd (has the password-hash field; /etc/passwd does not).
#  * "Disable" = pw lock + set shell to /usr/sbin/nologin. Nothing is deleted.
#  * Re-enable = pw unlock + restore shell from backup/fallback (see -r).
#  * SSH keys are audited (existence + perms + count + fingerprints); history is
#    audited (existence/perms) and can be enabled with -e.
#  * Keep-list (packet) users are low-risk but NOT exempt from checks: UID0/empty
#    password always apply; authorized_keys/history always audited; -k/-a offers
#    disable for them too (see -k note above). They are still nolisted as "OK"
#    if nothing is flagged, but you can still disable/re-enable them.
#  * whiteteam AND blackteam are out of scope (rules 6/14): skipped entirely.
#  * root and admin are protected: shown, but never offered for disabling.
#  * GUI SSH keys in config.xml are reported (unauth fields) but not hashed here.

MASTER="${MASTER:-/etc/master.passwd}"
GROUPF="${GROUPF:-/etc/group}"
CONFIG="${CONFIG:-/cf/conf/config.xml}"
LOG="${LOG:-/root/user_audit.log}"
DRYRUN="${DRYRUN:-0}"
ASK_ALL=0
ASK_KEEP=0
REENABLE=""
ENABLE_HIST=0
while [ $# -gt 0 ]; do
  case "$1" in
    -a) ASK_ALL=1;;
    -k) ASK_KEEP=1;;
    -r) shift; REENABLE="${1:-}";;
    -e) ENABLE_HIST=1;;
    -h|--help) sed -n '2,27p' "$0"; exit 0;;
    *) echo "unknown option $1"; exit 1;;
  esac
  shift
done

# Handle -r <user> early: re-enable without full audit loop
if [ -n "$REENABLE" ]; then
  _u="$REENABLE"
  _orig_shell=$(awk -v u="$_u" -F: '$1==u{print $NF}' "$MASTER" 2>/dev/null)
  # Try to recover original shell from backup
  _bak=$(ls -t /root/master.passwd.bak* 2>/dev/null | head -1)
  if [ -n "$_bak" ] && [ -r "$_bak" ]; then
    _b_shell=$(awk -v u="$_u" -F: '$1==u{print $NF}' "$_bak" 2>/dev/null)
    [ -n "$_b_shell" ] && _orig_shell="$_b_shell"
  fi
  case "$_orig_shell" in
    ""|*/nologin|*/false) _orig_shell="/bin/csh";;
  esac
  echo "Re-enable $_u (shell -> $_orig_shell)"
  if [ "$DRYRUN" = "1" ]; then
    echo "  [dry-run] pw unlock $_u ; pw usermod $_u -s $_orig_shell"
  else
    [ -r "$MASTER" ] || { echo "Cannot read $MASTER"; exit 1; }
    [ "$(id -u)" -eq 0 ] || { echo "Need root to re-enable"; exit 1; }
    log "REENABLE $_u (shell -> $_orig_shell)"
    if pw unlock "$_u" && pw usermod "$_u" -s "$_orig_shell"; then
      echo "Re-enabled $_u (unlocked + $_orig_shell)"
    else
      echo "pw failed for $_u - check manually"
    fi
  fi
  exit 0
fi

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

enable_user() { # enable_user <user> <shell>
  if [ "$DRYRUN" = "1" ]; then
    echo "  [dry-run] pw unlock $1 ; pw usermod $1 -s ${2:-/bin/csh}"
    return
  fi
  backup_once
  if pw unlock "$1" && pw usermod "$1" -s "${2:-/bin/csh}"; then
    echo "  ${GRN}Login re-enabled for $1 (unlocked + ${2:-/bin/csh}).${RST}"
    log "REENABLED $1 (pw unlock + ${2:-/bin/csh})"
  else
    echo "  ${RED}pw failed for $1 - check manually.${RST}"
    log "FAILED to re-enable $1"
  fi
}

# ---------- SSH-key + history audit helpers ----------
# Audit ~/.ssh dir/file perms, count keys, fingerprints; and history files.
audit_ssh_and_hist() { # audit_ssh_and_hist <home> <shell> <user>
  _h="$1"; _s="$2"; _u="$3"
  # --- SSH keys ---
  if [ -n "$_h" ] && [ -d "$_h/.ssh" ]; then
    _sp=$(stat -c "%a" "$_h/.ssh" 2>/dev/null || stat -f "%Lp" "$_h/.ssh" 2>/dev/null)
    case "$_sp" in 700) ;; *) flag 1 "home/.ssh perms $_sp (expected 700)";; esac
    for _f in "$_h/.ssh/authorized_keys" "$_h/.ssh/known_hosts" "$_h/.ssh/id_rsa" "$_h/.ssh/id_ed25519"; do
      [ -e "$_f" ] || continue
      _fp=$(stat -c "%a" "$_f" 2>/dev/null || stat -f "%Lp" "$_f" 2>/dev/null)
      case "$_fp" in 600) ;; *) flag 1 "$_f perms $_fp (expected 600)";; esac
    done
    if [ -s "$_h/.ssh/authorized_keys" ]; then
      _kc=$(grep -v '^#' "$_h/.ssh/authorized_keys" 2>/dev/null | grep -v '^$' | wc -l | tr -d ' ')
      flag 1 "has ~/.ssh/authorized_keys ($_kc keys) — review fingerprints below"
      if command -v ssh-keygen >/dev/null 2>&1; then
        echo "  authorized_keys fingerprints (_u):"
        ssh-keygen -l -f "$_h/.ssh/authorized_keys" 2>/dev/null | sed 's/^/    /'
      fi
      log "SSH_KEYS $_u $_h/.ssh/authorized_keys keys=$_kc"
    fi
  fi
  # --- shell history (csh/tcsh + bash/sh) ---
  for _hf in "$_h/.history" "$_h/.sh_history" "$_h/.bash_history" "$_h/.zsh_history"; do
    [ -e "$_hf" ] || continue
    _hp=$(stat -c "%a" "$_hf" 2>/dev/null || stat -f "%Lp" "$_hf" 2>/dev/null)
    case "$_hp" in 600) ;; *) flag 1 "$_hf perms $_hp (expected 600)";; esac
    _hs=$(wc -l < "$_hf" 2>/dev/null | tr -d ' ')
    if [ "$_hs" = "0" ]; then flag 1 "history file empty: $_hf (history disabled? enable with -e)"; fi
    log "HISTORY $_u $_hf lines=$_hs perms=$_hp"
  done
  # history disabled signals
  if [ -n "$_h" ]; then
    grep -q "set histfile=/dev/null" "$_h/.cshrc" 2>/dev/null && flag 2 "history disabled via .cshrc (set histfile=/dev/null)"
    grep -q "HISTSIZE=0" "$_h/.profile" "$_h/.bashrc" 2>/dev/null && flag 2 "history disabled (HISTSIZE=0)"
  fi
}
enable_history_for_home() { # enable_history_for_home <home> <user>
  _h="$1"; _u="$2"
  [ -z "$_h" ] && return
  mkdir -p "$_h" 2>/dev/null
  if [ ! -e "$_h/.history" ]; then
    if [ "$DRYRUN" = "1" ]; then echo "  [dry-run] touch $_h/.history (600)"
    else touch "$_h/.history" 2>/dev/null && chmod 600 "$_h/.history" 2>/dev/null && chown "$_u" "$_h/.history" 2>/dev/null; echo "  Created $_h/.history (600)"; log "HISTORY_ENABLED $_h/.history (created)"; fi
  else
    chmod 600 "$_h/.history" 2>/dev/null; chown "$_u" "$_h/.history" 2>/dev/null; echo "  Ensured $_h/.history 600"
  fi
  # cshrc lines
  for _rc in "$_h/.cshrc" "$_h/.tcshrc"; do
    [ -e "$_rc" ] || continue
    grep -q "set savehist" "$_rc" 2>/dev/null || { echo "set savehist=(1000 merge)" >> "$_rc"; echo "  appended savehist to $_rc"; log "HISTORY_ENABLED $_rc savehist"; }
    grep -q "set history=" "$_rc" 2>/dev/null || { echo "set history=1000" >> "$_rc"; echo "  appended history to $_rc"; }
    grep -q "set histfile=" "$_rc" 2>/dev/null || { echo "set histfile=~/.history" >> "$_rc"; echo "  appended histfile to $_rc"; }
    chmod 644 "$_rc" 2>/dev/null
  done
  # bash/sh profile lines
  for _pr in "$_h/.profile" "$_h/.bashrc"; do
    [ -e "$_pr" ] || continue
    grep -q "HISTFILE=" "$_pr" 2>/dev/null || { printf '\nHISTFILE=~/.bash_history\nHISTSIZE=1000\nHISTTIMEFORMAT="%%F %%T "\n' >> "$_pr"; echo "  appended HISTFILE to $_pr"; }
  done
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
  for _hf in "$1/.history" "$1/.sh_history" "$1/.bash_history"; do
    [ -e "$_hf" ] && { echo "  ls -la $_hf"; ls -l "$_hf" | sed 's/^/    /'; }
  done
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
if [ $ENABLE_HIST -eq 1 ]; then
  echo "${BLD}Enabling shell history for all users (-e) ...${RST}"
  while IFS=: read -r _n _pw _uid _gid _cls _chg _exp _gec _home _sh <&3; do
    case "$_n" in ""|\#*|whiteteam|blackteam) continue;; esac
    enable_history_for_home "$_home" "$_n"
  done 3< "$MASTER"
  echo
fi

# ---------- main loop (file on fd 3 so prompts can use stdin) ----------
while IFS=: read -r name pw uid gid class chg exp gecos home shell <&3; do
  case "$name" in ""|\#*) continue;; esac

  if [ "$name" = "whiteteam" ] || [ "$name" = "blackteam" ]; then
    echo "${BLD}$name${RST}: out of scope (rules 6/14) - skipped."
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
  fi
  # SSH keys + history: audit for ALL users (incl. KEEP) except OOS/protected is handled at prompt time
  # (protected still gets flagged here, just not offered disable)
  audit_ssh_and_hist "$home" "$shell" "$name"
  # GUI SSH key in config.xml (pfSense User Manager sshkey field) — report, don't hash
  if [ $GUI_OK -eq 1 ]; then
    _gkey=$(awk -v u="$name" -v RS='<user>' '$0 ~ "<name>" u "</name>"' "$CONFIG" 2>/dev/null | grep -o '<sshkey>[^<]*</sshkey>' 2>/dev/null | head -1)
    if [ -n "$_gkey" ]; then flag 1 "has GUI SSH key in config.xml ($name) — verify fingerprint in User Manager"; fi
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
  # Offer disable for flagged users, ALL with -a, and KEEP users with -k (or -a)
  _offer=0
  if [ $SEV -ge 1 ]; then _offer=1; fi
  if [ $ASK_ALL -eq 1 ]; then _offer=1; fi
  if [ $is_keep -eq 1 ] && [ $ASK_KEEP -eq 1 ]; then _offer=1; fi
  if [ $is_keep -eq 1 ] && [ $ASK_ALL -eq 1 ]; then _offer=1; fi
  if [ $_offer -eq 1 ]; then
    show_home "$home"
    # history enable check
    if [ $ENABLE_HIST -eq 1 ]; then
      echo "  Enabling history for $name ..."
      enable_history_for_home "$home" "$name"
    fi
    _procs=$(ps -U "$name" -o pid,etime,command 2>/dev/null | sed 1d)
    if [ -n "$_procs" ]; then
      echo "  Running processes:"; echo "$_procs" | sed 's/^/    /'
    fi
    [ $in_gui -eq 1 ] && echo "  ${CYN}Note: this is a webConfigurator user; pfSense may re-sync it from config.xml. Also disable it in System > User Manager.${RST}"
    case "$shell" in */nologin|*/false) _is_disabled=1;; *) _is_disabled=0;; esac
    case "$pw" in \**|\!*) _is_locked=1;; *) _is_locked=0;; esac
    if [ $_is_disabled -eq 1 ] || [ $_is_locked -eq 1 ]; then
      echo "  [Account appears disabled: shell=$shell locked=$_is_locked]"
      printf "  Re-enable login for '%s'? [y/N] " "$name"
      read -r rens
      case "$rens" in
        y|Y|yes|YES)
          _rs=""
          _bak=$(ls -t /root/master.passwd.bak* 2>/dev/null | head -1)
          if [ -n "$_bak" ]; then _rs=$(awk -v u="$name" -F: '$1==u{print $NF}' "$_bak" 2>/dev/null); fi
          case "$_rs" in ""|*/nologin|*/false) _rs="/bin/csh";; esac
          enable_user "$name" "$_rs"
          ;;
        *) echo "  Left as-is (disabled)."; log "SKIPPED re-enable $name";;
      esac
      printf "  Disable login for '%s'? (keep-list: %s) [y/N] " "$name" "$is_keep"
      read -r ans
    else
      printf "  Disable login for '%s'? (keep-list: %s) [y/N] " "$name" "$is_keep"
      read -r ans
    fi
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
log "=== audit end: reviewed=$TOTAL flagged=$FLAGGED disabled=$DISABLED ==="