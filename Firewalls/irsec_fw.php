#!/usr/local/bin/php -f
<?php
/*
 * irsec_fw.php - team F1SH staged pfSense ruleset + mismatch/drift alerts (IRSeC 2026)
 * UNTESTED on a live box. Test in a pfSense 2.7.2 VM first (Rule 18).
 * Run `php irsec_fw.php --help` for usage.
 */
function f1_usage() {
  echo <<<TXT

irsec_fw.php - team F1SH staged pfSense rules with mismatch/drift alerts

USAGE   php irsec_fw.php <command> [args] [flags]

COMMANDS
  preflight           Read-only checks: required dirs/files, WAN/LAN IPs, anti-lockout,
                      NAT, pre-staged rules, DataDog table. Changes nothing.
  stage1              Aliases, Rule 14 allows (NetBird, DataDog, mgmt, RITSEC), allow-all
                      to/from the Wazuh box (timing), BLOCKED_IPS blocks.
  stage2              Scored-service allows (source = ALLOWED_IPS) + Cloud->pitwall AD.
  stage3              LAN allows: teamradio->barrier, P2P admin paths, ping, DNS, allowed
                      websites, and the TEMP 80/443-to-anywhere rule.
  lockdown            MANUAL. Needs stages 1-3, >=10 min since stage1, clean verify, and you
                      typing GREEN. Adds self-deny + logged deny-all rules, disables the
                      default "allow LAN to any" rules, turns default-block logging on, then
                      auto-rolls-back (soft) unless you type KEEP in time.
  verify              Compare config AND loaded pf rules to expected. Exit 1 on any CRIT.
  watch               verify every 60s; prints only NEW alerts (incl. rules that are
                      disabled when they should be enabled, and vice versa).
  status              Applied stage, timestamps, lockdown countdown, backups.
  backup [label]      Save a manual full copy of config.xml (do this when you like the rules).
  backups             List stage and manual backups.
  rollback N          SOFT rollback: re-apply managed rules for stages < N. Touches nothing
                      else (users, aliases, NAT, logging stay as they are).
  rollback N --full   FULL restore of the whole config.xml saved before stage N.
  rollback manual     FULL restore of the newest manual backup (or give a backup file path).
  remove-temp         Remove the TEMP LAN->any 80/443 rule and re-apply.
  help                This text.

FLAGS
  -h, --help          This text (works on any machine, no pfSense needed).
  --handson           REQUIRED for anything that changes the firewall (Rule 7).
  --dry-run           Print the exact rules that would be applied; write nothing.
  --lab               Lab mode: a WAN IP that is not 172.20.1.<team> is INFO, not CRIT.
  --force             Skip safety gates (stage order, CRIT preflight, lockdown timer).
  --list              With verify/watch: also list every unmanaged rule.
  --full              With rollback: restore the whole config instead of only the rules.
  --no-deny-all       Lockdown: skip the explicit deny-all rules (self-deny stays).
  --disable-antilockout
                      Lockdown: also disable the anti-lockout rule (asks CONSOLE-OK).

TYPICAL RUN
  php irsec_fw.php preflight
  php irsec_fw.php stage1 --dry-run
  php irsec_fw.php stage1 --handson     (then stage2, stage3; check Hermes each time)
  php irsec_fw.php backup stage3-good
  php irsec_fw.php watch                (second SSH session)
  php irsec_fw.php lockdown --handson   (10+ minutes after stage1)

NOTES
  * No floating rules are created. Existing floating rules are only reported (WARN).
  * Scorer discovery: ALLOWED_IPS (network alias) is created ONCE, seeded with 10.64.0.0/16,
    and never overwritten. Scored rules log. Replace the /16 with exact IPs in the GUI when
    found. BLOCKED_IPS / ALLOWED_SITES / AI_SITES are also created once, never overwritten.
  * Rule port fields use hyphen ranges (5985-5986); alias ranges use the separator set by
    ALIAS_PORT_SEP in the script.
  * DNS_SERVERS (host alias: router, pitwall, 1.1.1.1) is also created once; every client may
    reach it on port 53, and 1.1.1.1 is allowed on all protocols.
  * ok-research (CSEC-720-RESEARCH-DO-NOT-DELETE) allows any source -> 10.64.250.228:9000.
    verify raises CRIT if it is ever missing or modified.
  * Rules are tagged F1SH:S<stage>:<id>. Old IRSEC-tagged rules are removed on next apply.
  * State/backups/alerts: /root/irsec_fw/

TXT;
}
$__a = $argv ?? [];
if (count($__a) < 2 || in_array('-h', $__a) || in_array('--help', $__a) || ($__a[1] ?? '') == 'help') { f1_usage(); exit(0); }

require_once("config.inc");
require_once("util.inc");
require_once("interfaces.inc");
require_once("filter.inc");
require_once("shaper.inc");

/* ================= EDIT THESE ================= */
$TEAM            = 5;
$TAG             = "F1SH";
$LEGACY_TAGS     = ["IRSEC"];    // rules with these tags are purged on the next apply
$ALLOWED_SEED    = "10.64.0.0/16"; // initial ALLOWED_IPS content (scorer discovery)
$FTP_PASV        = "";           // e.g. "40000-40100" to enable the FTP passive-data rule (off if empty)
$PITWALL_DNS_FWD = "any";        // narrow to pitwall's DNS forwarder IP once known
$TEMP_WEB        = true;         // TEMP LAN->any 80/443 (remove with: remove-temp)
$ALLOW_AI_SITES  = false;        // claude.ai/chatgpt.com/gemini - see Rules 12 and 23 before enabling
$LOCK_DELAY      = 600;          // seconds after stage1 before lockdown is allowed (10 min)
$CONFIRM_WINDOW  = 120;          // seconds to type KEEP after lockdown before auto-rollback
$RULE_PORT_SEP   = "-";          // port ranges inside RULES (GUI saves hyphen)
$ALIAS_PORT_SEP  = ":";          // port ranges inside port ALIASES
$ALLOWED_SITES   = ["google.com","www.google.com","docs.google.com","www.gstatic.com","www.youtube.com",
                    "clients2.google.com","f1-sh.duckdns.org","f-1sh.duckdns.org"];
$AI_SITES        = ["claude.ai","chatgpt.com","gemini.google.com"];
$RESEARCH_IP     = "10.64.250.228"; // CSEC-720-RESEARCH-DO-NOT-DELETE: all traffic to this IP:port is allowed
$RESEARCH_PORT   = "9000";
$DD              = "DataDog_IP_Table";
$DD_URL          = "https://f-1sh.duckdns.org/downloads/us5-datadog.txt";
$DIR             = "/root/irsec_fw";
/* ============================================== */

$NETBIRD = "10.$TEAM.1.99"; $MGMT = "172.16.1.0/24";
$IP = [
  'pitwall'=>"10.$TEAM.1.1", 'teamradio'=>"10.$TEAM.1.2", 'safetycar'=>"10.$TEAM.1.3",
  'pitlane'=>"10.$TEAM.1.4", 'garage'=>"10.$TEAM.1.5", 'grandstand'=>"10.$TEAM.1.6",
  'transporters'=>"192.168.$TEAM.1", 'stewards'=>"192.168.$TEAM.2",
  'scrutineering'=>"192.168.$TEAM.3", 'timing'=>"192.168.$TEAM.4",
];
$DNS_DEFAULT = ["10.$TEAM.1.254", $IP['pitwall'], "1.1.1.1"];   // router (barrier LAN), DNS server (pitwall), Cloudflare
@mkdir("$DIR/backup", 0700, true);
$ALERTS = []; $CUR = []; $PREV = []; $WATCH = false; $state = [];
$cmd = $argv[1] ?? 'help';
$POS = array_values(array_filter(array_slice($argv, 2), fn($x) => $x !== '' && $x[0] !== '-'));
$DRY = in_array('--dry-run', $argv); $FORCE = in_array('--force', $argv); $HANDS = in_array('--handson', $argv);
$LAB = in_array('--lab', $argv); $LIST = in_array('--list', $argv); $FULL = in_array('--full', $argv);
$NODENY = in_array('--no-deny-all', $argv);

/* ---------------- helpers ---------------- */
function f1_alert($lvl, $msg) {
  global $ALERTS, $CUR, $PREV, $WATCH, $DIR;
  $ALERTS[] = [$lvl, $msg]; $CUR[$lvl.$msg] = 1;
  if ($WATCH && isset($PREV[$lvl.$msg])) return;
  $c = ['CRIT'=>"\033[1;41m", 'WARN'=>"\033[1;33m", 'INFO'=>"\033[36m", 'OK'=>"\033[32m"][$lvl] ?? '';
  echo "{$c}[$lvl] $msg\033[0m\n";
  @file_put_contents("$DIR/alerts.log", date('c')." [$lvl] $msg\n", FILE_APPEND);
  // user.alert lands in the pfSense system log (local0 is excluded from it)
  if ($lvl == 'CRIT' || $lvl == 'WARN') exec('logger -p user.alert -t irsec_fw '.escapeshellarg("[$lvl] $msg"));
}
function f1_count_lvl($l) { global $ALERTS; return count(array_filter($ALERTS, fn($a) => $a[0] == $l)); }
function f1_load_state() { global $DIR; return @json_decode(@file_get_contents("$DIR/state.json"), true) ?: []; }
function f1_save_state() { global $DIR, $state; file_put_contents("$DIR/state.json", json_encode($state, JSON_PRETTY_PRINT)); }
function f1_norm($v) { if (is_array($v)) { if (!$v) return ''; ksort($v); return array_map('f1_norm', $v); } return (string)$v; }
function f1_sig($r) {
  $s = [];
  foreach (['type','interface','ipprotocol','protocol','icmptype','source','destination','floating'] as $k)
    if (isset($r[$k])) $s[$k] = f1_norm($r[$k]);
  foreach (['source','destination'] as $k)      // ':' and '-' port ranges are treated as equal
    if (isset($s[$k]['port'])) $s[$k]['port'] = str_replace(':', '-', $s[$k]['port']);
  $s['log'] = isset($r['log']);
  return json_encode($s);   // 'disabled' is checked separately (clearer alerts)
}
function f1_tag($d) { global $TAG; return "$TAG:S{$d['st']}:{$d['id']}"; }
function f1_is_ours($descr) {
  global $TAG, $LEGACY_TAGS;
  foreach (array_merge([$TAG], $LEGACY_TAGS) as $t) if (strpos($descr, "$t:") === 0) return true;
  return false;
}
function f1_psep($p, $sep) { return preg_match('/^\d+[-:]\d+$/', $p) ? preg_replace('/[-:]/', $sep, $p) : $p; }
function f1_addr($s, $p) {
  global $RULE_PORT_SEP;
  if ($s == 'any') $a = ['any'=>''];
  elseif ($s == '(self)') $a = ['network'=>'(self)'];     // "This Firewall"
  else $a = ['address'=>$s];
  if ($p !== '') $a['port'] = f1_psep($p, $RULE_PORT_SEP);
  return $a;
}
function f1_build($d) {
  global $TAG;
  $r = ['id'=>'', 'type'=>$d['type'], 'interface'=>$d['if'], 'ipprotocol'=>$d['ipp'] ?? 'inet'];
  if ($d['proto'] != 'any') $r['protocol'] = $d['proto'];
  if ($d['proto'] == 'icmp') $r['icmptype'] = 'echoreq';
  $r['source'] = f1_addr($d['src'], ''); $r['destination'] = f1_addr($d['dst'], $d['dport']);
  $r['descr'] = f1_tag($d).' '.$d['descr'];
  if (!empty($d['log'])) $r['log'] = '';
  if (!empty($d['off'])) $r['disabled'] = '';
  $r['tracker'] = (string)(1790000000 + $d['n']);        // stable per rule
  $r['created'] = ['time'=>time(), 'username'=>strtolower($TAG).'_fw']; $r['updated'] = $r['created'];
  return $r;
}
function f1_ask($prompt, $timeout = null) {
  echo $prompt;
  if ($timeout) { $r = [STDIN]; $w = $e = null; if (!stream_select($r, $w, $e, $timeout)) return null; }
  return trim((string)fgets(STDIN));
}
function f1_backup($name) {
  global $DIR, $state; $f = "$DIR/backup/$name-".time().".xml";
  copy('/cf/conf/config.xml', $f); $state['bk'][$name] = $f; return $f;
}

/* ---------------- aliases ---------------- */
function f1_alias_defs() {
  global $IP, $config;
  $lan = [$IP['pitwall'],$IP['teamradio'],$IP['safetycar'],$IP['pitlane'],$IP['garage'],$IP['grandstand']];
  $cloud = [$IP['transporters'],$IP['stewards'],$IP['scrutineering'],$IP['timing']];
  $gui = $config['system']['webgui']['port'] ?? '54431';
  return [
    'LAN_HOSTS_IND'=>['host', implode(' ', $lan)], 'CLOUD_HOSTS_IND'=>['host', implode(' ', $cloud)],
    'CLOUD_WIN'=>['host', "{$IP['transporters']} {$IP['stewards']}"],
    'RITSEC_FQDN'=>['host', 'compsole.ritsec.cloud scoring.irsec.club store.irsec.club'],
    'PORTS_AD_MEMBER'=>['port', '53 88 135 389 445 464 636 3268-3269 49152-65535'],
    'PORTS_IIS'=>['port', '80 443 8080 8888'],
    'PORTS_BARRIER_ADMIN'=>['port', implode(' ', array_unique(['22','80','443',$gui]))],
    'PORTS_TRANSPORTERS'=>['port', '5985 5986 22 3389'],
    'PORTS_WEB'=>['port', '80 443'],
  ];
}
function f1_find_alias($name) {
  global $config;
  foreach (($config['aliases']['alias'] ?? []) as $k => $a) if ($a['name'] == $name) return $k;
  return null;
}
function f1_set_alias($name, $type, $addr, $descr) {
  global $config, $ALIAS_PORT_SEP;
  if ($type == 'port') $addr = implode(' ', array_map(fn($t) => f1_psep($t, $ALIAS_PORT_SEP), preg_split('/\s+/', trim($addr))));
  $n = count(preg_split('/\s+/', trim($addr)));
  $new = ['name'=>$name, 'type'=>$type, 'address'=>$addr, 'descr'=>$descr, 'detail'=>implode('||', array_fill(0, $n, ''))];
  if (!isset($config['aliases']['alias']) || !is_array($config['aliases']['alias'])) $config['aliases']['alias'] = [];
  $k = f1_find_alias($name);
  if ($k !== null) {
    if (trim($config['aliases']['alias'][$k]['address']) != trim($addr))
      f1_alert('WARN', "alias $name existed with different content, replaced (was: {$config['aliases']['alias'][$k]['address']})");
    $config['aliases']['alias'][$k] = $new;
  } else $config['aliases']['alias'][] = $new;
}
function f1_create_once($name, $type, $addr, $descr) {   // user-edited lists: never overwritten
  if (f1_find_alias($name) === null) f1_set_alias($name, $type, $addr, $descr);
}
function f1_ensure_aliases() {
  global $ALLOWED_SEED, $ALLOWED_SITES, $AI_SITES, $DNS_DEFAULT;
  foreach (f1_alias_defs() as $n => $d) f1_set_alias($n, $d[0], $d[1], 'F1SH fw managed');
  f1_create_once('BLOCKED_IPS', 'host', '192.0.2.1', 'confirmed malicious IPs ONLY (seeded w/ doc addr)');
  f1_create_once('ALLOWED_IPS', 'network', $ALLOWED_SEED, 'scorer source IPs; seeded with the /16 for discovery - replace with exact IPs');
  f1_create_once('ALLOWED_SITES', 'host', implode(' ', $ALLOWED_SITES), 'websites LAN hosts may reach on 80/443');
  f1_create_once('DNS_SERVERS', 'host', implode(' ', $DNS_DEFAULT), 'DNS servers every client may use (router, pitwall, 1.1.1.1) - edit freely');
  f1_create_once('AI_SITES', 'host', implode(' ', $AI_SITES), 'AI chatbot sites (rule off unless ALLOW_AI_SITES)');
}
function f1_dd_count() {
  global $DD;
  return (int)trim((string)shell_exec('/sbin/pfctl -t '.escapeshellarg($DD).' -T show 2>/dev/null | /usr/bin/wc -l'));
}
function f1_dd_check($lvl = 'CRIT') {
  global $DD, $DD_URL, $config;
  $k = f1_find_alias($DD);
  if ($k === null) { f1_alert($lvl, "alias $DD does not exist (stage1 creates it)"); return false; }
  $a = $config['aliases']['alias'][$k];
  if (($a['type'] ?? '') != 'urltable') f1_alert('CRIT', "alias $DD is type '".($a['type'] ?? '?')."', expected urltable");
  elseif (($a['url'] ?? '') != $DD_URL) f1_alert('WARN', "alias $DD url is '".($a['url'] ?? '')."', expected $DD_URL");
  $c = f1_dd_count();
  if ($c == 0) { f1_alert($lvl, "$DD table is EMPTY. Rule 14: DataDog traffic must not be blocked. Can barrier resolve+reach the URL?"); return false; }
  if ($c < 50) f1_alert('WARN', "$DD table has only $c entries (lab list had ~190)");
  return true;
}
function f1_ensure_dd_alias() {   // runs BEFORE any rule references the alias
  global $config, $DD, $DD_URL, $FORCE;
  if (f1_find_alias($DD) === null) {
    if (!isset($config['aliases']['alias']) || !is_array($config['aliases']['alias'])) $config['aliases']['alias'] = [];
    $config['aliases']['alias'][] = ['name'=>$DD, 'type'=>'urltable', 'url'=>$DD_URL, 'updatefreq'=>'12',
      'address'=>$DD_URL, 'descr'=>'DataDog us5 IPs (Rule 14)', 'detail'=>'Entry added '.date('r')];
    write_config("irsec_fw: create $DD urltable alias"); filter_configure();
    f1_alert('INFO', "created urltable alias $DD");
  }
  if (f1_dd_count() == 0) {      // not downloaded yet: force the fetch (usage from memory of rc.update_urltables)
    passthru('/etc/rc.update_urltables now forceupdate'); sleep(3);
  }
  if (!f1_dd_check('CRIT') && !$FORCE) die("DataDog table is empty - fix before applying rules (or --force).\n");
}

/* ---------------- rule table (interface rules only, no floating) ---------------- */
function f1_rule_defs($upto) {
  global $IP, $NETBIRD, $MGMT, $RESEARCH_IP, $RESEARCH_PORT, $FTP_PASV, $PITWALL_DNS_FWD, $TEMP_WEB, $ALLOW_AI_SITES, $NODENY, $DD, $state;
  $R = [];
  $A = function ($st, $id, $type, $if, $proto, $src, $dst, $dport, $descr, $o = []) use (&$R) {
    $R[] = array_merge(compact('st','id','type','if','proto','src','dst','dport','descr'), $o);
  };
  $SC = 'ALLOWED_IPS';
  // ---- Stage 1: Rule 14 + trusted Wazuh box (allowed first), then targeted blocks
  $A(1,'ok-nb','pass','lan','any',$NETBIRD,'any','','Rule14 NetBird egress');
  $A(1,'ok-dd-in','pass','wan','any',$DD,'any','','Rule14 DataDog in',['ipp'=>'inet46']);
  $A(1,'ok-dd-out','pass','lan','any','any',$DD,'','Rule14 DataDog out',['ipp'=>'inet46']);
  $A(1,'ok-mgmt-in','pass','wan','any',$MGMT,'any','','Rule14/15 mgmt in');
  $A(1,'ok-mgmt-out','pass','lan','any','any',$MGMT,'','Rule14/15 mgmt out');
  $A(1,'ok-ritsec','pass','lan','any','any','RITSEC_FQDN','','Rule14 RITSEC FQDN');
  $A(1,'ok-tm-in','pass','lan','any','any',$IP['timing'],'','ALL traffic to Wazuh (timing)');
  $A(1,'ok-tm-out','pass','wan','any',$IP['timing'],'any','','ALL traffic from Wazuh (timing)');
  $A(1,'ok-dns-lan','pass','lan','tcp/udp','any','DNS_SERVERS','53','All clients -> DNS_SERVERS (LAN side)');
  $A(1,'ok-dns-wan','pass','wan','tcp/udp','any','DNS_SERVERS','53','All clients -> DNS_SERVERS (WAN side)');
  $A(1,'ok-cf','pass','lan','any','any','1.1.1.1','','Allow 1.1.1.1 (all protocols: ping, DoT, DoH)');
  $A(1,'ok-research','pass','lan','tcp/udp','any',$RESEARCH_IP,$RESEARCH_PORT,'CSEC-720-RESEARCH-DO-NOT-DELETE');
  $A(1,'bl-wan','block','wan','any','BLOCKED_IPS','any','','BLOCKED_IPS in',['log'=>1]);
  $A(1,'bl-lan','block','lan','any','any','BLOCKED_IPS','','BLOCKED_IPS out',['log'=>1]);
  // ---- Stage 2: scored services (confirmed ports), source = ALLOWED_IPS, logged for discovery
  $A(2,'w-dns','pass','wan','udp',$SC,$IP['pitwall'],'53','Scored DNS',['log'=>1]);
  $A(2,'w-ldap','pass','wan','tcp',$SC,$IP['pitwall'],'389','Scored LDAP',['log'=>1]);
  $A(2,'w-winrm','pass','wan','tcp',$SC,$IP['teamradio'],'5985','Scored WinRM',['log'=>1]);
  $A(2,'w-icmp','pass','wan','icmp',$SC,$IP['safetycar'],'','Scored ICMP',['log'=>1]);
  $A(2,'w-telnet','pass','wan','tcp',$SC,$IP['safetycar'],'23','Scored Telnet',['log'=>1]);
  $A(2,'w-ssh','pass','wan','tcp',$SC,$IP['pitlane'],'22','Scored SSH',['log'=>1]);
  $A(2,'w-ftp','pass','wan','tcp',$SC,$IP['garage'],'21','Scored FTP',['log'=>1]);
  $A(2,'w-ftp-pasv','pass','wan','tcp',$SC,$IP['garage'],$FTP_PASV !== '' ? $FTP_PASV : '1024-65535','FTP passive data',['off'=>$FTP_PASV === '']);
  $A(2,'w-irc','pass','wan','tcp',$SC,$IP['grandstand'],'6669','Scored IRC',['log'=>1]);
  // Cloud scored services: only matter if scorer->Cloud traffic actually crosses barrier
  $A(2,'w-smb','pass','wan','tcp',$SC,$IP['transporters'],'445','Scored SMB',['log'=>1]);
  $A(2,'w-iis','pass','wan','tcp',$SC,$IP['stewards'],'PORTS_IIS','Scored IIS',['log'=>1]);
  $A(2,'w-sql','pass','wan','tcp',$SC,$IP['scrutineering'],'3306','Scored MariaDB (assumed scrutineering)',['log'=>1]);
  $A(2,'w-cwin-ad','pass','wan','tcp/udp','CLOUD_WIN',$IP['pitwall'],'PORTS_AD_MEMBER','Cloud Windows -> AD');
  $A(2,'w-scr-dns','pass','wan','tcp/udp',$IP['scrutineering'],$IP['pitwall'],'53','scrutineering -> DNS');
  // ---- Stage 3: LAN admin / P2P / egress
  $A(3,'l-admin','pass','lan','tcp',$IP['teamradio'],'(self)','PORTS_BARRIER_ADMIN','teamradio -> barrier SSH/HTTP/HTTPS/GUI');
  $A(3,'l-pl-tp','pass','lan','tcp',$IP['pitlane'],$IP['transporters'],'PORTS_TRANSPORTERS','pitlane -> transporters');
  $A(3,'l-pl-tp-u','pass','lan','udp',$IP['pitlane'],$IP['transporters'],'3389','pitlane -> transporters RDP/UDP');
  $A(3,'l-gs-st','pass','lan','tcp/udp',$IP['grandstand'],$IP['stewards'],'3389','grandstand -> stewards RDP');
  $A(3,'l-ga-sc','pass','lan','tcp',$IP['garage'],$IP['scrutineering'],'22','garage -> scrutineering SSH');
  $A(3,'l-icmp','pass','lan','icmp','LAN_HOSTS_IND','CLOUD_HOSTS_IND','','LAN->Cloud ping');
  $A(3,'l-dns','pass','lan','tcp/udp',$IP['pitwall'],$PITWALL_DNS_FWD,'53','pitwall upstream DNS');
  $A(3,'l-sites','pass','lan','tcp','LAN_HOSTS_IND','ALLOWED_SITES','PORTS_WEB','allowed websites');
  $A(3,'l-ai','pass','lan','tcp','LAN_HOSTS_IND','AI_SITES','PORTS_WEB','AI chatbot sites (Rules 12/23!)',['off'=>!$ALLOW_AI_SITES]);
  $A(3,'temp-web','pass','lan','tcp','LAN_HOSTS_IND','any','PORTS_WEB','TEMP tool downloads - remove-temp',['log'=>1]);
  // ---- Stage 4: deny rules (manual lockdown only), all logged
  $A(4,'d-self-lan','block','lan','any','any','(self)','','Deny traffic to barrier (LAN)',['log'=>1]);
  $A(4,'d-self-wan','block','wan','any','any','(self)','','Deny traffic to barrier (WAN)',['log'=>1]);
  $A(4,'d-all-lan','block','lan','any','any','any','','DENY ALL LAN',['log'=>1]);
  $A(4,'d-all-wan','block','wan','any','any','any','','DENY ALL WAN',['log'=>1]);
  $out = [];
  foreach ($R as $n => $d) {
    $d['n'] = $n;
    if ($d['st'] > $upto || in_array($d['id'], $state['skip'] ?? [])) continue;
    if ($d['id'] == 'temp-web' && !$TEMP_WEB) continue;
    if (in_array($d['id'], ['d-all-lan','d-all-wan']) && $NODENY) continue;
    $out[] = $d;
  }
  return $out;
}

/* ---------------- checks ---------------- */
function f1_file_checks() {
  global $DIR;
  $need = [
    ['dir',  $DIR, 'CRIT'], ['dir', "$DIR/backup", 'CRIT'], ['dir', '/cf/conf', 'CRIT'],
    ['file', '/cf/conf/config.xml', 'CRIT'], ['file', '/etc/version', 'WARN'],
    ['file', '/sbin/pfctl', 'CRIT'], ['file', '/usr/local/bin/php', 'CRIT'], ['file', '/usr/bin/wc', 'CRIT'],
    ['file', '/usr/bin/logger', 'WARN'], ['file', '/etc/rc.update_urltables', 'WARN'],
    ['dir',  '/var/db/aliastables', 'WARN'], ['file', '/var/log/filter.log', 'WARN'],
    ['dir',  '/cf/conf/backup', 'INFO'], ['file', '/tmp/rules.debug', 'INFO'],
  ];
  $bad = 0;
  foreach ($need as [$t, $p, $lvl]) {
    $ok = $t == 'dir' ? is_dir($p) : is_file($p);
    if (!$ok) { f1_alert($lvl, "missing $t: $p"); $bad++; }
  }
  foreach ([$DIR, "$DIR/backup"] as $d) if (is_dir($d) && !is_writable($d)) { f1_alert('CRIT', "not writable: $d"); $bad++; }
  if (is_file('/cf/conf/config.xml') && !is_writable('/cf/conf/config.xml')) { f1_alert('CRIT', 'config.xml not writable (run as root)'); $bad++; }
  if (is_file("$DIR/state.json") && (!is_readable("$DIR/state.json") || !is_writable("$DIR/state.json"))) { f1_alert('CRIT', "state.json not readable/writable"); $bad++; }
  if (@file_put_contents("$DIR/alerts.log", '', FILE_APPEND) === false) { f1_alert('CRIT', "cannot write $DIR/alerts.log"); $bad++; }
  if (!$bad) f1_alert('OK', 'all required directories and files present and writable');
  return $bad;
}
function f1_env_checks($n) {
  global $config, $TEAM, $LAB, $ALLOW_AI_SITES;
  $v = trim((string)@file_get_contents('/etc/version'));
  if (strpos($v, '2.7.2') !== 0) f1_alert('WARN', "pfSense version '$v' (script written for 2.7.2)");
  $w = function_exists('get_interface_ip') ? (string)get_interface_ip('wan') : '';
  if ($w == '') $w = $config['interfaces']['wan']['ipaddr'] ?? '?';
  $l = $config['interfaces']['lan']['ipaddr'] ?? '?';
  if ($w != "172.20.1.$TEAM") f1_alert($LAB ? 'INFO' : 'CRIT', "WAN ip is $w, expected 172.20.1.$TEAM".($LAB ? ' (lab mode: ignored)' : ' (wrong team number / interface mapping?)'));
  if ($l != "10.$TEAM.1.254") f1_alert('CRIT', "LAN ip is $l, expected 10.$TEAM.1.254");
  if (isset($config['interfaces']['wan']['blockpriv']))
    f1_alert('CRIT', 'WAN "Block private networks" is ON: it blocks RFC1918 sources (mgmt, Cloud, scorer?) BEFORE your rules. Interfaces > WAN.');
  if (isset($config['interfaces']['wan']['blockbogons'])) f1_alert('INFO', 'WAN "Block bogon networks" is on');
  $wg = $config['system']['webgui'] ?? [];
  if (($wg['port'] ?? '') != '54431') f1_alert('WARN', 'GUI port is '.($wg['port'] ?? 'default').', sheet assumes 54431 (alias uses the real port)');
  if (($wg['protocol'] ?? '') != 'https') f1_alert('WARN', 'GUI protocol is not https');
  f1_alert('INFO', isset($wg['noantilockout']) ? 'anti-lockout rule is DISABLED (l-admin keeps teamradio in)' : 'anti-lockout rule is ENABLED: any LAN host can reach GUI/SSH regardless of self-deny');
  if (!isset($config['system']['ssh']['enable'])) f1_alert('WARN', 'SSH is not enabled on barrier (teamradio SSH rule is moot)');
  $m = $config['nat']['outbound']['mode'] ?? 'automatic';
  if ($m != 'automatic') f1_alert('WARN', "outbound NAT mode is '$m' (expected automatic) - topology changed? (Rule 10)");
  if (!empty($config['nat']['rule'])) f1_alert('WARN', count($config['nat']['rule']).' NAT port forward(s) present - review');
  if (!empty($config['nat']['onetoone'])) f1_alert('WARN', '1:1 NAT entries present - review');
  if (!empty($config['ifgroups']['ifgroupentry'])) f1_alert('WARN', 'interface groups exist (group rules run BEFORE interface rules) - review');
  if (isset($config['syslog']['nologdefaultblock'])) f1_alert($n >= 4 ? 'WARN' : 'INFO', 'default-block logging is OFF (Status > System Logs > Settings)');
  if ($ALLOW_AI_SITES && !$LAB) f1_alert('WARN', 'ALLOW_AI_SITES is on: Rule 23 only allows AI chatbots on your physical competitor machine/personal device, and Rule 12 forbids exfiltration');
  f1_alert('INFO', 'Not machine-checkable here: Ethernet (L2) rules tab, NAT source seen by Cloud hosts (Diagnostics > States), host firewalls');
}
function f1_verify($n) {
  global $config, $ALERTS, $CUR, $LIST, $ALLOWED_SEED, $TAG;
  $ALERTS = []; $CUR = [];
  $config = parse_config(true);
  f1_env_checks($n);
  f1_dd_check('CRIT');
  $k = f1_find_alias('ALLOWED_IPS');
  if ($k !== null && in_array($ALLOWED_SEED, preg_split('/\s+/', trim($config['aliases']['alias'][$k]['address']))))
    f1_alert($n >= 4 ? 'WARN' : 'INFO', "ALLOWED_IPS still contains $ALLOWED_SEED (scorer discovery open) - replace with exact scorer IPs, then deny-all is fully effective");
  $defs = f1_rule_defs($n); $rules = $config['filter']['rule'] ?? [];
  $byTag = [];
  foreach ($rules as $r) if (strpos($r['descr'] ?? '', "$TAG:") === 0) $byTag[explode(' ', $r['descr'])[0]] = $r;
  foreach ($defs as $d) {
    $t = f1_tag($d);
    if (!isset($byTag[$t])) { f1_alert('CRIT', "MISSING rule $t"); continue; }
    $r = $byTag[$t]; $wantOff = !empty($d['off']); $isOff = isset($r['disabled']);
    if ($wantOff && !$isOff) f1_alert('WARN', "rule $t is ENABLED but should be DISABLED");
    if (!$wantOff && $isOff) f1_alert('WARN', "rule $t is DISABLED but should be ENABLED");
    if (f1_sig($r) != f1_sig(f1_build($d))) f1_alert('CRIT', "MODIFIED rule $t (differs from expected)");
  }
  $exp = array_map('f1_tag', $defs); $front = [];
  foreach (array_slice($rules, 0, count($exp)) as $r) $front[] = explode(' ', $r['descr'] ?? '')[0];
  if ($front !== $exp || count($byTag) != count($exp)) f1_alert('CRIT', 'managed rules are reordered, duplicated, or something sits above them');
  $other = 0;
  foreach ($rules as $r) {
    $dsc = $r['descr'] ?? ''; $lbl = $dsc !== '' ? $dsc : '(no descr)';
    if (strpos($dsc, "$TAG:") === 0) continue;
    if (f1_is_ours($dsc)) { f1_alert('WARN', "stale rule from an older script version: $lbl (removed on next apply)"); continue; }
    if (isset($r['disabled'])) {
      if ($n >= 4 && preg_match('/^Default allow LAN/', $dsc)) continue;      // expected disabled
      continue;
    }
    if (isset($r['floating'])) f1_alert('WARN', "unmanaged FLOATING rule (runs before interface rules, can override yours): $lbl [{$r['interface']}]");
    elseif (preg_match('/^Default allow LAN/', $dsc)) { if ($n >= 4) f1_alert('WARN', "default allow rule is ENABLED but should be DISABLED after lockdown: $lbl"); }
    elseif (($r['type'] ?? 'pass') == 'pass' && isset($r['source']['any']) && isset($r['destination']['any']))
      f1_alert($n >= 4 ? 'CRIT' : 'WARN', "unmanaged allow-any rule on {$r['interface']}: $lbl");
    else { $other++; if ($LIST) f1_alert('INFO', "unmanaged rule on {$r['interface']}: $lbl ({$r['type']})"); }
  }
  if ($other && !$LIST) f1_alert('INFO', "$other other enabled unmanaged rule(s); use --list to show them");
  $pf = (string)shell_exec('/sbin/pfctl -sr 2>&1');
  foreach ($defs as $d) {
    $t = f1_tag($d); $cfgOn = isset($byTag[$t]) && !isset($byTag[$t]['disabled']);
    $loaded = strpos($pf, $t.' ') !== false;
    if ($cfgOn && !$loaded) f1_alert('CRIT', "enabled in config but NOT LOADED in pf: $t (alias/filter error?)");
    if (!$cfgOn && isset($byTag[$t]) && $loaded) f1_alert('WARN', "disabled in config but still loaded in pf: $t");
  }
  if (is_file('/tmp/rules.debug')) {
    $e = trim((string)shell_exec('/sbin/pfctl -nf /tmp/rules.debug 2>&1'));
    if ($e != '') f1_alert('WARN', 'pfctl parse output: '.str_replace("\n", ' | ', $e));
  }
  $c = f1_count_lvl('CRIT'); $w = f1_count_lvl('WARN');
  f1_alert($c ? 'CRIT' : 'OK', "verify(stage<=$n): $c CRIT, $w WARN, ".count($defs).' managed rules expected');
  return $c;
}

/* ---------------- actions ---------------- */
function f1_apply_stage($n) {
  global $config, $DRY, $FORCE, $state, $HANDS;
  $defs = f1_rule_defs($n);
  if ($DRY) {
    foreach ($defs as $d) echo (!empty($d['off']) ? '[off] ' : '      ').str_pad(f1_tag($d), 26)." {$d['type']} {$d['if']} {$d['proto']} {$d['src']} -> {$d['dst']}".($d['dport'] !== '' ? ":{$d['dport']}" : '')."\n";
    return;
  }
  if (!$HANDS) die("Rule 7: add --handson to confirm this is a hands-on period.\n");
  $prev = $state['applied'] ?? 0;
  if ($n > 1 && $prev < $n - 1 && !$FORCE) die("Apply stage ".($n-1)." first (or --force).\n");
  $config = parse_config(true);
  if ($n == 1) {
    f1_file_checks(); f1_env_checks(1);
    if (f1_count_lvl('CRIT') && !$FORCE) die("Preflight CRIT - fix or --force.\n");
  }
  if ($n >= 1) f1_backup("before-stage$n");
  if ($n >= 1) { f1_ensure_dd_alias(); $config = parse_config(true); f1_ensure_aliases(); }
  $others = [];
  foreach (($config['filter']['rule'] ?? []) as $r) if (!f1_is_ours($r['descr'] ?? '')) $others[] = $r;
  if ($n >= 4) f1_lockdown_extras($others); else f1_lockdown_undo($others);
  $managed = []; foreach ($defs as $d) $managed[] = f1_build($d);
  $config['filter']['rule'] = array_merge($managed, $others);
  write_config("irsec_fw: stage $n");
  filter_configure(); sleep(3);
  $state['applied'] = $n; $state['t'][$n] = time(); f1_save_state();
  f1_verify($n);
}
function f1_lockdown_extras(&$others) {
  global $config, $state;
  foreach ($others as &$r)
    if (preg_match('/^Default allow LAN( IPv6)? to any rule/', $r['descr'] ?? '') && !isset($r['disabled'])) {
      $r['disabled'] = ''; $state['dd_off'][] = $r['descr']; f1_alert('INFO', "disabled: {$r['descr']}");
    }
  unset($r);
  unset($config['syslog']['nologdefaultblock']);   // make sure default-block hits are logged
  if (in_array('--disable-antilockout', $GLOBALS['argv']) && !isset($config['system']['webgui']['noantilockout'])) {
    if (f1_ask("Compsole console to barrier open and teamradio->barrier rule working? type CONSOLE-OK: ") !== 'CONSOLE-OK') die("aborted\n");
    $config['system']['webgui']['noantilockout'] = ''; $state['al_off'] = true;
  }
}
function f1_lockdown_undo(&$others) {   // undo what lockdown changed (used by soft rollback)
  global $config, $state;
  if (!empty($state['dd_off'])) {
    foreach ($others as &$r) if (in_array($r['descr'] ?? '', $state['dd_off'])) unset($r['disabled']);
    unset($r); unset($state['dd_off']); f1_alert('INFO', 're-enabled default allow rules disabled by lockdown');
  }
  if (!empty($state['al_off'])) { unset($config['system']['webgui']['noantilockout']); unset($state['al_off']); f1_alert('INFO', 'anti-lockout rule re-enabled'); }
}
function f1_lockdown() {
  global $state, $LOCK_DELAY, $CONFIRM_WINDOW, $FORCE, $config, $HANDS;
  if (!$HANDS) die("Rule 7: add --handson to confirm this is a hands-on period.\n");
  if (($state['applied'] ?? 0) < 3 && !$FORCE) die("Stages 1-3 must be applied first.\n");
  $el = time() - ($state['t'][1] ?? time());
  if ($el < $LOCK_DELAY && !$FORCE) die("Too early: ".($LOCK_DELAY - $el)."s left (or --force).\n");
  $config = parse_config(true);
  if (f1_verify(3) > 0 && !$FORCE) die("verify has CRIT alerts - resolve first (or --force).\n");
  echo "Reminder: deny-all is logged (Status > System Logs > Firewall). Anything not allowed above, incl. LAN hosts using barrier for DNS/NTP, will break.\n";
  if (f1_ask("Hermes team dashboard ALL GREEN? type GREEN to apply deny rules: ") !== 'GREEN') die("aborted\n");
  f1_apply_stage(4);
  echo "\nDeny rules applied. Check Hermes NOW. You have {$CONFIRM_WINDOW}s to type KEEP, else automatic SOFT rollback.\n";
  if (f1_ask("> ", $CONFIRM_WINDOW) !== 'KEEP') { f1_alert('CRIT', 'no confirmation - soft-rolling back lockdown'); f1_soft_rollback(4); }
  else f1_alert('OK', 'lockdown confirmed');
}
function f1_soft_rollback($n) {
  f1_alert('WARN', "SOFT rollback: re-applying managed rules for stages < $n. Users, aliases, NAT, logging and other settings are NOT touched.");
  f1_apply_stage($n - 1);
}
function f1_full_restore($f, $applied) {
  global $state;
  if (!is_file($f)) die("backup file not found: $f\n");
  if (f1_ask("FULL restore replaces the ENTIRE config (users/passwords/keys, aliases incl. BLOCKED_IPS+ALLOWED_IPS, NAT, DHCP, syslog...). Type FULL: ") !== 'FULL') die("aborted\n");
  copy($f, '/cf/conf/config.xml'); @unlink('/tmp/config.cache');
  passthru('/usr/local/bin/php -r '.escapeshellarg('require_once("config.inc");require_once("util.inc");require_once("filter.inc");filter_configure();'));
  $state['applied'] = $applied; f1_save_state();
  f1_alert('WARN', "FULL restore from $f. Only the firewall was reloaded: GUI/sshd/syslog/DHCP keep running old settings until reloaded or rebooted.");
}
function f1_rollback_cmd($arg) {
  global $state, $FULL;
  $isN = preg_match('/^\d+$/', $arg);
  if ($isN && !$FULL) { f1_soft_rollback((int)$arg); return; }
  if ($isN) { $f = $state['bk']["before-stage$arg"] ?? ''; f1_full_restore($f, max(0, (int)$arg - 1)); return; }
  if ($arg === 'manual') {
    $m = $state['manual'] ?? []; $last = end($m);
    if (!$last) die("no manual backups (use: backup [label])\n");
    f1_full_restore($last['file'], $last['applied']); return;
  }
  if ($arg !== '' && is_file($arg)) { f1_full_restore($arg, $state['applied'] ?? 0); return; }
  die("usage: rollback <N | N --full | manual | /path/to/backup.xml>\n");
}
function f1_manual_backup($label) {
  global $state, $DIR;
  $label = preg_replace('/[^A-Za-z0-9_-]/', '', $label) ?: 'manual';
  $f = "$DIR/backup/manual-$label-".date('Ymd-His').".xml";
  if (!copy('/cf/conf/config.xml', $f)) die("backup failed\n");
  $state['manual'][] = ['t'=>time(), 'file'=>$f, 'label'=>$label, 'applied'=>$state['applied'] ?? 0];
  f1_save_state();
  f1_alert('OK', "manual backup saved: $f (managed stage at backup time: ".($state['applied'] ?? 0).')');
}
function f1_list_backups() {
  global $state;
  foreach (($state['manual'] ?? []) as $i => $m) echo "manual #".($i+1)." ".date('H:i:s', $m['t'])." stage {$m['applied']} {$m['file']}\n";
  foreach (($state['bk'] ?? []) as $k => $f) echo "$k  $f\n";
}
function f1_status() {
  global $state, $LOCK_DELAY;
  $a = $state['applied'] ?? 0; echo "applied stage: $a\n";
  foreach (($state['t'] ?? []) as $s => $t) echo " stage $s at ".date('H:i:s', $t)."\n";
  if (isset($state['t'][1])) { $left = $LOCK_DELAY - (time() - $state['t'][1]);
    echo $left > 0 ? " lockdown unlocks in ".floor($left/60)."m ".($left%60)."s\n" : " lockdown is unlocked\n"; }
  if (!empty($state['skip'])) echo " removed: ".implode(',', $state['skip'])."\n";
  echo " manual backups: ".count($state['manual'] ?? [])."\n";
}

/* ---------------- main ---------------- */
$state = f1_load_state();
switch ($cmd) {
  case 'preflight': f1_file_checks(); $config = parse_config(true); f1_env_checks(0); f1_dd_check('WARN'); break;
  case 'stage1': f1_apply_stage(1); break;
  case 'stage2': f1_apply_stage(2); break;
  case 'stage3': f1_apply_stage(3); break;
  case 'lockdown': $DRY ? f1_apply_stage(4) : f1_lockdown(); break;
  case 'verify': exit(f1_verify($state['applied'] ?? 0) ? 1 : 0);
  case 'status': f1_status(); break;
  case 'backup': f1_manual_backup($POS[0] ?? ''); break;
  case 'backups': f1_list_backups(); break;
  case 'rollback':
    if (!$HANDS) die("add --handson\n");
    $config = parse_config(true); f1_rollback_cmd($POS[0] ?? ''); break;
  case 'remove-temp':
    if (!$HANDS) die("add --handson\n");
    $state['skip'][] = 'temp-web'; f1_save_state(); $config = parse_config(true);
    if (($state['applied'] ?? 0) > 0) { $a = $state['applied']; $state['applied'] = $a - 1; f1_apply_stage($a); }
    break;
  case 'watch':
    $WATCH = true;
    while (true) { $state = f1_load_state(); $PREV = $CUR; $CUR = [];
      if (($state['applied'] ?? 0) > 0) f1_verify($state['applied']); else { $config = parse_config(true); f1_env_checks(0); f1_dd_check('WARN'); }
      sleep(60); }
  default: f1_usage();
}
