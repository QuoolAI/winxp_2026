/* XP25 security baseline and audit: portable C89 core. See sec_core.h. */
#include "sec_core.h"

/* ---- small freestanding helpers (no C runtime dependency) -------------- */
static size_t length(const char *s) { size_t n = 0; while (s[n]) ++n; return n; }
static char lower(char c) { return (char)(c >= 'A' && c <= 'Z' ? c + 32 : c); }
static char slash(char c) { return (char)(c == '/' ? '\\' : lower(c)); }

int sec_equal_nocase(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a && lower(*a) == lower(*b)) { ++a; ++b; }
    return *a == 0 && *b == 0;
}

static int equal(const char *a, const char *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return *a == 0 && *b == 0;
}

/* Case- and separator-insensitive prefix test that ends at a path boundary. */
static int under(const char *path, const char *directory)
{
    size_t i;
    if (!directory || !directory[0]) return 0;
    for (i = 0; directory[i]; ++i)
        if (slash(path[i]) != slash(directory[i])) return 0;
    if (i && (directory[i - 1] == '\\' || directory[i - 1] == '/')) return 1;
    return path[i] == 0 || path[i] == '\\' || path[i] == '/';
}

static int contains_nocase(const char *text, const char *part)
{
    size_t i, j;
    for (i = 0; text[i]; ++i) {
        for (j = 0; part[j] && slash(text[i + j]) == slash(part[j]); ++j) { }
        if (!part[j]) return 1;
    }
    return 0;
}

/* ---- Service baseline --------------------------------------------------- */
static const SEC_SERVICE_RULE service_rules[] = {
    {"RemoteRegistry", SEC_START_DISABLED, SEC_SVC_REMOTE_ADMIN | SEC_SVC_NETWORK_LISTENER,
     "Remote registry access over the winreg named pipe is remote administration nobody uses on a desktop.",
     "Remote registry editing and some remote management tools stop working until an administrator re-enables the service."},
    {"LanmanServer", SEC_START_DISABLED, SEC_SVC_NETWORK_LISTENER | SEC_SVC_LEGACY_PROTOCOL,
     "The Server service is the inbound SMBv1 file, print and named-pipe server (srv.sys), the main remote attack surface of NT 5.1.",
     "This computer no longer shares folders or printers and no longer exposes administrative shares. Access to other computers' shares is unaffected."},
    {"Browser", SEC_START_DISABLED, SEC_SVC_LEGACY_DISCOVERY,
     "Computer Browser takes part in NetBIOS browse elections and depends on the Server service.",
     "This computer does not announce itself in Network Neighborhood."},
    {"SSDPSRV", SEC_START_DISABLED, SEC_SVC_LEGACY_DISCOVERY | SEC_SVC_NETWORK_LISTENER,
     "SSDP discovery listens for UPnP announcements on the local network.",
     "Networked UPnP devices are not listed in My Network Places."},
    {"upnphost", SEC_START_DISABLED, SEC_SVC_LEGACY_DISCOVERY | SEC_SVC_NETWORK_LISTENER,
     "Universal Plug and Play Device Host accepts HTTP requests for hosted UPnP devices.",
     "Programs cannot publish UPnP devices from this computer."},
    {"WebClient", SEC_START_DISABLED, SEC_SVC_LEGACY_PROTOCOL,
     "The WebDAV redirector lets a UNC path or link reach arbitrary HTTP servers and forwards credentials to them.",
     "WebDAV servers cannot be opened as UNC paths or mapped drives; Web Folders in Explorer are separate and remain."},
    {"RDSessMgr", SEC_START_DISABLED, SEC_SVC_REMOTE_ADMIN,
     "Remote Desktop Help Session Manager serves Remote Assistance invitations.",
     "Remote Assistance is unavailable."},
    {"mnmsrvc", SEC_START_DISABLED, SEC_SVC_REMOTE_ADMIN,
     "NetMeeting Remote Desktop Sharing gives remote control of the desktop.",
     "NetMeeting desktop sharing is unavailable."},
    {"PolicyAgent", SEC_START_DISABLED, SEC_SVC_NETWORK_LISTENER,
     "IPSEC Services runs the IKE negotiator inside LSASS and receives unauthenticated UDP 500 datagrams.",
     "IPsec policies and L2TP/IPsec VPN connections do not work until an administrator re-enables the service."},
    {"wuauserv", SEC_START_DISABLED, SEC_SVC_RETIRED_ENDPOINT,
     "Automatic Updates polls update servers that no longer serve NT 5.1; its SHA-1 era trust chain is a spoofing target.",
     "Windows Update and Microsoft Update no longer run. XP25 updates need their own signed channel."},
    {"ERSvc", SEC_START_DISABLED, SEC_SVC_RETIRED_ENDPOINT,
     "Error Reporting uploads crash data, including memory contents, to a retired vendor endpoint.",
     "Crashes show the plain application error dialog without the report prompt."},
    {"Messenger", SEC_START_DISABLED, SEC_SVC_NETWORK_LISTENER | SEC_SVC_LEGACY_PROTOCOL,
     "Messenger displays unauthenticated network popups (net send).", "None: already disabled by Service Pack 2."},
    {"Alerter", SEC_START_DISABLED, SEC_SVC_LEGACY_PROTOCOL,
     "Alerter forwards administrative alerts through Messenger.", "None: already disabled by Service Pack 2."},
    {"NetDDE", SEC_START_DISABLED, SEC_SVC_NETWORK_LISTENER | SEC_SVC_LEGACY_PROTOCOL,
     "Network DDE exposes DDE shares to other computers.", "None: already disabled by Service Pack 2."},
    {"NetDDEdsdm", SEC_START_DISABLED, SEC_SVC_LEGACY_PROTOCOL,
     "Network DDE share database manager.", "None: already disabled by Service Pack 2."},
    {"ClipSrv", SEC_START_DISABLED, SEC_SVC_LEGACY_PROTOCOL,
     "ClipBook shares clipboard pages with remote computers through Network DDE.", "None: already disabled."},
    {"TlntSvr", SEC_START_DISABLED, SEC_SVC_REMOTE_ADMIN | SEC_SVC_NETWORK_LISTENER,
     "Telnet gives a remote command prompt over an unencrypted connection.", "None: already disabled."},
    {"RemoteAccess", SEC_START_DISABLED, SEC_SVC_NETWORK_LISTENER,
     "Routing and Remote Access accepts inbound dial-up and VPN connections and routes packets.",
     "None: already disabled. Outbound dial-up and VPN use other services."}
};

/* Never disabled or stopped by the baseline, whatever a later table edit says. */
static const char *const critical_services[] = {
    "RpcSs", "DcomLaunch", "PlugPlay", "Eventlog", "SamSs", "ProtectedStorage", "Netlogon", "NtLmSsp",
    "lanmanworkstation", "Dhcp", "Dnscache", "SharedAccess", "CryptSvc", "Themes", "ShellHWDetection",
    "AudioSrv", "winmgmt", "EventSystem", "SENS", "seclogon", "Netman", "Nla", "Schedule", "Spooler",
    "MSIServer", "TermService", "LmHosts", "dmserver", "srservice", "W32Time", "XP25Broker", "helpsvc",
    "FastUserSwitchingCompatibility", "COMSysApp", "TrkWks", "WZCSVC", "stisvc", "BITS", "TapiSrv",
    "RasMan", "RasAuto", "Wmi"
};

unsigned sec_service_rule_count(void) { return (unsigned)(sizeof(service_rules) / sizeof(service_rules[0])); }
const SEC_SERVICE_RULE *sec_service_rule_at(unsigned index)
{
    return index < sec_service_rule_count() ? &service_rules[index] : NULL;
}
const SEC_SERVICE_RULE *sec_service_rule(const char *name)
{
    unsigned i;
    for (i = 0; i < sec_service_rule_count(); ++i)
        if (sec_equal_nocase(name, service_rules[i].name)) return &service_rules[i];
    return NULL;
}
int sec_service_is_critical(const char *name)
{
    unsigned i;
    for (i = 0; i < sizeof(critical_services) / sizeof(critical_services[0]); ++i)
        if (sec_equal_nocase(name, critical_services[i])) return 1;
    return 0;
}

/* ---- Registry baseline --------------------------------------------------- */
#define LSA "SYSTEM\\CurrentControlSet\\Control\\Lsa"
#define SRV "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"
#define WKS "SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters"
#define TCP "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
#define TS "SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
#define SM "SYSTEM\\CurrentControlSet\\Control\\Session Manager"
#define FW "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\"
#define EXPLORER "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
#define ZONE3 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3"
#define CLASSES "SOFTWARE\\Classes\\"
#define R SEC_EFFECT_RESTART
#define I SEC_EFFECT_IMMEDIATE
#define ZONE_REASON "Internet-zone content in the unmaintained MSHTML engine must not run this class of active content."
#define ZONE_COMPAT "Internet Explorer and programs that embed it show Internet-zone pages without it. Local, intranet and trusted-zone content is unchanged."
#define SCRIPT_REASON "Opening a script file from Explorer, mail or a download runs it. The default action becomes Edit."
#define SCRIPT_COMPAT "Double-clicking the file opens Notepad. cscript.exe and wscript.exe still run scripts when named explicitly, and the Open verb stays on the context menu."
#define BROADCAST_REASON "After each broadcast the computer sends, Windows Firewall admits unicast packets from any address to the sending port for three seconds. NetBIOS broadcasts keep that window open on UDP 137, where any neighbour can reach the name service or answer name queries falsely."
#define BROADCAST_COMPAT "Names are no longer resolved by NetBIOS broadcast, and a program that finds LAN peers by broadcast needs a firewall exception (the usual Unblock prompt). DHCP is not affected."
#define FWS_REASON "The firewall exception for this inbound service stays closed."
#define FWS_COMPAT "An administrator must open the exception deliberately before using the service."

static const SEC_REGISTRY_RULE registry_rules[] = {
    {"lsa.restrictanonymous", LSA, "restrictanonymous", SEC_REG_DWORD_MIN, 1, NULL, R, "lsa",
     "Anonymous connections cannot enumerate accounts and shares.", "Pre-NT4 domain trust scenarios only."},
    {"lsa.restrictanonymoussam", LSA, "restrictanonymoussam", SEC_REG_DWORD, 1, NULL, R, "lsa",
     "Anonymous connections cannot enumerate SAM accounts.", "None on a standalone computer."},
    {"lsa.everyoneincludesanonymous", LSA, "everyoneincludesanonymous", SEC_REG_DWORD, 0, NULL, R, "lsa",
     "Anonymous logons do not receive the Everyone group.", "None."},
    {"lsa.nolmhash", LSA, "nolmhash", SEC_REG_DWORD, 1, NULL, I, "lsa",
     "No LAN Manager hash is stored at the next password change; LM hashes are trivially cracked.",
     "Windows 9x clients cannot authenticate to this computer with accounts whose password changes afterwards."},
    {"lsa.lmcompatibilitylevel", LSA, "lmcompatibilitylevel", SEC_REG_DWORD_MIN, 3, NULL, I, "lsa",
     "The client sends NTLMv2 only and never LM or NTLMv1 responses.",
     "Servers older than Windows NT 4.0 SP4 reject the logon."},
    {"lsa.nodefaultadminowner", LSA, "nodefaultadminowner", SEC_REG_DWORD, 0, NULL, R, "lsa",
     "Objects created by an administrator are owned by the Administrators group, not by the account, so a restricted process of that account does not own them.",
     "Programs that compare a file's owner with the current user see the Administrators group for files an administrator creates."},
    {"lsa.limitblankpassworduse", LSA, "limitblankpassworduse", SEC_REG_DWORD, 1, NULL, I, "lsa",
     "Accounts with a blank password can log on at the console only, never over the network.", "None."},
    {"smb.server.autosharewks", SRV, "AutoShareWks", SEC_REG_DWORD, 0, NULL, R, "smb",
     "Administrative shares (C$, ADMIN$) are not created if the Server service is ever re-enabled.",
     "Remote administration tools that need ADMIN$ require the shares to be recreated."},
    {"smb.server.restrictnullsessaccess", SRV, "RestrictNullSessAccess", SEC_REG_DWORD, 1, NULL, R, "smb",
     "Null sessions get no access to shares and pipes.", "None."},
    {"smb.server.nullsessionpipes", SRV, "NullSessionPipes", SEC_REG_MULTI_EMPTY, 0, NULL, R, "smb",
     "No named pipe is exempt from the null-session restriction.", "None on a standalone computer."},
    {"smb.server.nullsessionshares", SRV, "NullSessionShares", SEC_REG_MULTI_EMPTY, 0, NULL, R, "smb",
     "No share is exempt from the null-session restriction.", "None on a standalone computer."},
    {"smb.server.enablesecuritysignature", SRV, "enablesecuritysignature", SEC_REG_DWORD, 1, NULL, R, "smb",
     "The SMB server signs packets when the client supports it.", "None."},
    {"smb.client.enablesecuritysignature", WKS, "enablesecuritysignature", SEC_REG_DWORD, 1, NULL, R, "smb",
     "The SMB client signs packets when the server supports it.", "None."},
    {"smb.client.enableplaintextpassword", WKS, "enableplaintextpassword", SEC_REG_DWORD, 0, NULL, R, "smb",
     "The SMB client never sends a clear-text password.", "Very old SMB servers without challenge/response cannot be used."},
    {"tcpip.disableipsourcerouting", TCP, "DisableIPSourceRouting", SEC_REG_DWORD, 2, NULL, R, "tcpip",
     "Source-routed packets are dropped.", "None."},
    {"tcpip.enableicmpredirect", TCP, "EnableICMPRedirect", SEC_REG_DWORD, 0, NULL, R, "tcpip",
     "ICMP redirects cannot rewrite the routing table.", "None on a single-gateway network."},
    {"tcpip.performrouterdiscovery", TCP, "PerformRouterDiscovery", SEC_REG_DWORD, 0, NULL, R, "tcpip",
     "ICMP router advertisements cannot install a default gateway.", "None with DHCP or static configuration."},
    {"netbt.nonamereleaseondemand", "SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters", "NoNameReleaseOnDemand",
     SEC_REG_DWORD, 1, NULL, R, "tcpip",
     "The computer ignores NetBIOS name-release requests from the network.", "None."},
    {"remote.fdenytsconnections", TS, "fDenyTSConnections", SEC_REG_DWORD, 1, NULL, I, "remote",
     "Remote Desktop does not accept connections.", "Remote Desktop into this computer is off until an administrator enables it."},
    {"remote.fallowtogethelp", TS, "fAllowToGetHelp", SEC_REG_DWORD, 0, NULL, I, "remote",
     "Remote Assistance invitations cannot be created or answered.", "Remote Assistance is unavailable."},
    {"rpc.restrictremoteclients", "SOFTWARE\\Policies\\Microsoft\\Windows NT\\RPC", "RestrictRemoteClients",
     SEC_REG_DWORD_MIN, 1, NULL, R, "rpc",
     "Remote RPC clients must authenticate before reaching an interface.", "None: this is the Service Pack 2 default made explicit."},
    {"autorun.nodrivetypeautorun", EXPLORER, "NoDriveTypeAutoRun", SEC_REG_DWORD, 0xDF, NULL, I, "autorun",
     "AutoRun is off for removable, fixed, network, RAM and unknown drives; only CD and DVD media keep it.",
     "USB and network media never start a program by themselves. Game and software discs still start their setup."},
    {"autorun.honorautorunsetting", EXPLORER, "HonorAutorunSetting", SEC_REG_DWORD, 1, NULL, I, "autorun",
     "The shell applies the AutoRun policy to cached mount points too.", "None."},
    {"process.safedllsearchmode", SM, "SafeDllSearchMode", SEC_REG_DWORD, 1, NULL, R, "process",
     "The current directory is searched for DLLs after the system directories.",
     "A program that relies on a same-named DLL in its working directory overriding a system DLL loads the system one."},
    {"process.protectionmode", SM, "ProtectionMode", SEC_REG_DWORD, 1, NULL, R, "process",
     "Base named objects get the stricter default access control.", "None."},
    {"firewall.standard.enable", FW "StandardProfile", "EnableFirewall", SEC_REG_DWORD, 1, NULL, R, "firewall",
     "Windows Firewall filters inbound connections on workgroup and home networks.", "Inbound services need an explicit exception."},
    {"firewall.domain.enable", FW "DomainProfile", "EnableFirewall", SEC_REG_DWORD, 1, NULL, R, "firewall",
     "Windows Firewall filters inbound connections on domain networks.", "Inbound services need an explicit exception."},
    {"firewall.standard.nobroadcastresponse", FW "StandardProfile", "DisableUnicastResponsesToMulticastBroadcast", SEC_REG_DWORD, 1, NULL, R, "firewall", BROADCAST_REASON, BROADCAST_COMPAT},
    {"firewall.domain.nobroadcastresponse", FW "DomainProfile", "DisableUnicastResponsesToMulticastBroadcast", SEC_REG_DWORD, 1, NULL, R, "firewall", BROADCAST_REASON, BROADCAST_COMPAT},
    {"firewall.standard.fileandprint", FW "StandardProfile\\Services\\FileAndPrint", "Enabled", SEC_REG_DWORD, 0, NULL, R, "firewall", FWS_REASON, FWS_COMPAT},
    {"firewall.standard.remotedesktop", FW "StandardProfile\\Services\\RemoteDesktop", "Enabled", SEC_REG_DWORD, 0, NULL, R, "firewall", FWS_REASON, FWS_COMPAT},
    {"firewall.standard.upnp", FW "StandardProfile\\Services\\UPnPFramework", "Enabled", SEC_REG_DWORD, 0, NULL, R, "firewall", FWS_REASON, FWS_COMPAT},
    {"firewall.standard.remoteadmin", FW "StandardProfile\\RemoteAdminSettings", "Enabled", SEC_REG_DWORD, 0, NULL, R, "firewall", FWS_REASON, FWS_COMPAT},
    {"firewall.domain.fileandprint", FW "DomainProfile\\Services\\FileAndPrint", "Enabled", SEC_REG_DWORD, 0, NULL, R, "firewall", FWS_REASON, FWS_COMPAT},
    {"firewall.domain.remotedesktop", FW "DomainProfile\\Services\\RemoteDesktop", "Enabled", SEC_REG_DWORD, 0, NULL, R, "firewall", FWS_REASON, FWS_COMPAT},
    {"firewall.domain.upnp", FW "DomainProfile\\Services\\UPnPFramework", "Enabled", SEC_REG_DWORD, 0, NULL, R, "firewall", FWS_REASON, FWS_COMPAT},
    {"firewall.domain.remoteadmin", FW "DomainProfile\\RemoteAdminSettings", "Enabled", SEC_REG_DWORD, 0, NULL, R, "firewall", FWS_REASON, FWS_COMPAT},
    {"eventlog.security.maxsize", "SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security", "MaxSize", SEC_REG_DWORD_MIN, 0x1000000, NULL, R, "audit",
     "The Security log holds 16 MiB so audit records are not lost within hours.", "Up to 16 MiB of disk space."},
    {"eventlog.security.retention", "SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security", "Retention", SEC_REG_DWORD, 0, NULL, R, "audit",
     "A full Security log overwrites its oldest records instead of discarding new ones.", "Records older than the log capacity are lost; export the log to keep them."},
    {"help.maxallowedzone", "SOFTWARE\\Microsoft\\HTMLHelp\\1.x\\ItssRestrictions", "MaxAllowedZone", SEC_REG_DWORD, 0, NULL, I, "help",
     "Compiled HTML Help opens content from the local computer only.", "CHM files on network shares show blank topics until copied locally."},
    {"ie.security_hklm_only", "SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "Security_HKLM_only",
     SEC_REG_DWORD, 1, NULL, I, "ie",
     "Security zones come from the machine settings only, so a user or a user-level program cannot lower them.",
     "Per-user zone changes, including the user's own trusted sites, are ignored; an administrator manages zones."},
    {"ie.zone3.1001", ZONE3, "1001", SEC_REG_DWORD, 3, NULL, I, "ie", ZONE_REASON, ZONE_COMPAT},
    {"ie.zone3.1004", ZONE3, "1004", SEC_REG_DWORD, 3, NULL, I, "ie", ZONE_REASON, ZONE_COMPAT},
    {"ie.zone3.1200", ZONE3, "1200", SEC_REG_DWORD, 3, NULL, I, "ie", ZONE_REASON, ZONE_COMPAT},
    {"ie.zone3.1201", ZONE3, "1201", SEC_REG_DWORD, 3, NULL, I, "ie", ZONE_REASON, ZONE_COMPAT},
    {"ie.zone3.1400", ZONE3, "1400", SEC_REG_DWORD, 3, NULL, I, "ie", ZONE_REASON, ZONE_COMPAT},
    {"ie.zone3.1405", ZONE3, "1405", SEC_REG_DWORD, 3, NULL, I, "ie", ZONE_REASON, ZONE_COMPAT},
    {"ie.zone3.1c00", ZONE3, "1C00", SEC_REG_DWORD, 0, NULL, I, "ie", ZONE_REASON, ZONE_COMPAT},
    {"ie.zone3.2000", ZONE3, "2000", SEC_REG_DWORD, 3, NULL, I, "ie", ZONE_REASON, ZONE_COMPAT},
    {"wsh.vbsfile", CLASSES "VBSFile\\Shell", "", SEC_REG_SZ, 0, "Edit", I, "wsh", SCRIPT_REASON, SCRIPT_COMPAT},
    {"wsh.vbefile", CLASSES "VBEFile\\Shell", "", SEC_REG_SZ, 0, "Edit", I, "wsh", SCRIPT_REASON, SCRIPT_COMPAT},
    {"wsh.jsfile", CLASSES "JSFile\\Shell", "", SEC_REG_SZ, 0, "Edit", I, "wsh", SCRIPT_REASON, SCRIPT_COMPAT},
    {"wsh.jsefile", CLASSES "JSEFile\\Shell", "", SEC_REG_SZ, 0, "Edit", I, "wsh", SCRIPT_REASON, SCRIPT_COMPAT},
    {"wsh.wsffile", CLASSES "WSFFile\\Shell", "", SEC_REG_SZ, 0, "Edit", I, "wsh", SCRIPT_REASON, SCRIPT_COMPAT}
};

unsigned sec_registry_rule_count(void) { return (unsigned)(sizeof(registry_rules) / sizeof(registry_rules[0])); }
const SEC_REGISTRY_RULE *sec_registry_rule_at(unsigned index)
{
    return index < sec_registry_rule_count() ? &registry_rules[index] : NULL;
}
const SEC_REGISTRY_RULE *sec_registry_rule(const char *id)
{
    unsigned i;
    if (!id) return NULL;
    for (i = 0; i < sec_registry_rule_count(); ++i)
        if (equal(id, registry_rules[i].id)) return &registry_rules[i];
    return NULL;
}
int sec_registry_dword_ok(const SEC_REGISTRY_RULE *rule, int present, unsigned long current)
{
    if (!rule || !present) return 0;
    if (rule->kind == SEC_REG_DWORD) return current == rule->number;
    if (rule->kind == SEC_REG_DWORD_MIN) return current >= rule->number;
    return 0;
}

/* ---- Access-control baseline ------------------------------------------------- */
#define XP25_FILES "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
#define REPAIR_REASON "Files written into this directory by an administrator account or by offline servicing can carry that account's ownership or an open ACL. Windows loads them as system code."
#define REPAIR_COMPAT "None for installed programs: the files get the directory's own inherited access control."
static const SEC_ACL_RULE acl_rules[] = {
    {"acl.windows", SEC_ACL_REPAIR_FILES, "%W%", NULL, REPAIR_REASON, REPAIR_COMPAT},
    {"acl.system32", SEC_ACL_REPAIR_FILES, "%W%\\system32", NULL, REPAIR_REASON, REPAIR_COMPAT},
    {"acl.drivers", SEC_ACL_REPAIR_FILES, "%W%\\system32\\drivers", NULL, REPAIR_REASON, REPAIR_COMPAT},
    {"acl.xp25_programs", SEC_ACL_TREE_FILES, "%P%\\XP25", XP25_FILES,
     "XP25Broker.exe runs as SYSTEM from here. Files installed by a logged-on administrator are owned by that account, so a restricted process of the same account could replace them.",
     "Only administrators can update the XP25 program files."},
    {"acl.xp25_lab", SEC_ACL_TREE_FILES, "%D%\\xp25", XP25_FILES,
     "The XP25 Winlogon (SYSTEM) writes its log here and engineering tools are started from here.",
     "Only administrators can write test tools and logs into this directory."},
    {"acl.service_keys", SEC_ACL_REPAIR_KEYS, "SYSTEM\\CurrentControlSet\\Services", NULL,
     "A service's registry key names the program that runs as its account. Keys created by an administrator account's installer are owned by that account.",
     "None: the keys get the Services key's own inherited access control."},
    {"acl.com_classes", SEC_ACL_REPAIR_KEYS, "SOFTWARE\\Classes\\CLSID", NULL,
     "A COM class registration names the DLL that Explorer and other programs load. Registrations made by an administrator account are owned by that account.",
     "None: the keys get the CLSID key's own inherited access control."},
    {"acl.xp25_registry", SEC_ACL_TREE_REGISTRY, "SOFTWARE\\XP25", "O:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)",
     "The broker's service allowlist and the security baseline state live here; whoever can write them decides what the SYSTEM broker does.",
     "Only administrators can change XP25 machine policy. Per-user ClippyAI settings are stored elsewhere."}
};

unsigned sec_acl_rule_count(void) { return (unsigned)(sizeof(acl_rules) / sizeof(acl_rules[0])); }
const SEC_ACL_RULE *sec_acl_rule_at(unsigned index) { return index < sec_acl_rule_count() ? &acl_rules[index] : NULL; }
const SEC_ACL_RULE *sec_acl_rule(const char *id)
{
    unsigned i;
    if (!id) return NULL;
    for (i = 0; i < sec_acl_rule_count(); ++i) if (equal(id, acl_rules[i].id)) return &acl_rules[i];
    return NULL;
}

int sec_acl_root(const SEC_ACL_RULE *rule, const char *windows, const char *programs, char *out, size_t size)
{
    const char *p, *insert;
    size_t n = 0;
    if (!rule || !out || !size) return 0;
    for (p = rule->root; *p; ) {
        insert = NULL;
        if (p[0] == '%' && p[1] && p[2] == '%') {
            if (p[1] == 'W') insert = windows;
            else if (p[1] == 'P') insert = programs;
            else if (p[1] == 'D') {
                if (!windows || !windows[0] || windows[1] != ':' || n + 3 >= size) return 0;
                out[n++] = windows[0]; out[n++] = ':';
                p += 3;
                continue;
            }
        }
        if (insert) {
            if (!insert[0]) return 0;
            while (*insert) { if (n + 1 >= size) return 0; out[n++] = *insert++; }
            p += 3;
        } else { if (n + 1 >= size) return 0; out[n++] = *p++; }
    }
    out[n] = 0;
    return n > 0;
}

int sec_acl_in_scope(const SEC_ACL_RULE *rule, const char *path, const char *windows, const char *programs)
{
    char root[520];
    size_t n, i;
    if (!path || !sec_acl_root(rule, windows, programs, root, sizeof(root))) return 0;
    n = length(root);
    for (i = 0; i < n; ++i) if (slash(path[i]) != slash(root[i])) return 0;
    if (path[n] == 0) return rule->kind == SEC_ACL_TREE_FILES || rule->kind == SEC_ACL_TREE_REGISTRY;
    if (path[n] != '\\' && path[n] != '/') return 0;
    for (i = n + 1; path[i]; ++i) {
        int boundary = path[i - 1] == '\\' || path[i - 1] == '/';
        if (path[i] == '\\' || path[i] == '/') {
            if (boundary || rule->kind == SEC_ACL_REPAIR_FILES) return 0;   /* empty component, or deeper than a direct child */
        } else if (boundary && path[i] == '.' && (path[i + 1] == 0 || path[i + 1] == '\\' || path[i + 1] == '/' ||
                   (path[i + 1] == '.' && (path[i + 2] == 0 || path[i + 2] == '\\' || path[i + 2] == '/')))) return 0;
    }
    return path[n + 1] != 0;
}

/* ---- Audit policy --------------------------------------------------------- */
static const char *const audit_names[SEC_AUDIT_CATEGORIES] = {
    "system", "logon", "object_access", "privilege_use", "process_tracking", "policy_change",
    "account_management", "directory_service", "account_logon"
};
/* Object access and process tracking stay off: without SACLs and with every
   process start logged they bury the records that matter on a 512 KiB log. */
static const unsigned long audit_baseline[SEC_AUDIT_CATEGORIES] = {
    SEC_AUDIT_SUCCESS | SEC_AUDIT_FAILURE, SEC_AUDIT_SUCCESS | SEC_AUDIT_FAILURE, 0, SEC_AUDIT_FAILURE, 0,
    SEC_AUDIT_SUCCESS | SEC_AUDIT_FAILURE, SEC_AUDIT_SUCCESS | SEC_AUDIT_FAILURE, 0,
    SEC_AUDIT_SUCCESS | SEC_AUDIT_FAILURE
};
const char *sec_audit_category_name(unsigned category)
{
    return category < SEC_AUDIT_CATEGORIES ? audit_names[category] : NULL;
}
unsigned long sec_audit_baseline(unsigned category)
{
    return category < SEC_AUDIT_CATEGORIES ? audit_baseline[category] : 0;
}

/* ---- Backup records --------------------------------------------------------- */
typedef struct { char *data; size_t size, length; int overflow; } OUT;

static void put(OUT *o, const char *text)
{
    while (*text) {
        if (o->length + 1 >= o->size) { o->overflow = 1; return; }
        o->data[o->length++] = *text++;
    }
    o->data[o->length] = 0;
}
static void put_number(OUT *o, unsigned long value)
{
    char digits[24];
    int n = 0;
    do { digits[n++] = (char)('0' + value % 10); value /= 10; } while (value);
    while (n) {
        char one[2];
        one[0] = digits[--n]; one[1] = 0;
        put(o, one);
    }
}

size_t sec_backup_format(const SEC_BACKUP_RECORD *r, char *line, size_t size)
{
    static const char hex[] = "0123456789abcdef";
    OUT o;
    unsigned long i;
    if (!r || !line || size < 8) return 0;
    o.data = line; o.size = size; o.length = 0; o.overflow = 0; line[0] = 0;
    if (r->item == SEC_ITEM_SERVICE) {
        if (!sec_service_rule(r->id) || r->start > SEC_START_DISABLED || r->running > 1) return 0;
        put(&o, "service "); put(&o, sec_service_rule(r->id)->name);
        put(&o, " start="); put_number(&o, r->start);
        put(&o, " running="); put_number(&o, r->running);
    } else if (r->item == SEC_ITEM_REGISTRY) {
        if (!sec_registry_rule(r->id) || r->present > 1 || r->size > SEC_BACKUP_DATA_MAX) return 0;
        if (!r->present && (r->size || r->type)) return 0;
        put(&o, "registry "); put(&o, r->id);
        put(&o, " present="); put_number(&o, r->present);
        put(&o, " type="); put_number(&o, r->type);
        put(&o, " data=");
        for (i = 0; i < r->size; ++i) {
            char pair[3];
            pair[0] = hex[r->data[i] >> 4]; pair[1] = hex[r->data[i] & 15]; pair[2] = 0;
            put(&o, pair);
        }
        if (!r->size) put(&o, "-");
    } else if (r->item == SEC_ITEM_AUDIT) {
        unsigned c;
        for (c = 0; c < SEC_AUDIT_CATEGORIES && !equal(r->id, audit_names[c]); ++c) { }
        if (equal(r->id, "mode") ? r->options > 1 : (c == SEC_AUDIT_CATEGORIES || r->options > 3)) return 0;
        put(&o, "audit "); put(&o, r->id);
        put(&o, " options="); put_number(&o, r->options);
    } else if (r->item == SEC_ITEM_ACL) {
        unsigned long separators = 0;
        if (!sec_acl_rule(r->id) || r->size < 3 || r->size > SEC_BACKUP_DATA_MAX || r->data[r->size - 1] == 0 || r->data[0] == 0) return 0;
        for (i = 0; i < r->size; ++i) if (!r->data[i]) ++separators;
        if (separators != 1) return 0;
        put(&o, "acl "); put(&o, r->id);
        put(&o, " data=");
        for (i = 0; i < r->size; ++i) {
            char pair[3];
            pair[0] = hex[r->data[i] >> 4]; pair[1] = hex[r->data[i] & 15]; pair[2] = 0;
            put(&o, pair);
        }
    } else return 0;
    put(&o, "\n");
    return o.overflow ? 0 : o.length;
}

/* Reads an exact keyword; returns the position after it or NULL. */
static const char *keyword(const char *p, const char *word)
{
    while (*word) if (*p++ != *word++) return NULL;
    return p;
}
static const char *number(const char *p, unsigned long limit, unsigned long *value)
{
    unsigned long v = 0;
    int digits = 0;
    if (!p) return NULL;
    while (*p >= '0' && *p <= '9') {
        if (++digits > 10 || v > (limit - (unsigned long)(*p - '0')) / 10) return NULL;
        v = v * 10 + (unsigned long)(*p++ - '0');
    }
    if (!digits || v > limit) return NULL;
    *value = v;
    return p;
}
static const char *identifier(const char *p, char *id, size_t size)
{
    size_t n = 0;
    if (!p) return NULL;
    while (*p && *p != ' ') {
        if (n + 1 >= size) return NULL;
        id[n++] = *p++;
    }
    id[n] = 0;
    return n ? p : NULL;
}
static int nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int sec_backup_parse(const char *line, SEC_BACKUP_RECORD *r)
{
    const char *p;
    unsigned long value;
    size_t i;
    if (!line || !r) return 0;
    for (i = 0; i < sizeof(*r); ++i) ((unsigned char *)r)[i] = 0;
    if ((p = keyword(line, "service ")) != NULL) {
        r->item = SEC_ITEM_SERVICE;
        p = identifier(p, r->id, sizeof(r->id));
        if (!p || !sec_service_rule(r->id) || !equal(sec_service_rule(r->id)->name, r->id)) return 0;
        p = number(keyword(p, " start="), SEC_START_DISABLED, &r->start);
        if (!p) return 0;
        p = number(keyword(p, " running="), 1, &value);
        if (!p || *p) return 0;
        r->running = (unsigned)value;
        return 1;
    }
    if ((p = keyword(line, "registry ")) != NULL) {
        r->item = SEC_ITEM_REGISTRY;
        p = identifier(p, r->id, sizeof(r->id));
        if (!p || !sec_registry_rule(r->id)) return 0;
        p = number(keyword(p, " present="), 1, &value);
        if (!p) return 0;
        r->present = (unsigned)value;
        p = number(keyword(p, " type="), 11, &r->type);
        if (!p) return 0;
        p = keyword(p, " data=");
        if (!p) return 0;
        if (p[0] == '-' && !p[1]) return r->present || !r->type;
        while (*p) {
            int high = nibble(p[0]), low = high < 0 ? -1 : nibble(p[1]);
            if (low < 0 || r->size >= SEC_BACKUP_DATA_MAX) return 0;
            r->data[r->size++] = (unsigned char)(high << 4 | low);
            p += 2;
        }
        return r->present && r->size;
    }
    if ((p = keyword(line, "acl ")) != NULL) {
        unsigned long separators = 0;
        r->item = SEC_ITEM_ACL;
        p = identifier(p, r->id, sizeof(r->id));
        if (!p || !sec_acl_rule(r->id)) return 0;
        p = keyword(p, " data=");
        if (!p) return 0;
        while (*p) {
            int high = nibble(p[0]), low = high < 0 ? -1 : nibble(p[1]);
            if (low < 0 || r->size >= SEC_BACKUP_DATA_MAX) return 0;
            r->data[r->size] = (unsigned char)(high << 4 | low);
            if (!r->data[r->size]) ++separators;
            ++r->size;
            p += 2;
        }
        /* Exactly "path\0SDDL", both non-empty. */
        return separators == 1 && r->size >= 3 && r->data[0] != 0 && r->data[r->size - 1] != 0;
    }
    if ((p = keyword(line, "audit ")) != NULL) {
        unsigned c;
        r->item = SEC_ITEM_AUDIT;
        p = identifier(p, r->id, sizeof(r->id));
        if (!p) return 0;
        for (c = 0; c < SEC_AUDIT_CATEGORIES && !equal(r->id, audit_names[c]); ++c) { }
        /* "mode" records whether auditing was enabled at all. */
        if (c == SEC_AUDIT_CATEGORIES && !equal(r->id, "mode")) return 0;
        p = number(keyword(p, " options="), c == SEC_AUDIT_CATEGORIES ? 1UL : 3UL, &r->options);
        return p && !*p;
    }
    return 0;
}

/* ---- JSON line writer ------------------------------------------------------ */
static void json_put(SEC_JSON *j, const char *text)
{
    while (*text) {
        if (j->length + 4 >= j->size) { j->overflow = 1; return; }
        j->data[j->length++] = *text++;
    }
}
static void json_quoted(SEC_JSON *j, const char *text)
{
    static const char hex[] = "0123456789abcdef";
    char one[7];
    json_put(j, "\"");
    for (; text && *text; ++text) {
        unsigned char c = (unsigned char)*text;
        if (c == '"' || c == '\\') { one[0] = '\\'; one[1] = (char)c; one[2] = 0; }
        else if (c < 0x20 || c == 0x7f) {
            one[0] = '\\'; one[1] = 'u'; one[2] = '0'; one[3] = '0';
            one[4] = hex[c >> 4]; one[5] = hex[c & 15]; one[6] = 0;
        } else { one[0] = (char)c; one[1] = 0; }
        json_put(j, one);
    }
    json_put(j, "\"");
}
static void json_key(SEC_JSON *j, const char *key)
{
    json_put(j, j->first ? "" : ",");
    j->first = 0;
    json_quoted(j, key);
    json_put(j, ":");
}
void sec_json_begin(SEC_JSON *j, char *buffer, size_t size)
{
    j->data = buffer; j->size = size; j->length = 0; j->overflow = size < 8; j->first = 1;
    if (!j->overflow) json_put(j, "{");
}
void sec_json_string(SEC_JSON *j, const char *key, const char *value)
{
    json_key(j, key);
    json_quoted(j, value);
}
void sec_json_uint(SEC_JSON *j, const char *key, unsigned long value)
{
    char digits[24], text[24];
    int n = 0, m = 0;
    do { digits[n++] = (char)('0' + value % 10); value /= 10; } while (value);
    while (n) text[m++] = digits[--n];
    text[m] = 0;
    json_key(j, key);
    json_put(j, text);
}
void sec_json_bool(SEC_JSON *j, const char *key, int value)
{
    json_key(j, key);
    json_put(j, value ? "true" : "false");
}
size_t sec_json_end(SEC_JSON *j)
{
    json_put(j, "}\r\n");
    if (j->overflow) return 0;
    j->data[j->length] = 0;
    return j->length;
}

/* ---- Classification rules ---------------------------------------------------- */
const char *sec_severity_name(int severity)
{
    static const char *const names[] = {"info", "low", "medium", "high"};
    return severity >= 0 && severity <= 3 ? names[severity] : "info";
}

unsigned sec_path_facts(const char *command, const char *windows, const char *programs)
{
    char program[520];
    const char *p = command;
    unsigned facts = 0;
    size_t n = 0, i;
    int quoted, executable = 0;
    if (!command) return 0;
    while (*p == ' ') ++p;
    quoted = *p == '"';
    if (quoted) {
        for (++p; *p && *p != '"' && n + 1 < sizeof(program); ++p) program[n++] = *p;
    } else {
        /* Windows tries each space-separated prefix as the program: the path
           ends at the first prefix that names an executable extension. */
        for (; *p && n + 1 < sizeof(program); ++p) {
            program[n++] = *p;
            if (n >= 4 && program[n - 4] == '.' && (p[1] == ' ' || p[1] == 0)) {
                char a = lower(program[n - 3]), b = lower(program[n - 2]), c = lower(program[n - 1]);
                if ((a == 'e' && b == 'x' && c == 'e') || (a == 'd' && b == 'l' && c == 'l') ||
                    (a == 's' && b == 'y' && c == 's') || (a == 'c' && b == 'o' && c == 'm') ||
                    (a == 'b' && b == 'a' && c == 't') || (a == 'c' && b == 'm' && c == 'd')) { executable = 1; break; }
            }
        }
        if (!executable) for (n = 0, p = command; *p == ' '; ++p) { }
        if (!executable) for (; *p && *p != ' ' && n + 1 < sizeof(program); ++p) program[n++] = *p;
    }
    program[n] = 0;
    if (!n) return 0;
    if (!quoted && executable) for (i = 0; i < n; ++i) if (program[i] == ' ') facts |= SEC_PATH_UNQUOTED_SPACE;
    if (program[0] == '\\' && program[1] == '\\' && program[2] != '?' && program[2] != '.') facts |= SEC_PATH_NETWORK;
    else if (program[0] == '%' || under(program, "\\SystemRoot") || under(program, "System32") ||
             under(program, "\\??\\")) { /* SCM forms resolved below the Windows directory */ }
    else if (!(program[1] == ':' && (program[2] == '\\' || program[2] == '/'))) facts |= SEC_PATH_RELATIVE;
    if (contains_nocase(program, "\\Documents and Settings\\") || contains_nocase(program, "\\Temp\\") ||
        contains_nocase(program, "\\RECYCLER\\") || contains_nocase(program, "\\Temporary Internet Files\\") ||
        contains_nocase(program, "%TEMP%") || contains_nocase(program, "%USERPROFILE%") ||
        contains_nocase(program, "%APPDATA%")) facts |= SEC_PATH_USER_WRITABLE;
    if (program[1] == ':' && !under(program, windows) && !under(program, programs)) facts |= SEC_PATH_OUTSIDE_SYSTEM;
    return facts;
}

static const SEC_PORT ports[] = {
    {21, 0, SEC_SEVERITY_HIGH, "FTP", "MSFTPSVC"}, {23, 0, SEC_SEVERITY_HIGH, "Telnet", "TlntSvr"},
    {25, 0, SEC_SEVERITY_MEDIUM, "SMTP", "SMTPSVC"}, {80, 0, SEC_SEVERITY_MEDIUM, "HTTP", "W3SVC or HTTP.SYS"},
    {135, 0, SEC_SEVERITY_HIGH, "RPC endpoint mapper", "RpcSs"}, {139, 0, SEC_SEVERITY_HIGH, "NetBIOS session (SMBv1)", "NetBT/LanmanServer"},
    {445, 0, SEC_SEVERITY_HIGH, "SMB direct host (SMBv1)", "NetBT/LanmanServer"}, {593, 0, SEC_SEVERITY_HIGH, "RPC over HTTP", "RpcSs"},
    {1433, 0, SEC_SEVERITY_HIGH, "SQL Server", "MSSQLSERVER"}, {2869, 0, SEC_SEVERITY_MEDIUM, "UPnP device host", "upnphost/SSDPSRV"},
    {3389, 0, SEC_SEVERITY_HIGH, "Remote Desktop", "TermService"}, {5000, 0, SEC_SEVERITY_MEDIUM, "UPnP (SSDP events)", "SSDPSRV"},
    {69, 1, SEC_SEVERITY_MEDIUM, "TFTP", "tftpd"}, {123, 1, SEC_SEVERITY_LOW, "NTP", "W32Time"},
    {137, 1, SEC_SEVERITY_MEDIUM, "NetBIOS name service", "NetBT"}, {138, 1, SEC_SEVERITY_MEDIUM, "NetBIOS datagram", "NetBT"},
    {161, 1, SEC_SEVERITY_HIGH, "SNMP", "SNMP"}, {445, 1, SEC_SEVERITY_MEDIUM, "SMB direct host", "NetBT"},
    {500, 1, SEC_SEVERITY_MEDIUM, "IKE (IPsec)", "PolicyAgent"}, {1434, 1, SEC_SEVERITY_HIGH, "SQL Server browser", "MSSQLSERVER"},
    {1900, 1, SEC_SEVERITY_MEDIUM, "SSDP discovery", "SSDPSRV"}, {4500, 1, SEC_SEVERITY_MEDIUM, "IPsec NAT traversal", "PolicyAgent"}
};
const SEC_PORT *sec_port_lookup(unsigned short port, int udp)
{
    unsigned i;
    for (i = 0; i < sizeof(ports) / sizeof(ports[0]); ++i)
        if (ports[i].port == port && !ports[i].udp == !udp) return &ports[i];
    return NULL;
}

static const SEC_EVENT events[] = {
    {"Security", NULL, 517, SEC_SEVERITY_HIGH, "event.audit_log_cleared", "The security audit log was cleared"},
    {"Security", NULL, 612, SEC_SEVERITY_MEDIUM, "event.audit_policy_changed", "The audit policy was changed"},
    {"Security", NULL, 624, SEC_SEVERITY_MEDIUM, "event.account_created", "A user account was created"},
    {"Security", NULL, 630, SEC_SEVERITY_LOW, "event.account_deleted", "A user account was deleted"},
    {"Security", NULL, 632, SEC_SEVERITY_MEDIUM, "event.group_member_added", "A member was added to a global group"},
    {"Security", NULL, 636, SEC_SEVERITY_MEDIUM, "event.group_member_added", "A member was added to a local group"},
    {"Security", NULL, 628, SEC_SEVERITY_LOW, "event.password_set", "An account password was set by another account"},
    {"Security", NULL, 642, SEC_SEVERITY_LOW, "event.account_changed", "A user account was changed"},
    {"Security", NULL, 644, SEC_SEVERITY_MEDIUM, "event.account_locked", "A user account was locked out"},
    {"Security", NULL, 608, SEC_SEVERITY_MEDIUM, "event.user_right_assigned", "A user right was assigned"},
    {"Security", NULL, 609, SEC_SEVERITY_LOW, "event.user_right_removed", "A user right was removed"},
    {"Security", NULL, 601, SEC_SEVERITY_MEDIUM, "event.service_install_attempt", "A service or driver installation was attempted"},
    {"Security", NULL, 529, SEC_SEVERITY_LOW, "event.logon_failure", "Logon failure: unknown user name or bad password"},
    {"Security", NULL, 530, SEC_SEVERITY_LOW, "event.logon_failure", "Logon failure: account logon time restriction"},
    {"Security", NULL, 531, SEC_SEVERITY_LOW, "event.logon_failure", "Logon failure: account disabled"},
    {"Security", NULL, 532, SEC_SEVERITY_LOW, "event.logon_failure", "Logon failure: account expired"},
    {"Security", NULL, 533, SEC_SEVERITY_LOW, "event.logon_failure", "Logon failure: not allowed at this computer"},
    {"Security", NULL, 534, SEC_SEVERITY_LOW, "event.logon_failure", "Logon failure: logon type not granted"},
    {"Security", NULL, 535, SEC_SEVERITY_LOW, "event.logon_failure", "Logon failure: password expired"},
    {"Security", NULL, 537, SEC_SEVERITY_LOW, "event.logon_failure", "Logon failure: unexpected error"},
    {"Security", NULL, 539, SEC_SEVERITY_LOW, "event.logon_failure", "Logon failure: account locked out"},
    {"Security", NULL, 578, SEC_SEVERITY_LOW, "event.privileged_operation", "A privileged object operation was attempted"},
    {"Security", NULL, 577, SEC_SEVERITY_LOW, "event.privileged_operation", "A privileged service was called"},
    {"System", "Service Control Manager", 7040, SEC_SEVERITY_MEDIUM, "event.service_start_type_changed", "The start type of a service was changed"},
    {"System", "Service Control Manager", 7000, SEC_SEVERITY_LOW, "event.service_start_failed", "A service failed to start"},
    {"System", "Service Control Manager", 7026, SEC_SEVERITY_LOW, "event.driver_load_failed", "A boot-start or system-start driver failed to load"},
    {"System", "Service Control Manager", 7031, SEC_SEVERITY_LOW, "event.service_crashed", "A service terminated unexpectedly"},
    {"System", "Service Control Manager", 7034, SEC_SEVERITY_LOW, "event.service_crashed", "A service terminated unexpectedly"},
    {"System", "EventLog", 6008, SEC_SEVERITY_LOW, "event.unexpected_shutdown", "The previous system shutdown was unexpected"}
};
const SEC_EVENT *sec_event_lookup(const char *log, const char *source, unsigned long id)
{
    unsigned i;
    for (i = 0; i < sizeof(events) / sizeof(events[0]); ++i)
        if (events[i].id == id && sec_equal_nocase(log, events[i].log) &&
            (!events[i].source || sec_equal_nocase(source, events[i].source))) return &events[i];
    return NULL;
}

#define CV "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
#define NTCV "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
static const SEC_AUTOSTART autostarts[] = {
    {"run", 1, CV "Run", SEC_AS_VALUES, NULL, NULL, SEC_SEVERITY_MEDIUM},
    {"runonce", 1, CV "RunOnce", SEC_AS_VALUES, NULL, NULL, SEC_SEVERITY_MEDIUM},
    {"runonceex", 0, CV "RunOnceEx", SEC_AS_VALUES, NULL, NULL, SEC_SEVERITY_MEDIUM},
    {"runservices", 1, CV "RunServices", SEC_AS_VALUES | SEC_AS_ANY_IS_FINDING, NULL, NULL, SEC_SEVERITY_MEDIUM},
    {"policies_run", 1, CV "Policies\\Explorer\\Run", SEC_AS_VALUES | SEC_AS_ANY_IS_FINDING, NULL, NULL, SEC_SEVERITY_MEDIUM},
    {"winlogon_shell", 1, NTCV "Winlogon", SEC_AS_SINGLE, "Shell", "Explorer.exe", SEC_SEVERITY_HIGH},
    {"winlogon_userinit", 0, NTCV "Winlogon", SEC_AS_SINGLE, "Userinit", "%W%\\system32\\userinit.exe,", SEC_SEVERITY_HIGH},
    {"winlogon_uihost", 0, NTCV "Winlogon", SEC_AS_SINGLE, "UIHost", "logonui.exe", SEC_SEVERITY_HIGH},
    {"winlogon_ginadll", 0, NTCV "Winlogon", SEC_AS_SINGLE, "GinaDLL", "", SEC_SEVERITY_HIGH},
    {"winlogon_system", 0, NTCV "Winlogon", SEC_AS_SINGLE, "System", "", SEC_SEVERITY_HIGH},
    {"winlogon_taskman", 0, NTCV "Winlogon", SEC_AS_SINGLE, "Taskman", "", SEC_SEVERITY_HIGH},
    {"winlogon_notify", 0, NTCV "Winlogon\\Notify", SEC_AS_SUBKEYS, "DllName", NULL, SEC_SEVERITY_HIGH},
    {"appinit_dlls", 0, NTCV "Windows", SEC_AS_SINGLE, "AppInit_DLLs", "", SEC_SEVERITY_HIGH},
    {"windows_load", 1, NTCV "Windows", SEC_AS_SINGLE, "Load", "", SEC_SEVERITY_MEDIUM},
    {"windows_run", 1, NTCV "Windows", SEC_AS_SINGLE, "Run", "", SEC_SEVERITY_MEDIUM},
    {"image_file_execution_options", 0, NTCV "Image File Execution Options", SEC_AS_SUBKEYS | SEC_AS_ANY_IS_FINDING,
     "Debugger", NULL, SEC_SEVERITY_HIGH},
    {"aedebug", 0, NTCV "AeDebug", SEC_AS_SINGLE, "Debugger", "drwtsn32 -p %ld -e %ld -g", SEC_SEVERITY_MEDIUM},
    {"command_processor_autorun", 1, "SOFTWARE\\Microsoft\\Command Processor", SEC_AS_SINGLE, "AutoRun", "", SEC_SEVERITY_MEDIUM},
    {"lsa_authentication_packages", 0, LSA, SEC_AS_MULTI, "Authentication Packages", "msv1_0", SEC_SEVERITY_HIGH},
    {"lsa_notification_packages", 0, LSA, SEC_AS_MULTI, "Notification Packages", "scecli", SEC_SEVERITY_HIGH},
    {"lsa_security_packages", 0, LSA, SEC_AS_MULTI, "Security Packages", "kerberos|msv1_0|schannel|wdigest|tspkg", SEC_SEVERITY_HIGH},
    {"boot_execute", 0, SM, SEC_AS_MULTI, "BootExecute", "autocheck autochk *", SEC_SEVERITY_HIGH},
    {"shell_service_objects", 0, CV "ShellServiceObjectDelayLoad", SEC_AS_VALUES, NULL, NULL, SEC_SEVERITY_MEDIUM},
    {"shell_execute_hooks", 0, CV "Explorer\\ShellExecuteHooks", SEC_AS_VALUES, NULL, NULL, SEC_SEVERITY_MEDIUM},
    {"shared_task_scheduler", 0, CV "Explorer\\SharedTaskScheduler", SEC_AS_VALUES, NULL, NULL, SEC_SEVERITY_MEDIUM},
    {"browser_helper_objects", 0, CV "Explorer\\Browser Helper Objects", SEC_AS_SUBKEYS, "", NULL, SEC_SEVERITY_MEDIUM},
    {"active_setup", 0, "SOFTWARE\\Microsoft\\Active Setup\\Installed Components", SEC_AS_SUBKEYS, "StubPath", NULL, SEC_SEVERITY_MEDIUM},
    {"print_monitors", 0, "SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors", SEC_AS_SUBKEYS, "Driver", NULL, SEC_SEVERITY_MEDIUM}
};
unsigned sec_autostart_count(void) { return (unsigned)(sizeof(autostarts) / sizeof(autostarts[0])); }
const SEC_AUTOSTART *sec_autostart_at(unsigned index)
{
    return index < sec_autostart_count() ? &autostarts[index] : NULL;
}

/* Compares current with one expected alternative of the given length, expanding %W%. */
static int matches(const char *current, const char *expected, size_t count, const char *windows)
{
    size_t i = 0;
    while (i < count) {
        if (count - i >= 3 && expected[i] == '%' && expected[i + 1] == 'W' && expected[i + 2] == '%') {
            const char *w = windows ? windows : "";
            while (*w) if (slash(*current++) != slash(*w++)) return 0;
            i += 3;
        } else if (slash(*current++) != slash(expected[i++])) return 0;
    }
    return *current == 0;
}
int sec_autostart_default(const SEC_AUTOSTART *location, const char *current, const char *windows)
{
    const char *start, *p;
    int kind;
    if (!location || !location->expected || !current) return 0;
    kind = location->kind & 0xff;
    if (kind == SEC_AS_SINGLE) return matches(current, location->expected, length(location->expected), windows);
    if (kind != SEC_AS_MULTI) return 0;
    for (start = p = location->expected; ; ++p) {
        if (*p == '|' || *p == 0) {
            if (matches(current, start, (size_t)(p - start), windows)) return 1;
            if (!*p) return 0;
            start = p + 1;
        }
    }
}
