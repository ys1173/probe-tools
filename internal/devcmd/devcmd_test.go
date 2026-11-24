package devcmd

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"probetools/internal/protocol"
)

// mustPass are realistic commands, with arguments, that each built-in list allows. Every built-in pattern must be
// matched by at least one of them (TestEveryPatternExercised), which catches a mistyped pattern that allows nothing.
var mustPass = map[string][]string{
	protocol.PlatformIOS: {
		"show version", "show version running", "show clock detail", "show inventory", "show inventory raw",
		"show environment all", "show module", "show module 2", "show processes cpu sorted 5min",
		"show processes cpu history", "show processes memory sorted", "show power inline GigabitEthernet1/0/1 detail",
		"show ntp status", "show ntp associations detail",
		"show interfaces", "show interfaces GigabitEthernet1/0/1", "show interfaces Gi1/0/1 status",
		"show interfaces status err-disabled", "show interfaces description", "show interfaces counters errors",
		"show interfaces TenGigabitEthernet1/1/1 counters", "show interfaces GigabitEthernet1/0/1 transceiver detail",
		"show interfaces transceiver", "show interfaces Vlan 10", "show ip interface brief", "show ip interface Vlan10",
		"show ip interface Loopback0 brief", "show ipv6 interface brief",
		"show ip route", "show ip route vrf CUST-A", "show ip route summary", "show ip route vrf MGMT static",
		"show ip route 10.1.2.3", "show ip route 10.0.0.0 255.0.0.0 longer-prefixes",
		"show ip route vrf CUST 192.168.1.0 255.255.255.0", "show ipv6 route",
		"show ipv6 route 2001:db8::/32 longer-prefixes", "show ipv6 route vrf CUST",
		"show arp", "show arp vrf CUST 10.1.1.1", "show arp detail", "show ip arp", "show ip arp 10.1.1.1",
		"show ip arp GigabitEthernet0/0", "show ip arp 0011.2233.4455", "show ipv6 neighbors",
		"show ipv6 neighbors GigabitEthernet0/0",
		"show mac address-table", "show mac address-table dynamic vlan 10",
		"show mac address-table address 0011.2233.4455", "show mac address-table interface GigabitEthernet1/0/1",
		"show mac address-table count vlan 10",
		"show lldp neighbors", "show lldp neighbors detail", "show lldp neighbors GigabitEthernet1/0/1 detail",
		"show cdp neighbors", "show cdp neighbors detail",
		"show ip ospf neighbor", "show ip ospf neighbor detail", "show ip ospf neighbor summary",
		"show ip ospf interface brief", "show ipv6 ospf neighbor", "show ip bgp summary",
		"show ip bgp vpnv4 vrf CUST summary", "show ip bgp ipv4 unicast summary", "show ip bgp neighbors 192.0.2.1",
		"show ip bgp neighbors 192.0.2.1 received-routes", "show ip eigrp neighbors",
		"show ip eigrp vrf CUST 100 neighbors detail", "show isis neighbors detail", "show clns neighbors",
		"show vlan brief", "show vlan id 10", "show spanning-tree", "show spanning-tree vlan 10,20-30",
		"show spanning-tree summary totals", "show spanning-tree blockedports", "show etherchannel summary",
		"show etherchannel 1 detail", "show lacp neighbor", "show lacp 1 counters", "show standby brief",
		"show standby Vlan10 1 brief", "show vrrp brief", "show vrrp interface GigabitEthernet0/1 brief",
		// short interface types are not abbreviations of refused words (te: test, tech; po: poweroff)
		"show interfaces Te 1/1/1", "show interfaces Po 10 status", "show ip interface Lo 0 brief",
		"show interfaces Fa 0/1 counters", "show environment power",
		// nor are common VRF names (red: redirect, app: append, guest: guestshell, tel: telnet)
		"show ip route vrf RED", "show ip route vrf GUEST static", "show ip route vrf APP", "show arp vrf TEL",
	},
	protocol.PlatformNXOS: {
		"show version", "show clock", "show inventory", "show inventory fans", "show module", "show module uptime",
		"show environment", "show environment power detail", "show system resources", "show system uptime",
		"show system reset-reason", "show processes cpu sort", "show processes cpu history", "show ntp peer-status",
		"show vpc brief",
		"show interface", "show interface ethernet1/1", "show interface Ethernet1/1 quick", "show interface brief",
		"show interface ethernet1/1 brief", "show interface status up", "show interface status down",
		"show interface counters errors",
		"show interface ethernet1/1 counters errors non-zero", "show interface description",
		"show interface transceiver details", "show interface ethernet1/49 transceiver", "show ip interface brief",
		"show ip interface brief vrf all", "show ip interface Vlan10 vrf CUST",
		"show ip route", "show ip route 10.0.0.0/8 longer-prefixes", "show ip route summary vrf all",
		"show ip route bgp vrf CUST", "show ip route 10.1.1.1", "show ipv6 route vrf CUST", "show ip arp",
		"show ip arp vrf all", "show ip arp 10.1.1.1 vrf MGMT", "show ip arp ethernet1/1",
		"show ipv6 neighbor detail vrf all", "show mac address-table", "show mac address-table dynamic vlan 10",
		"show mac address-table interface ethernet1/1", "show mac address-table count",
		"show lldp neighbors", "show lldp neighbors interface ethernet1/1 detail", "show cdp neighbors detail",
		"show ip ospf neighbors", "show ip ospf 1 neighbors detail vrf all", "show bgp ipv4 unicast summary",
		"show bgp vrf CUST ipv4 unicast summary", "show bgp all summary", "show ip eigrp neighbors",
		"show ip eigrp 100 neighbors detail", "show isis adjacency", "show isis adjacency detail vrf all",
		"show vlan", "show vlan id 10", "show spanning-tree", "show spanning-tree vlan 10 blockedports",
		"show spanning-tree summary", "show port-channel summary", "show lacp neighbor",
		"show lacp neighbor interface port-channel10", "show vrrp summary", "show hsrp brief",
		"show hsrp interface Vlan10 brief", "show hsrp summary",
	},
	protocol.PlatformJunos: {
		"show version", "show version detail", "show system uptime", "show system alarms",
		"show system processes extensive", "show chassis alarms", "show chassis hardware",
		"show chassis hardware detail", "show chassis hardware models", "show chassis environment",
		"show chassis environment fpc 0", "show chassis fpc", "show chassis fpc pic-status", "show chassis fpc detail 0",
		"show chassis routing-engine", "show virtual-chassis", "show virtual-chassis status",
		"show ntp associations no-resolve", "show ntp status",
		"show interfaces", "show interfaces terse", "show interfaces ge-0/0/0 extensive",
		"show interfaces ge-0/0/0.0 terse", "show interfaces ae0 detail", "show interfaces descriptions",
		"show interfaces xe-0/0/1 media", "show interfaces statistics", "show interfaces statistics ge-0/0/0 detail",
		"show interfaces diagnostics optics xe-0/0/0", "show interfaces diagnostics optics",
		"show route", "show route 10.0.0.0/8", "show route 10.1.1.1 table inet.0", "show route detail 10.0.0.0/24",
		"show route terse", "show route exact 10.0.0.0/24 extensive", "show route best 2001:db8::/32",
		"show route table CUST.inet.0 terse", "show route protocol bgp", "show route summary",
		"show route summary table inet6.0", "show route forwarding-table",
		"show route forwarding-table destination 10.0.0.0/8",
		"show arp", "show arp no-resolve", "show arp interface ge-0/0/0.0 no-resolve", "show ipv6 neighbors",
		"show ethernet-switching table", "show ethernet-switching table interface ge-0/0/1.0",
		"show ethernet-switching table vlan-name users", "show lldp neighbors",
		"show lldp neighbors interface ge-0/0/0 detail",
		"show ospf neighbor", "show ospf neighbor extensive", "show ospf3 neighbor", "show ospf neighbor instance CUST",
		"show ospf interface", "show ospf interface detail", "show ospf interface ge-0/0/0.0", "show bgp summary",
		"show bgp summary instance CUST", "show bgp neighbor", "show bgp neighbor 192.0.2.1", "show isis adjacency",
		"show isis adjacency detail",
		"show vlans", "show vlans extensive", "show vlans users detail", "show spanning-tree bridge",
		"show spanning-tree interface detail", "show spanning-tree bridge vlan-id 10", "show lacp interfaces",
		"show lacp interfaces ae0 extensive", "show vrrp summary", "show vrrp brief interface ge-0/0/0.0",
	},
	protocol.PlatformEOS: {
		"show version", "show version detail", "show clock", "show inventory", "show system environment all",
		"show system environment cooling detail", "show system environment power budget", "show environment power",
		"show environment temperature detail", "show hardware capacity", "show ntp status", "show ntp associations",
		"show mlag", "show mlag detail",
		"show interfaces", "show interfaces Ethernet1", "show interfaces Ethernet1/1 description",
		"show interfaces status", "show interfaces status connected", "show interfaces Ethernet1 status",
		"show interfaces counters errors", "show interfaces Ethernet1 counters rates",
		"show interfaces counters discards", "show interfaces phy detail", "show interfaces transceiver",
		"show interfaces Ethernet49/1 transceiver detail", "show interfaces transceiver properties",
		"show ip interface brief", "show ip interface vrf MGMT brief", "show ip interface Vlan10 brief",
		"show ip route", "show ip route vrf MGMT", "show ip route 10.0.0.0/8 longer-prefixes", "show ip route bgp",
		"show ip route 10.1.1.1 detail", "show ip route vrf CUST summary", "show ip route summary", "show ipv6 route",
		"show ipv6 route 2001:db8::/32 bgp detail", "show ipv6 route summary", "show ip arp", "show ip arp vrf MGMT",
		"show arp interface Ethernet1", "show ip arp 10.1.1.1", "show ipv6 neighbors",
		"show ipv6 neighbors Vlan10 summary", "show mac address-table", "show mac address-table dynamic vlan 10",
		"show mac address-table interface Ethernet1", "show mac address-table address 0011.2233.4455",
		"show mac address-table count", "show lldp neighbors", "show lldp neighbors Ethernet1 detail",
		"show lldp neighbors detailed",
		"show ip ospf neighbor", "show ip ospf 1 neighbor detail vrf CUST", "show ip ospf neighbor summary",
		"show ip bgp summary", "show ip bgp summary vrf all", "show ipv6 bgp summary", "show ip bgp neighbors 192.0.2.1",
		"show ip bgp neighbors vrf CUST", "show isis neighbors", "show isis neighbors detail",
		"show vlan", "show vlan id 10", "show vlan 10-20", "show vlan brief count", "show vlan trunk", "show spanning-tree",
		"show spanning-tree vlan 10 detail", "show spanning-tree blockedports", "show spanning-tree root detail",
		"show port-channel", "show port-channel 10 detailed", "show port-channel dense", "show lacp peer",
		"show lacp 10 peer brief", "show lacp counters", "show lacp sys-id", "show vrrp brief",
		"show vrrp Vlan10 brief all",
	},
	protocol.PlatformPANOS: {
		"show system info", "show system resources", "show system environmentals", "show system software status",
		"show clock", "show ntp", "show session info", "show session meter", "show running resource-monitor",
		"show interface all", "show interface management", "show interface ethernet1/1", "show interface ae1",
		"show interface tunnel.1", "show counter interface all", "show counter interface ethernet1/1",
		"show counter global", "show routing route", "show routing summary", "show routing fib",
		"show routing resource", "show routing protocol bgp summary", "show routing protocol bgp peer",
		"show routing protocol ospf summary", "show advanced-routing route",
		"show advanced-routing route afi ipv4 destination 10.0.0.0/8 logical-router default type static",
		"show advanced-routing fib afi both", "show advanced-routing resource", "show advanced-routing route type connect",
		"show advanced-routing bgp summary logical-router default",
		"show advanced-routing bgp peer status peer-name isp1 logical-router default",
		"show advanced-routing ospf neighbor", "show arp all", "show mac all", "show neighbor interface all",
		"show vlan all", "show lacp aggregate-ethernet all", "show high-availability state",
		"show high-availability all", "show high-availability state-synchronization",
	},
	protocol.PlatformFortiOS: {
		"get system status", "get system performance status", "get system interface physical", "get system arp",
		"get system ha status", "get system session status", "get router info routing-table all",
		"get router info routing-table details 10.1.1.1", "get router info routing-table details 10.0.0.0/8",
		"get router info routing-table details", "get router info routing-table database",
		"get router info6 routing-table", "get router info6 routing-table 2001:db8::1", "get router info bgp summary",
		"get router info bgp neighbors", "get router info bgp neighbors 192.0.2.1 advertised-routes",
		"get router info ospf neighbor", "get router info ospf neighbor all", "get router info ospf interface",
		"get router info6 ospf neighbor", "get router info vrrp", "get hardware status", "get hardware cpu",
		"get hardware nic port1", "get hardware nic wan1", "diagnose sys session stat",
		"diagnose hardware deviceinfo nic port1", "diagnose ip arp list", "diagnose ip route list",
		"diagnose sys ha status", "diagnose system ha status", "diagnose netlink aggregate list",
		"diagnose netlink aggregate name agg1", "diagnose netlink aggregate name agg1 show",
		"diagnose hardware sysinfo memory", "diagnose hardware sysinfo conserve",
	},
	protocol.PlatformEdgeOS: {
		"show version", "show hardware temperature", "show interfaces", "show interfaces ethernet",
		"show interfaces ethernet detail", "show interfaces detail", "show interfaces ethernet eth0",
		"show interfaces ethernet eth1 physical", "show interfaces ethernet eth0.10", "show ip route",
		"show ip route 10.0.0.0/8", "show ip route 10.1.1.1", "show ip route summary", "show ip route ospf",
		"show ip ospf neighbor", "show ip ospf neighbor detail", "show ip bgp summary", "show ip bgp neighbors",
		"show ip bgp neighbors 192.0.2.1 received-routes", "show vrrp summary", "show arp",
		"show ipv6 route", "show ipv6 neighbors", "show ntp", "show lldp neighbors", "show lldp neighbors detail",
		"show lldp neighbors interface eth0",
	},
	protocol.PlatformRouterOS: {
		"/interface print", "/interface print stats", "/interface print stats-detail",
		"/interface print detail where name=ether1", "/interface print terse without-paging",
		"/interface print where running", "/interface ethernet print",
		"/interface ethernet print stats where name=sfp-sfpplus1", "/interface bridge print",
		"/interface bridge port print", "/interface bridge host print where interface=ether2",
		"/interface bridge vlan print", "/interface vlan print detail", "/interface bonding print",
		"/interface ethernet monitor ether1 once", "/interface bridge monitor bridge1 once",
		"/interface bonding monitor bond1 once", "/interface monitor-traffic ether1 once", "/ip address print",
		"/ip address print detail where interface=ether1", "/ip route print",
		"/ip route print detail where dst-address=10.0.0.0/8", "/ip route print where dst-address in 10.0.0.0/8",
		"/ip route print where vrf=main", "/ip route print count-only", "/ip route print as-value", "/ip arp print",
		"/ip neighbor print detail", "/ipv6 address print", "/ipv6 route print", "/ipv6 neighbor print",
		"/routing route print where dst-address=2001:db8::/32", "/routing ospf neighbor print",
		"/routing bgp session print detail", "/system resource print", "/system resource cpu print",
		"/system health print", "/system routerboard print", "/system identity print", "/system clock print",
		"/system package print", "/system ntp client print",
	},
}

// refusal is a command that the built-in lists must refuse. permissive says what happens once the probe's local file
// allows everything that starts with the read verb (permissiveFile): "floor" means the floor still refuses it (and
// already refuses it with the built-in lists), "pass" means the local file lets it through: the operator's choice.
type refusal struct {
	cmd        string
	permissive string
}

// showCorpus applies to every platform whose read verb is show.
var showCorpus = []refusal{
	// configuration dumps
	{"show running-config", "pass"},
	{"show running-config all", "pass"},
	{"show run", "floor"},
	{"sh run", "floor"},
	{"SHOW RUN", "floor"},
	{"show startup-config", "pass"},
	{"show configuration", "pass"},
	{"show configuration | display set", "floor"},
	{"show full-configuration", "pass"},
	{"show archive", "floor"},
	// keys and certificates
	{"show crypto key mypubkey rsa", "pass"},
	{"show crypto pki certificates", "pass"},
	{"show ssh", "floor"},
	// users and sessions
	{"show users", "pass"},
	{"show user-account", "pass"},
	// SNMP and AAA
	{"show snmp community", "pass"},
	{"show snmp user", "pass"},
	{"show tacacs", "pass"},
	{"show radius", "pass"},
	{"show aaa servers", "pass"},
	// tech-support
	{"show tech-support", "floor"},
	{"show tech", "floor"},
	{"show tech-support details", "floor"},
	{"show tec", "floor"},
	{"show TEC", "floor"},
	{"show tech-sup details", "floor"},
	{"request support-file", "floor"},
	// file systems
	{"show flash:", "pass"},
	{"dir", "floor"},
	{"dir flash:", "floor"},
	{"file show /var/log/messages", "floor"},
	{"file list", "floor"},
	{"show file systems", "floor"},
	// writes, reloads, state
	{"configure terminal", "floor"},
	{"conf t", "floor"},
	{"copy run start", "floor"},
	{"copy running-config startup-config", "floor"},
	{"write memory", "floor"},
	{"wr", "floor"},
	{"reload", "floor"},
	{"request system reboot", "floor"},
	{"clear counters", "floor"},
	{"clear ip bgp *", "floor"},
	{"debug ip packet", "floor"},
	{"undebug all", "floor"},
	{"execute reboot", "floor"},
	{"set cli pager off", "floor"},
	{"commit", "floor"},
	{"start shell", "floor"},
	{"run bash", "floor"},
	{"bash", "floor"},
	{"ping 10.0.0.1", "floor"},
	{"traceroute 10.0.0.1", "floor"},
	{"show clock reload", "floor"},
	{"show interfaces RELOAD", "floor"},
	{"show ip interface brief ping 1.1.1.1", "floor"},
	// injection
	{"show version | redirect tftp://1.2.3.4/x", "floor"},
	{"show version | append flash:x", "floor"},
	{"show version | tee flash:x", "floor"},
	{"show version > flash:x", "floor"},
	{"show version >> x", "floor"},
	{"show version < x", "floor"},
	{"show version ; reload", "floor"},
	{"show version;reload", "floor"},
	{"show version && reload", "floor"},
	{"show version\nreload", "floor"},
	{"show version\rreload", "floor"},
	{"show version\treload", "floor"},
	{"show version\x00", "floor"},
	{"show version\x1b[A", "floor"},
	{"show versión", "floor"},
	{"show interfaces $(x)", "floor"},
	{"show interfaces ${x}", "floor"},
	{"show interfaces `x`", "floor"},
	{"show interfaces [x]", "floor"},
	{"show ip route \"x\"", "floor"},
	{"show ip route 'x'", "floor"},
	{"show ip route \\x", "floor"},
	{"show version # reload", "floor"},
	{"show version !", "floor"},
	{"show ip route ?", "floor"},
	{"show ip route *", "floor"},
	{"show ip route (x)", "floor"},
	{"show ip route ~", "floor"},
	{"show ip route a=b", "pass"},
	{"show version a=reload", "floor"},
	{"show version x@reload", "floor"},
	{"show version 1+run", "floor"},
	{"show version a=rel", "floor"},
	{"show ip route add 10.0.0.0", "floor"},
	{"show ip route del 10.0.0.0", "floor"},
	{"show ip bgp neighbors 192.0.2.1 sen", "floor"},
	{"show interfaces Gi1/0/1 shut", "floor"},
	{"show interfaces Gi1/0/1 bounce", "floor"},
	{"show crypto key rotate", "floor"},
	{"show users@host", "pass"},
	{" show version", "floor"},
	{"show version ", "floor"},
	{"show  version", "floor"},
	{"", "floor"},
	{"show " + strings.Repeat("a", 300), "floor"},
	// streams and long jobs
	{"show logging | include x", "floor"},
	{"show monitor session 1", "floor"},
	{"monitor interface ge-0/0/0", "floor"},
	{"monitor traffic interface ge-0/0/0", "floor"},
	{"show log tail", "floor"},
	{"show interfaces x follow", "floor"},
	{"show processes top", "floor"},
	{"show processes to", "floor"},
	{"show processes cpu to", "floor"},
	{"show mon session 1", "floor"},
	{"show interfaces x foll", "floor"},
	{"show system resources fol", "floor"},
	{"show system resources follow", "floor"},
	{"show interfaces ethernet eth0 capture", "floor"},
	{"show bash", "floor"},
}

// platformCorpus adds each platform's own refusals.
var platformCorpus = map[string][]refusal{
	protocol.PlatformIOS: {
		{"show vtp password", "pass"},
		{"show vrrp", "pass"},
		{"show logging", "pass"},
		{"show platform", "pass"},
		{"show ip route vrf *", "floor"},
		{"show interfaces | json", "floor"},
	},
	protocol.PlatformNXOS: {
		{"show ntp authentication-keys", "pass"},
		{"show running-config | include x", "floor"},
		{"show interface > bootflash:x", "floor"},
		{"show vrrp detail", "pass"},
		{"show vrrp", "pass"},
		{"run guestshell", "floor"},
		{"show tech-sup details", "floor"},
	},
	protocol.PlatformJunos: {
		{"show log messages", "pass"},
		{"show system storage", "pass"},
		{"show interfaces ge-0/0/0 | save /tmp/x", "floor"},
		{"show configuration system login", "pass"},
		{"request support information", "floor"},
		{"show vrrp detail", "pass"},
		{"show vrrp extensive", "pass"},
		{"show vrrp", "pass"},
	},
	protocol.PlatformEOS: {
		{"show running-config sanitized", "pass"},
		{"show interfaces | json", "floor"},
		{"show processes top once", "floor"},
	},
	protocol.PlatformPANOS: {
		{"show admins", "pass"},
		{"show config running", "floor"},
		{"show log traffic", "pass"},
		{"request restart system", "floor"},
		{"debug software restart process mgmtsrvr", "floor"},
		{"less mp-log ms.log", "floor"},
		{"tail follow yes mp-log ms.log", "floor"},
		{"show counter global filter delta yes", "floor"},
		{"show session all", "pass"},
	},
	protocol.PlatformEdgeOS: {
		{"show configuration commands", "pass"},
		{"show system commit", "floor"},
		{"monitor interfaces", "floor"},
		{"sudo su", "floor"},
		{"show interfaces; reboot", "floor"},
		{"show dhcp leases", "pass"},
		{"vbash -c reboot", "floor"},
		{"show vrrp", "pass"},
		{"show vrrp detail", "pass"},
		{"show ubnt discover", "floor"},
		{"show ubnt disc", "floor"},
	},
}

// platformOnlyCorpus are floor refusals that hold on their platform only: EdgeOS expands two-letter prefixes of its
// streaming words, while elsewhere two letters are too often a real argument (TestFloorRefusalsEverywhere leaves
// these out).
var platformOnlyCorpus = map[string][]refusal{
	protocol.PlatformEdgeOS: {
		{"show interfaces ethernet eth0 ca", "floor"},
		{"show interfaces ethernet eth0 capture", "floor"},
		{"show log ta", "floor"},
		{"show log tail", "floor"},
		{"show log fo", "floor"},
		{"show interfaces ethernet eth0 mo", "floor"},
		{"show system to", "floor"},
	},
}

var fortiCorpus = []refusal{
	{"show", "floor"},
	{"show full-configuration", "floor"},
	{"show system admin", "floor"},
	{"get system admin", "pass"},
	{"get system interface", "pass"},
	{"execute reboot", "floor"},
	{"execute backup config tftp x 1.2.3.4", "floor"},
	{"config system interface", "floor"},
	{"diagnose debug enable", "floor"},
	{"diagnose debug flow trace start 10", "floor"},
	{"diagnose sniffer packet any", "floor"},
	{"diagnose sys top", "floor"},
	{"diagnose sys top 5 20 3", "floor"},
	{"diagnose sys mpstat 2", "floor"},
	{"diagnose sys session clear", "floor"},
	{"diagnose sys session filter dport 22", "floor"},
	{"diagnose hardware test suite all", "floor"},
	{"diagnose netlink aggregate name agg1 clear", "floor"},
	{"diagnose test authserver ldap srv user pass", "floor"},
	{"diagnose sys kill 9 123", "floor"},
	{"diagnose sys ha reset-uptime", "floor"},
	{"diagnose sys ha checksum recalculate", "floor"},
	// diagnose is limited by the floor to the built-in display commands: a broad local diagnose allow adds nothing,
	// not even a read-only one, and not an abbreviation of clear on a listed command
	{"diagnose sys ntp status", "floor"},
	{"diagnose netlink aggregate name agg1 c", "floor"},
	{"diagnose netlink aggregate name agg1 1", "floor"},
	{"diagnose vpn tunnel down vpn-to-hq", "floor"},
	{"diagnose vpn tunnel up vpn-to-hq", "floor"},
	{"diagnose vpn tunnel list", "floor"},
	{"diagnose ip arp add port1 10.0.0.9 00:11:22:33:44:55", "floor"},
	{"diagnose ip arp list port1", "floor"},
	{"diagnose ip route add 10.9.9.0/24 10.0.0.1", "floor"},
	{"diagnose wireless-controller wlac kickmac 00:11:22:33:44:55", "floor"},
	{"diagnose deb enable", "floor"},
	{"diagnose deb app ike -1", "floor"},
	{"diagnose sniff packet any", "floor"},
	{"diagnose sys ki 11 1234", "floor"},
	{"diagnose sys top-summary", "floor"},
	{"diagnose sys session stat clear", "floor"},
	{"DIAGNOSE sys session stat", "floor"},
	{"get system performance top", "floor"},
	{"get system performance to", "floor"},
	{"get system status | grep x", "floor"},
	{"get system status\nexecute reboot", "floor"},
	{"GET system status", "floor"},
}

var routerOSCorpus = []refusal{
	{"/export", "floor"},
	{"/export file=x", "floor"},
	{"/export show-sensitive", "floor"},
	{"/ip export", "floor"},
	{"/ip route print file=x", "floor"},
	{"/ip route print fil=x", "floor"},
	{"/ip route print f=x", "floor"},
	{"/ip route print append", "floor"},
	{"/ip route print follow", "floor"},
	{"/ip route print follow-only", "floor"},
	{"/ip route print fol", "floor"},
	{"/ip route print interval=1", "floor"},
	{"/ip route print in=1", "floor"},
	{"/ip route print detail interval=1 where interface=ether1", "floor"},
	{"/log print follow-only", "floor"},
	{"/interface print o=x", "floor"},
	{"/ip route print show-sensitive", "floor"},
	{"/ip route print [/system reboot]", "floor"},
	{":put [/system reboot]", "floor"},
	{"/ip route print; /system reboot", "floor"},
	{"/ip route print where comment~\"x\"", "floor"},
	{"/ip route print where dst-address=1.1.1.1 do={/system reboot}", "floor"},
	{"/ip route print do=x", "floor"},
	{"/ip/route/print", "floor"},
	{"/ip route/print", "floor"},
	{"/system reboot", "floor"},
	{"/system shutdown", "floor"},
	{"/system reset-configuration", "floor"},
	{"/system script run 0", "floor"},
	{"/ip address add address=1.1.1.1/24 interface=ether1", "floor"},
	{"/ip address set 0 disabled=yes", "floor"},
	{"/ip address remove 0", "floor"},
	{"/interface monitor-traffic ether1", "floor"},
	{"/interface ethernet monitor ether1", "floor"},
	{"/interface ethernet monitor ether1 once do=x", "floor"},
	{"/tool torch ether1", "floor"},
	{"/tool sniffer start", "floor"},
	{"/ping 10.0.0.1", "floor"},
	{"/file print", "floor"},
	{"/fil print", "floor"},
	{"/ip route pr", "floor"},
	{"/system reb print", "floor"},
	{"/system script ru print", "floor"},
	{"/ip address ad print", "floor"},
	{"/ip route print fo-o", "floor"},
	{"/ip route print proplist=dst-address,gateway", "pass"},
	{"/ip route print foo", "floor"},
	{"/interface ethernet monitor ether1 once detail", "floor"},
	{"/interface ethernet monitor once", "floor"},
	{"/ip route print where interface=ether1 fil=x", "floor"},
	{"/ip route print\n/system reboot", "floor"},
	{"ip route print", "floor"},
	{"/ print", "floor"},
	{"/user print", "pass"},
	{"/snmp community print", "pass"},
	{"/ppp secret print", "pass"},
	{"/interface vrrp print detail", "pass"},
	{"/certificate print", "pass"},
	{"/log print", "pass"},
	{"/log info print", "floor"},
	{"/log warning print", "floor"},
	{"/log error print", "floor"},
	{"/log i print", "floor"},
	{"/lo info print", "floor"},
	{"/system reset-configuration print", "floor"},
	{"/system reset-conf print", "floor"},
	{"/system sup-output print", "floor"},
	{"/tool flood-ping print", "floor"},
	{"/tool bandwidth-test print", "floor"},
	{"/ip firewall connection kill-connections print", "floor"},
	{"/ip dhcp-client renew print", "floor"},
	{"/ip dhcp-client release print", "floor"},
	{"/interface wireless scan print", "floor"},
	{"/tool e-mail send print", "floor"},
	{"/system upgrade print", "floor"},
	{"/tool wol print", "floor"},
	{"/tool wol", "floor"},
	{"/ip dhcp-server lease print", "pass"},
	{"/ip route print where gateway=10.0.0.1 and dynamic", "pass"},
}

func corpusFor(platform string) []refusal {
	return append(sharedCorpusFor(platform), platformOnlyCorpus[platform]...)
}

// sharedCorpusFor is corpusFor without platformOnlyCorpus: its floor refusals hold on every platform.
func sharedCorpusFor(platform string) []refusal {
	switch platform {
	case protocol.PlatformFortiOS:
		return fortiCorpus
	case protocol.PlatformRouterOS:
		return routerOSCorpus
	}
	return append(append([]refusal(nil), showCorpus...), platformCorpus[platform]...)
}

const permissiveFile = `platforms:
  ios: {allow: ['^show .*$']}
  nxos: {allow: ['^show .*$']}
  junos: {allow: ['^show .*$']}
  eos: {allow: ['^show .*$']}
  panos: {allow: ['^show .*$']}
  edgeos: {allow: ['^show .*$']}
  fortios: {allow: ['^(?:get|diagnose|show) .*$', '^show$']}
  routeros: {allow: ['^/.*$', '^:.*$', '^ip .*$', '^show .*$']}
`

func mustLoad(t *testing.T, content string) *Catalog {
	t.Helper()
	path := ""
	if content != "" {
		path = filepath.Join(t.TempDir(), "commands.yaml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

func TestMustPass(t *testing.T) {
	c := mustLoad(t, "")
	for _, p := range protocol.Platforms {
		if len(mustPass[p]) == 0 {
			t.Errorf("%s: no must-pass commands", p)
		}
		for _, cmd := range mustPass[p] {
			if err := c.Check(p, cmd); err != nil {
				t.Errorf("%s: %q refused: %v", p, cmd, err)
			}
		}
	}
}

func TestEveryPatternExercised(t *testing.T) {
	for _, p := range protocol.Platforms {
		pats, err := builtinPatterns(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, pat := range pats {
			hit := false
			for _, cmd := range mustPass[p] {
				if pat.re.MatchString(cmd) {
					hit = true
					break
				}
			}
			if !hit {
				t.Errorf("%s: no must-pass command exercises %s", p, pat.source)
			}
		}
	}
}

func reasonOf(err *protocol.Error) string {
	switch {
	case err == nil:
		return "pass"
	case err.Code != protocol.CodeNotAllowed:
		return "code " + err.Code
	case strings.Contains(err.Message, "refused by the floor"):
		return "floor"
	case strings.Contains(err.Message, "local deny pattern"):
		return "deny"
	case strings.Contains(err.Message, "not in the allow list"):
		return "list"
	}
	return "unknown: " + err.Message
}

func TestMustRefuseBuiltin(t *testing.T) {
	c := mustLoad(t, "")
	for _, p := range protocol.Platforms {
		for _, r := range corpusFor(p) {
			got := reasonOf(c.Check(p, r.cmd))
			want := "list"
			if r.permissive == "floor" {
				want = "floor"
			}
			if got != want {
				t.Errorf("%s: %q: got %s, want %s", p, r.cmd, got, want)
			}
		}
	}
}

// TestMustRefusePermissive loads a local file that allows anything starting with the read verb: the floor must still
// refuse the writes, injections and streams; the configuration dumps and the like now pass, as the operator chose.
func TestMustRefusePermissive(t *testing.T) {
	c := mustLoad(t, permissiveFile)
	for _, p := range protocol.Platforms {
		for _, r := range corpusFor(p) {
			if got := reasonOf(c.Check(p, r.cmd)); got != r.permissive {
				t.Errorf("%s: %q: got %s, want %s", p, r.cmd, got, r.permissive)
			}
		}
		// The built-in commands still pass.
		for _, cmd := range mustPass[p] {
			if err := c.Check(p, cmd); err != nil {
				t.Errorf("%s: %q refused under the permissive file: %v", p, cmd, err)
			}
		}
	}
}

// TestFloorRefusalsEverywhere runs the floor refusals of the show, platform and RouterOS corpora against every
// platform, built-in and permissive: none may pass anywhere. (The FortiOS corpus holds show commands that are only a
// floor refusal on FortiOS, whose verbs are get and diagnose.)
func TestFloorRefusalsEverywhere(t *testing.T) {
	for _, c := range []*Catalog{mustLoad(t, ""), mustLoad(t, permissiveFile)} {
		for _, src := range protocol.Platforms {
			if src == protocol.PlatformFortiOS {
				continue
			}
			for _, r := range sharedCorpusFor(src) {
				if r.permissive != "floor" {
					continue
				}
				for _, p := range protocol.Platforms {
					if err := c.Check(p, r.cmd); err == nil {
						t.Errorf("%s: %q (from the %s corpus) allowed", p, r.cmd, src)
					}
				}
			}
		}
	}
}

func TestUnknownPlatform(t *testing.T) {
	c := mustLoad(t, "")
	for _, p := range []string{"", "cisco", "IOS", "ios "} {
		if err := c.Check(p, "show version"); err == nil || err.Code != protocol.CodeInvalidParams {
			t.Errorf("platform %q: got %v, want invalid_params", p, err)
		}
	}
}

func TestDeny(t *testing.T) {
	c := mustLoad(t, `platforms:
  ios:
    allow: ['^show (?:ip|IP|Ip) .*$']
    deny:  ['^show ip route vrf .*$', '^show version$']
  routeros:
    deny: ['^/ip neighbor print.*$']
`)
	cases := []struct{ platform, cmd, want string }{
		{"ios", "show ip route vrf CUST", "deny"},
		{"ios", "show IP route vrf CUST", "deny"}, // keywords in another case are still denied
		{"ios", "show ip route", "pass"},
		{"ios", "show version", "deny"},      // deny beats a built-in allow
		{"ios", "show ip anything", "pass"},  // a local allow
		{"ios", "show ip x | y", "floor"},    // the floor beats a local allow
		{"ios", "show ip reload x", "floor"}, // ditto
		{"routeros", "/ip neighbor print", "deny"},
		{"routeros", "/ip neighbor print detail", "deny"},
		{"routeros", "/ip route print", "pass"},
		{"nxos", "show version", "pass"}, // other platforms keep their lists
	}
	for _, tc := range cases {
		if got := reasonOf(c.Check(tc.platform, tc.cmd)); got != tc.want {
			t.Errorf("%s: %q: got %s, want %s", tc.platform, tc.cmd, got, tc.want)
		}
	}
}

// TestDenySpellings records that deny patterns are not canonicalised: a deny written for one spelling of an interface
// misses the others the allow patterns admit, and a deny that covers every spelling catches them all.
func TestDenySpellings(t *testing.T) {
	c := mustLoad(t, `platforms:
  ios:
    deny: ['^show interfaces Vlan10$', '^show ip interface (?:vlan ?20|vl ?20)(?: brief)?$']
`)
	cases := []struct{ cmd, want string }{
		{"show interfaces Vlan10", "deny"},
		{"show interfaces vlan10", "deny"},  // deny patterns ignore case
		{"show interfaces Vlan 10", "pass"}, // another spelling of the same interface
		{"show interfaces Vl10", "pass"},
		{"show ip interface Vlan20", "deny"},
		{"show ip interface Vlan 20 brief", "deny"},
		{"show ip interface Vl20", "deny"},
		{"show ip interface VLAN 20", "deny"},
	}
	for _, tc := range cases {
		if got := reasonOf(c.Check("ios", tc.cmd)); got != tc.want {
			t.Errorf("%q: got %s, want %s", tc.cmd, got, tc.want)
		}
	}
}

// TestAnchoredAlternation proves that ^a|b$ is anchored on both sides: the pattern is compiled as ^(?:a|b)$.
func TestAnchoredAlternation(t *testing.T) {
	c := mustLoad(t, `platforms:
  ios:
    allow: ['^show foo|show bar$']
    deny: ['^show clock|nothing$']
`)
	cases := map[string]string{
		"show foo":          "pass",
		"show bar":          "pass",
		"show foo extra":    "list",
		"show xbar":         "list",
		"show clock":        "deny",
		"show clock detail": "pass", // the deny does not reach past its anchors
	}
	for cmd, want := range cases {
		if got := reasonOf(c.Check("ios", cmd)); got != want {
			t.Errorf("%q: got %s, want %s", cmd, got, want)
		}
	}
}

func TestLocalFileErrors(t *testing.T) {
	cases := map[string]string{
		"unanchored start": "platforms:\n  ios:\n    allow: ['show version$']\n",
		"unanchored end":   "platforms:\n  ios:\n    allow: ['^show version']\n",
		"escaped dollar":   "platforms:\n  ios:\n    allow: ['^show version\\$']\n",
		"bad regex":        "platforms:\n  ios:\n    allow: ['^show (version$']\n",
		"bad deny":         "platforms:\n  ios:\n    deny: ['^show [a-$']\n",
		"empty pattern":    "platforms:\n  ios:\n    allow: ['^$']\n",
		"too long":         "platforms:\n  ios:\n    allow: ['^show " + strings.Repeat("a", 520) + "$']\n",
		"unknown platform": "platforms:\n  cisco:\n    allow: ['^show version$']\n",
		"upper platform":   "platforms:\n  IOS:\n    allow: ['^show version$']\n",
		"unknown key":      "platforms:\n  ios:\n    allows: ['^show version$']\n",
		"unknown top key":  "platform:\n  ios:\n    allow: ['^show version$']\n",
		"scalar allow":     "platforms:\n  ios:\n    allow: '^show version$'\n",
		"not yaml":         "platforms: [\n",
		"two documents":    "platforms: {}\n---\nplatforms:\n  ios:\n    deny: ['^show version$']\n",
		"wrong shape":      "- ios\n",
	}
	dir := t.TempDir()
	for name, content := range cases {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".yaml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		if err == nil {
			t.Errorf("%s: Load accepted %q", name, content)
			continue
		}
		t.Logf("%s: %v", name, err)
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("Load accepted a missing file")
	}
}

func TestEmptyLocalFile(t *testing.T) {
	for _, content := range []string{"\n", "# nothing yet\n", "platforms: {}\n", "platforms:\n  ios: {}\n"} {
		path := filepath.Join(t.TempDir(), "c.yaml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := Load(path)
		if err != nil {
			t.Fatalf("%q: %v", content, err)
		}
		for _, pc := range c.List("") {
			if pc.Local || pc.Deny != nil {
				t.Errorf("%q: %s marked as changed", content, pc.Platform)
			}
		}
	}
}

func TestList(t *testing.T) {
	c := mustLoad(t, "")
	all := c.List("")
	if len(all) != len(protocol.Platforms) {
		t.Fatalf("List(\"\") has %d platforms, want %d", len(all), len(protocol.Platforms))
	}
	for i, pc := range all {
		if pc.Platform != protocol.Platforms[i] {
			t.Errorf("List order: [%d] = %s, want %s", i, pc.Platform, protocol.Platforms[i])
		}
		if len(pc.Allow) == 0 || pc.Deny != nil || pc.Local {
			t.Errorf("%s: built-in list: %d allow, deny %v, local %v", pc.Platform, len(pc.Allow), pc.Deny, pc.Local)
		}
		for _, a := range pc.Allow {
			if !strings.HasPrefix(a, "^") || !strings.HasSuffix(a, "$") || strings.ContainsAny(a, "<>") {
				t.Errorf("%s: listed pattern %q is not an expanded, anchored pattern", pc.Platform, a)
			}
		}
	}
	if got := c.List("bogus"); got != nil {
		t.Errorf("List(bogus) = %v, want nil", got)
	}

	c = mustLoad(t, `platforms:
  ios:
    allow: ['^show ip interface brief$']
    deny:  ['^show ip route vrf .*$']
  routeros:
    deny: ['^/ip neighbor print.*$']
`)
	ios := c.List("ios")
	if len(ios) != 1 || ios[0].Platform != "ios" || !ios[0].Local {
		t.Fatalf("List(ios) = %+v", ios)
	}
	if last := ios[0].Allow[len(ios[0].Allow)-1]; last != "^show ip interface brief$" {
		t.Errorf("local allow not last: %q", last)
	}
	if len(ios[0].Deny) != 1 || ios[0].Deny[0] != "^show ip route vrf .*$" {
		t.Errorf("ios deny = %v", ios[0].Deny)
	}
	for _, pc := range c.List("") {
		want := pc.Platform == "ios" || pc.Platform == "routeros"
		if pc.Local != want {
			t.Errorf("%s: local = %v, want %v", pc.Platform, pc.Local, want)
		}
	}
	// The result is a copy.
	ios[0].Allow[0] = "^tampered$"
	ios[0].Deny[0] = "^tampered$"
	again := c.List("ios")[0]
	if again.Allow[0] == "^tampered$" || again.Deny[0] == "^tampered$" {
		t.Error("List returned the catalog's own slices")
	}
}

// TestBuiltinLists checks the embedded lists themselves: each group names its source, each pattern expands, compiles
// and stays within bounds, and none is open-ended.
func TestBuiltinLists(t *testing.T) {
	for _, p := range protocol.Platforms {
		groups, err := builtinGroups(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) == 0 {
			t.Errorf("%s: no groups", p)
		}
		for _, g := range groups {
			if strings.TrimSpace(g.Source) == "" || len(g.Allow) == 0 {
				t.Errorf("%s: group without a source or patterns: %+v", p, g)
			}
			for _, src := range g.Allow {
				exp, err := expand(src)
				if err != nil {
					t.Errorf("%s: %v", p, err)
					continue
				}
				if _, err := compilePattern(exp, maxBuiltinPatternLength); err != nil {
					t.Errorf("%s: %v", p, err)
				}
				for _, open := range []string{".*", ".+", `\S`, `\w`, "[^", `\s`} {
					if strings.Contains(exp, open) {
						t.Errorf("%s: %s is open-ended (%s)", p, src, open)
					}
				}
			}
		}
	}
}

// TestFloorDirect covers floor rules that do not depend on any list.
func TestFloorDirect(t *testing.T) {
	cases := []struct {
		platform, cmd string
		ok            bool
	}{
		{"ios", "show version", true},
		{"ios", "Show version", false},
		{"fortios", "get system status", true},
		{"fortios", "diagnose sys session stat", true},
		{"fortios", "exec ping 1.1.1.1", false},
		{"routeros", "/ip route print", true},
		{"routeros", "/ip route print where dst-address in 10.0.0.0/8", true},
		{"routeros", "/ip route print in 10.0.0.0/8", false}, // "in" before where may abbreviate interval
		{"routeros", "/interface ethernet monitor ether1 once", true},
		{"routeros", "/interface ethernet monitor ether1", false},
		{"routeros", "/interface monitor-traffic ether1 duration=3", false},
		{"routeros", "/IP route print", false},
		{"routeros", "show version", false},
		{"routeros", "/ip route print FILE=x", false},
		{"routeros", "/ip route print =x", false},
		{"edgeos", "show interfaces", true},
		// abbreviations of refused words, after the first word
		{"ios", "show tec", false},
		{"ios", "show te", true}, // too short to call: two letters are an interface type (Te 1/1/1)
		{"eos", "show processes to", false},
		{"ios", "show power inline", true},
		{"ios", "show powero", false},
		{"nxos", "show interface status down", true},
		{"nxos", "show interface status downl", false},
		{"ios", "show tcp brief", true},
		{"ios", "show tcpd", false},
		{"ios", "show ip route x=deb", false},
		{"fortios", "get system ha status", true},
		{"fortios", "diagnose sys ha status", true},
		{"fortios", "diagnose sys ha statu", false},
		{"fortios", "diagnose hardware deviceinfo nic port1", true},
		{"fortios", "diagnose hardware deviceinfo nic port1 port2", false},
		{"fortios", "diagnose vpn tunnel list", false},
		{"fortios", "get system performance to", false},
		{"nxos", "show interface status up", true},
		{"fortios", "get system interface up", false},
		{"routeros", "/log print", true},
		{"routeros", "/log print where topics=system", true},
		{"routeros", "/log info print", false},
		{"routeros", "/system reset-configuration print", false},
		{"routeros", "/ip dhcp-server print", true},
		{"routeros", "/tool mac-telnet print", false},
		{"routeros", "/tool wol print", false},
		{"edgeos", "show ubnt discover", false},
		{"ios", "show cdp neighbors", true},
		// EdgeOS expands prefixes: two letters of a streaming word are refused there, and only there
		{"edgeos", "show interfaces ethernet eth0 ca", false},
		{"edgeos", "show log ta", false},
		{"ios", "show interfaces ethernet eth0 ca", true},
		{"edgeos", "show interfaces ethernet eth0 c", true}, // one letter: a documented limit
	}
	for _, tc := range cases {
		reason := floor(tc.platform, tc.cmd)
		if (reason == "") != tc.ok {
			t.Errorf("%s: %q: floor = %q, want ok=%v", tc.platform, tc.cmd, reason, tc.ok)
		}
	}
}

// TestNormalizedCorpus runs the corpus the way production does: DeviceShowParams.Normalize first (it collapses tabs
// and newlines into single spaces), then Check. A refusal that the floor makes must survive normalisation, except for
// the entries that only differ from an allowed command by spacing.
func TestNormalizedCorpus(t *testing.T) {
	for _, c := range []*Catalog{mustLoad(t, ""), mustLoad(t, permissiveFile)} {
		for _, p := range protocol.Platforms {
			for _, r := range corpusFor(p) {
				if r.permissive != "floor" {
					continue
				}
				params := protocol.DeviceShowParams{Device: "10.0.0.1", Command: r.cmd}
				if err := params.Normalize(); err != nil {
					continue // refused before Check
				}
				if params.Command != r.cmd && !strings.ContainsAny(r.cmd, "\n\r\t\v\f") {
					continue // a spacing variant of an allowed command
				}
				if err := c.Check(p, params.Command); err == nil {
					t.Errorf("%s: %q normalised to %q is allowed", p, r.cmd, params.Command)
				}
			}
		}
	}
}

// TestCharacterSet holds every built-in example command to the SSH runtime's character set, [A-Za-z0-9 ._:/,=@+-].
func TestCharacterSet(t *testing.T) {
	ok := regexp.MustCompile(`^[A-Za-z0-9 ._:/,=@+-]+$`)
	for _, p := range protocol.Platforms {
		for _, cmd := range mustPass[p] {
			if !ok.MatchString(cmd) {
				t.Errorf("%s: %q has a character outside the SSH runtime's set", p, cmd)
			}
		}
	}
	for c := 0; c < 256; c++ {
		if allowedChar(byte(c)) != ok.MatchString(string(rune(c))) {
			t.Errorf("character 0x%02x: floor and runtime set disagree", c)
		}
	}
}

// TestPatternsAvoidRefusedWords checks that no literal word in a built-in pattern, or in the RouterOS argument
// placeholders, is one the floor refuses on that platform, whole or as an abbreviation: such an alternative could never
// be used, and would mean the list and the floor disagree. It covers every alternation branch, including the ones no
// must-pass example exercises.
func TestPatternsAvoidRefusedWords(t *testing.T) {
	word := regexp.MustCompile(`[a-z][a-z0-9-]*`)
	for _, p := range protocol.Platforms {
		groups, err := builtinGroups(p)
		if err != nil {
			t.Fatal(err)
		}
		var lits []string
		for _, g := range groups {
			for _, src := range g.Allow {
				lits = append(lits, placeholder.ReplaceAllString(src, " "))
			}
		}
		if p == protocol.PlatformRouterOS {
			lits = append(lits, fragments["ROSOPT"], fragments["ROSWHERE"])
		}
		for _, lit := range lits {
			for _, w := range word.FindAllString(lit, -1) {
				if r := refusedToken(p, w, false); r != "" {
					t.Errorf("%s: %s: %s", p, lit, r)
				}
			}
		}
	}
}

// TestRefusedToken pins the abbreviation rule: a word after the first is refused when it is a refused word, a prefix
// of one at least minAbbrev long, or starts with a refused stem.
func TestRefusedToken(t *testing.T) {
	cases := []struct {
		platform, tok string
		first, ok     bool
	}{
		{"ios", "tech", false, false},
		{"ios", "tec", false, false},
		{"ios", "te", false, true},
		{"ios", "tech-sup", false, false},
		{"ios", "to", false, false},
		{"ios", "t", false, true},
		{"ios", "totals", false, true},
		{"ios", "deb", false, false},
		{"ios", "de", false, true},
		{"ios", "detail", false, true},
		{"ios", "Debug", false, false},
		{"ios", "power", false, true},
		{"ios", "powero", false, false},
		{"ios", "down", false, true},
		{"ios", "downl", false, false},
		{"ios", "tcp", false, true},
		{"ios", "tcpd", false, false},
		{"ios", "reset-reason", false, true},
		{"ios", "reset-conf", false, false},
		{"ios", "load-balance", false, true},
		{"ios", "a=rel", false, false},
		{"ios", "name=ether1,gateway", false, true},
		{"ios", "kickmac", false, false},
		{"ios", "red", false, true},
		{"ios", "redir", false, false},
		{"ios", "guest", false, true},
		{"ios", "guests", false, false},
		{"ios", "mon", false, false},
		{"ios", "cap", false, false},
		{"ios", "tec", true, true}, // the first word is compared whole; it must be the read verb anyway
		{"ios", "up", false, true},
		{"fortios", "up", false, false},
		{"fortios", "down", false, false},
		{"fortios", "ha", false, true},
		{"routeros", "monitor", false, true},
		{"routeros", "in", false, true},
		{"panos", "delta", false, false},
		{"ios", "discover", false, false},
		{"ios", "disco", false, false},
		{"ios", "discovery", false, true},
		{"routeros", "wol", false, false},
		{"edgeos", "ca", false, false},
		{"edgeos", "ta", false, false},
		{"edgeos", "fo", false, false},
		{"edgeos", "mo", false, false},
		{"edgeos", "to", false, false},
		{"edgeos", "x=ca", false, false},
		{"edgeos", "c", false, true},
		{"edgeos", "eth0", false, true},
		{"ios", "ca", false, true},
		{"ios", "ta", false, true},
		{"ios", "fo", false, true},
		{"ios", "mo", false, true},
	}
	for _, tc := range cases {
		r := refusedToken(tc.platform, tc.tok, tc.first)
		if (r == "") != tc.ok {
			t.Errorf("%s: %q (first %v): %q, want ok=%v", tc.platform, tc.tok, tc.first, r, tc.ok)
		}
	}
}

// TestFortiOSDiagnoseMatchesList holds the floor's diagnose commands and the built-in list's diagnose patterns to the
// same set, so the list never offers a diagnose command the floor refuses, and the floor never admits one the list
// does not show.
func TestFortiOSDiagnoseMatchesList(t *testing.T) {
	groups, err := builtinGroups(protocol.PlatformFortiOS)
	if err != nil {
		t.Fatal(err)
	}
	var list []string
	for _, g := range groups {
		for _, src := range g.Allow {
			if strings.HasPrefix(src, "^diagnose") {
				list = append(list, src)
			}
		}
	}
	floorSet := append([]string(nil), fortiOSDiagnose...)
	slices.Sort(list)
	slices.Sort(floorSet)
	if !slices.Equal(list, floorSet) {
		t.Errorf("fortios.yaml diagnose patterns %q, floor %q", list, floorSet)
	}
}

// TestBuiltinOff covers builtin: false, which makes a probe's own allow patterns the whole list for a platform.
func TestBuiltinOff(t *testing.T) {
	c := mustLoad(t, `
platforms:
  ios:
    builtin: false
    allow: ['^show version$', '^show ip route$', '^show .*$']
    deny: ['^show users$']
  edgeos:
    builtin: false
  junos:
    builtin: true
`)
	cases := []struct {
		platform, cmd string
		allowed       bool
	}{
		{"ios", "show version", true},
		{"ios", "show ip route", true},
		{"ios", "show users", false},        // local deny still wins over local allow
		{"ios", "show tech-support", false}, // the floor still applies under a hand-written list
		{"ios", "show running-config | redirect x", false},
		{"edgeos", "show version", false}, // builtin off and no allow patterns: nothing runs
		{"junos", "show version", true},   // builtin: true is the default
		{"nxos", "show version", true},    // platforms not in the file keep the built-in list
	}
	for _, tc := range cases {
		err := c.Check(tc.platform, tc.cmd)
		if (err == nil) != tc.allowed {
			t.Errorf("%s %q: allowed=%v, want %v (%v)", tc.platform, tc.cmd, err == nil, tc.allowed, err)
		}
	}
	// A built-in ios command that the hand-written list doesn't cover is refused.
	only := mustLoad(t, "platforms:\n  ios:\n    builtin: false\n    allow: ['^show version$']\n")
	if err := only.Check("ios", "show interfaces"); err == nil || err.Code != protocol.CodeNotAllowed {
		t.Fatalf("show interfaces with builtin off: %v", err)
	}
	for _, pc := range only.List("ios") {
		if !pc.Local || len(pc.Allow) != 1 || pc.Allow[0] != "^show version$" {
			t.Fatalf("List with builtin off: %+v", pc)
		}
	}
	for _, pc := range mustLoad(t, "platforms:\n  edgeos:\n    builtin: false\n").List("edgeos") {
		if !pc.Local || pc.Allow == nil || len(pc.Allow) != 0 {
			t.Fatalf("List with builtin off and no allow: %+v", pc)
		}
	}
}
