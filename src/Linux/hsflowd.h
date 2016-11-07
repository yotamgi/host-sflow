/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#ifndef HSFLOWD_H
#define HSFLOWD_H 1

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <assert.h>
#include <ctype.h>
#include <pthread.h>

#include <sys/mman.h> // for mlockall()
#include <pwd.h> // for getpwnam()
#include <grp.h>
#include <sys/resource.h> // for setrlimit()
#include <limits.h> // for UINT_MAX, LLONG_MAX

#if defined(__GLIBC__) || defined(__UCLIBC__)
// for signal backtrace, if supported by libc
#define HAVE_BACKTRACE 1
#include <execinfo.h>
#include <ucontext.h>
#endif

#include <regex.h> // for regex_t

#include <stdarg.h> // for va_start()
#include "util.h"
#include "sflow_api.h"
#include "evbus.h"

  // define these here because we use them to trigger a module load
  // even when the module is not referenced in the config.
#define HSP_CUMULUS_SWITCHPORT_CONFIG_PROG  "/usr/lib/cumulus/portsamp"
#define HSP_OS10_SWITCHPORT_CONFIG_PROG "/opt/dell/os10/bin/cps_config_sflow"

  typedef struct _HSPNameVal {
    char *nv_name;
    int nv_found;
    uint64_t nv_val64;
  } HSPNameVal;

  // forward declarations
  struct _HSP;
  struct _HSPVMState;

#define ADD_TO_LIST(linkedlist, obj) \
  do { \
    obj->nxt = linkedlist; \
    linkedlist = obj; \
  } while(0)

#define HSP_DAEMON_NAME "hsflowd"
#define HSP_DEFAULT_PIDFILE "/var/run/hsflowd.pid"
#define HSP_DEFAULT_CONFIGFILE "/etc/hsflowd.conf"
#define HSP_DEFAULT_OUTPUTFILE "/etc/hsflowd.auto"
#ifndef HSP_MOD_DIR
#define HSP_MOD_DIR /etc/hsflowd/modules
#endif

/* Numbering to avoid clash. See http://www.sflow.org/developers/dsindexnumbers.php */
#define HSP_DEFAULT_PHYSICAL_DSINDEX 1
#define HSP_DEFAULT_SUBAGENTID 100000
#define HSP_MAX_SUBAGENTID 199999
#define HSP_DEFAULT_LOGICAL_DSINDEX_START 100000
#define HSP_DEFAULT_APP_DSINDEX_START 150000
#define HSP_MAX_TICKS 60

#define HSP_REFRESH_VMS 60
#define HSP_FORGET_VMS 180
#define HSP_REFRESH_ADAPTORS 180

// set to 1 to allow agent.cidr setting in DNSSD TXT record.
// This is currently considered out-of-scope for the DNSSD config,
// so for now the agent.cidr setting is only allowed in hsflowd.conf.
#define HSP_DNSSD_AGENTCIDR 0

// the limit we will request before calling mlockall()
// calling res_search() seems to allocate about 11MB
// (not sure why), so set the limit accordingly.
// #define HSP_RLIMIT_MEMLOCK (1024 * 1024 * 15)
// set to 0 to disable the memlock feature
#define HSP_RLIMIT_MEMLOCK 0

// only one receiver, so the receiverIndex is a constant
#define HSP_SFLOW_RECEIVER_INDEX 1

// space to ask for in output sockets
#define HSP_SFLOW_SND_BUF 2000000

// just assume the sector size is 512 bytes
#define HSP_SECTOR_BYTES 512

// upper limit on number of VIFs per VM
// constrain this to make sure we can't overflow the sFlow datagram
// if we include lots of interfaces that should be left out. Each
// adaptor takes 16 bytes, so this sets the limit for the adaptorList
// structure to 516 bytes (see sflow_receiver.c)
#define HSP_MAX_VIFS 32
// similar constraint on the number of adaptors that we will
// list for a physical host
#define HSP_MAX_PHYSICAL_ADAPTORS 32

  // For when a switch-port is configured using the default
  // (calculated) sampling-rate (based on link speed)
#define HSP_SPEED_SAMPLING_RATIO 1000000
#define HSP_SPEED_SAMPLING_MIN 100

  typedef struct _HSPCollector {
    struct _HSPCollector *nxt;
    SFLAddress ipAddr;
    uint32_t udpPort;
    struct sockaddr_in6 sendSocketAddr;
  } HSPCollector;

  typedef struct _HSPPcap {
    struct _HSPPcap *nxt;
    char *dev;
    bool promisc;
    bool vport;
    bool vport_set;
    uint64_t speed_min;
    uint64_t speed_max;
    bool speed_set;
  } HSPPcap;

  typedef struct _HSPCIDR {
    struct _HSPCIDR *nxt;
    SFLAddress ipAddr;
    SFLAddress mask;
    uint32_t maskBits;
  } HSPCIDR;

#define SFL_UNDEF_COUNTER(c) c=(typeof(c))-1
#define SFL_UNDEF_GAUGE(c) c=0

  typedef struct _HSPApplicationSettings {
    struct _HSPApplicationSettings *nxt;
    char *application;
    bool got_sampling_n;
    uint32_t sampling_n;
    bool got_polling_secs;
    uint32_t polling_secs;
  } HSPApplicationSettings;

  typedef struct _HSPSFlowSettings {
    HSPCollector *collectors;
    uint32_t numCollectors;
    uint32_t samplingRate;
    uint32_t pollingInterval;
    uint32_t headerBytes;
    uint32_t datagramBytes;

    // option to control switch-port sampling direction
    int samplingDirection;
#define HSP_DIRN_UNDEFINED 0
#define HSP_DIRN_IN 1
#define HSP_DIRN_OUT 2
#define HSP_DIRN_BOTH (HSP_DIRN_IN | HSP_DIRN_OUT)

#define HSP_MAX_HEADER_BYTES 256
    HSPApplicationSettings *applicationSettings;
    HSPCIDR *agentCIDRs;
  } HSPSFlowSettings;

  // userData structure to store state for VM data-sources
  typedef enum {
    VMTYPE_UNDEFINED=0,
    VMTYPE_XEN,
    VMTYPE_KVM,
    VMTYPE_DOCKER} EnumVMType;

  typedef struct _HSPVMState {
    char uuid[16];
    EnumVMType vmType;
    uint32_t dsIndex;
    bool created:1;
    bool marked:1;
    SFLAdaptorList *interfaces;
    UTStringArray *volumes;
    UTStringArray *disks;
    SFLPoller *poller;
  } HSPVMState;

  typedef enum { IPSP_NONE=0,
		 IPSP_LOOPBACK6,
		 IPSP_LOOPBACK4,
		 IPSP_SELFASSIGNED4,
		 IPSP_IP6_SCOPE_LINK,
		 IPSP_VLAN6,
		 IPSP_VLAN4,
		 IPSP_IP6_SCOPE_UNIQUE,
		 IPSP_IP6_SCOPE_GLOBAL,
		 IPSP_IP4,
		 IPSP_NUM_PRIORITIES,
  } EnumIPSelectionPriority;

  typedef struct _HSP_ethtool_counters {
    uint64_t mcasts_in;
    uint64_t mcasts_out;
    uint64_t bcasts_in;
    uint64_t bcasts_out;
    uint64_t unknown_in;
    uint32_t operStatus;
    uint32_t adminStatus;
  } HSP_ethtool_counters;

#define HSP_ETCTR_MC_IN  0x0001
#define HSP_ETCTR_MC_OUT 0x0002
#define HSP_ETCTR_BC_IN  0x0004
#define HSP_ETCTR_BC_OUT 0x0008
#define HSP_ETCTR_UNKN   0x0010
#define HSP_ETCTR_OPER   0x0020
#define HSP_ETCTR_ADMIN  0x0040
  typedef uint32_t ETCTRFlags;

  typedef enum { HSPDEV_OTHER=0,
		 HSPDEV_PHYSICAL,
		 HSPDEV_VETH,
		 HSPDEV_VIF,
		 HSPDEV_OVS,
		 HSPDEV_BRIDGE } EnumHSPDevType;

  // cache nio counters per adaptor
  typedef struct _HSPAdaptorNIO {
    SFLAddress ipAddr;
    uint32_t /*EnumIPSelectionPriority*/ ipPriority;
    EnumHSPDevType devType;
    bool up:1;
    bool loopback:1;
    bool bond_master:1;
    bool bond_slave:1;
    bool switchPort:1;
    bool os10Port:1;
    bool vm_or_container:1;
    bool modinfo_tested:1;
    bool ethtool_GDRVINFO:1;
    bool ethtool_GMODULEINFO:1;
    bool ethtool_GLINKSETTINGS:1;
    bool ethtool_GSET:1;
    bool ethtool_GSTATS:1;
    bool procNetDev:1;
    bool changed_speed:1;
    int32_t vlan;
#define HSP_VLAN_ALL -1
    SFLHost_nio_counters nio;
    SFLHost_nio_counters last_nio;
    uint32_t last_bytes_in32;
    uint32_t last_bytes_out32;
#define HSP_MAX_NIO_DELTA32 0x7FFFFFFF
#define HSP_MAX_NIO_DELTA64 (uint64_t)(1.0e13)
    time_t last_update;
    uint32_t et_nctrs; // how many in total
    ETCTRFlags et_found; // bitmask of the ones we wanted
    // offsets within the ethtool stats block
    uint8_t et_idx_mcasts_in;
    uint8_t et_idx_mcasts_out;
    uint8_t et_idx_bcasts_in;
    uint8_t et_idx_bcasts_out;
    // latched counter for delta calculation
    HSP_ethtool_counters et_last;
    HSP_ethtool_counters et_total;
    // SFP (optical) stats
    // #define HSP_TEST_QSFP 1
    // These definitions should eventually be in ethtool.h
#ifndef ETH_MODULE_SFF_8472
#define ETH_MODULE_SFF_8472 0x02
#define ETH_MODULE_SFF_8472_LEN 512
#endif
#ifndef ETH_MODULE_SFF_8436
#define ETH_MODULE_SFF_8436 0x03
#define ETH_MODULE_SFF_8436_LEN 640
#endif
    uint32_t modinfo_type;
    uint32_t modinfo_len;
    SFLSFP_counters sfp;
    // LACP/bonding data
    SFLLACP_counters lacp;
    // switch ports that are sending individual interface
    // counters will keep a pointer to their sflow poller.
    SFLPoller *poller;
    // and those sending packet-samples will have a sampler.
    SFLSampler *sampler;
    uint32_t sampling_n;
    uint32_t sampling_n_set;
    uint32_t netlink_drops;
    // allow mod_xen to write regex-extracted fields here
    int xen_domid;
    int xen_netid;
  } HSPAdaptorNIO;

  typedef struct _HSPDiskIO {
    uint64_t last_sectors_read;
    uint64_t last_sectors_written;
    uint64_t bytes_read;
    uint64_t bytes_written;
  } HSPDiskIO;

#define HSPBUS_POLL "poll" // main thread
#define HSPBUS_CONFIG "config" // DNS-SD
#define HSPBUS_PACKET "packet" // pcap,ulog,nflog,json,tcp packet processing

// The generic start,tick,tock,final,end events are defined in evbus.h
#define HSPEVENT_HOST_COUNTER_SAMPLE "csample"   // (csample *) building counter-sample
#define HSPEVENT_FLOW_SAMPLE "flow_sample"       // (HSPPendingSample *) building flow-sample
#define HSPEVENT_CONFIG_START "config_start"     // begin config lines
#define HSPEVENT_CONFIG_LINE "config_line"       // (line)...next config line
#define HSPEVENT_CONFIG_END "config_end"         // (n_servers *) end config lines
#define HSPEVENT_CONFIG_FIRST "config_first"     // new config [first]
#define HSPEVENT_CONFIG_CHANGED "config_changed" // new config
#define HSPEVENT_CONFIG_SHAKE "config_shake"     // handkshake before done
#define HSPEVENT_CONFIG_DONE "config_done"       // after new config
#define HSPEVENT_INTF_READ "intf_read"           // (adaptor *) reading interface
#define HSPEVENT_INTF_SPEED "intf_speed"         // (adaptor *) interface speed change
#define HSPEVENT_INTFS_CHANGED "intfs_changed"   // some interface(s) changed
#define HSPEVENT_UPDATE_NIO "update_nio"         // (adaptor *) nio counter refresh


  typedef struct _HSPPendingSample {
    SFL_FLOW_SAMPLE_TYPE *fs;
    SFLSampler *sampler;
    int refCount;
    UTArray *ptrsToFree;
  } HSPPendingSample;

  typedef struct _HSP {
    char *modulesPath;
    EVMod *rootModule;
    EVBus *pollBus;
    EVEvent *evt_flow_sample;

    // agent
    SFLAgent *agent;
    pthread_mutex_t *sync_agent;
    // main host poller
    SFLPoller *poller;
    bool counterSampleQueued;

    // config settings
    HSPSFlowSettings *sFlowSettings_file;
    HSPSFlowSettings *sFlowSettings_dnsSD;
    HSPSFlowSettings *sFlowSettings_dnsSD_prev;
    HSPSFlowSettings *sFlowSettings;
    char *sFlowSettings_str;

    // resolve actual polling interval
    uint32_t syncPollingInterval;
    uint32_t minPollingInterval;
    uint32_t actualPollingInterval;

    // agent/agentIP config results
    uint32_t revisionNo;
    uint32_t subAgentId;
    char *agentDevice;
    SFLAddress agentIP;
    bool explicitAgentDevice;
    bool explicitAgentIP;

    // config-file-only settings by module
    struct {
      bool DNSSD;
      char *domain;
    } DNSSD;
    struct {
      bool json;
      uint32_t port;
      char *FIFO;
    } json;
    struct {
      bool kvm;
      uint32_t refreshVMListSecs;
      uint32_t forgetVMSecs;
    } kvm;
    struct {
      bool xen;
      regex_t *vif_regex;
      char *vif_regex_str;
      bool update_dominfo; // update dominfo for every VM at poll-time
      bool dsk; // include disk counters
      char *vbd; // path to virtual block device info
      uint32_t refreshVMListSecs;
      uint32_t forgetVMSecs;
    } xen;
    struct {
      bool docker;
      uint32_t refreshVMListSecs;
      uint32_t forgetVMSecs;
    } docker;
    struct {
      bool cumulus;
      char *swp_regex_str;
      regex_t *swp_regex;
    } cumulus;
    struct {
      bool ovs;
    } ovs;
    struct {
      bool os10;
      uint32_t port;
      char *swp_regex_str;
      regex_t *swp_regex;
    } os10;
    struct {
      bool nvml;
    } nvml;
    struct {
      bool ulog;
      uint32_t group;
      double probability;
      uint32_t samplingRate;
      uint32_t ds_options;
    } ulog;
    struct {
      bool nflog;
      uint32_t group;
      double probability;
      uint32_t samplingRate;
      uint32_t ds_options;
    } nflog;
    struct {
      bool sampletap;
      char* tapdev;
      uint32_t rate;
    } sampletap;
    struct {
      bool pcap;
      HSPPcap *pcaps;
      uint32_t numPcaps;
    } pcap;
    struct {
      bool tcp;
    } tcp;

    // hardware sampling flag
    bool hardwareSampling;

    // daemon setup
    char *configFile;
    bool configOK;
    char *outputFile;
    char *pidFile;
    bool daemonize;
    bool dropPriv;
    uint32_t outputRevisionNo;
    FILE *f_out;
    char *crashFile;
    UTStringArray *retainRootReasons;

    // Identity
    char hostname[SFL_MAX_HOSTNAME_CHARS+1];
    char os_release[SFL_MAX_OSRELEASE_CHARS+1];
    uint32_t machine_type;
    char uuid[16];

    // interfaces and MACs
    UTHash *adaptorsByName; // global namespace only
    UTHash *adaptorsByIndex;
    UTHash *adaptorsByPeerIndex;
    UTHash *adaptorsByMac;

    // poll actions for tick-tock cycle
    UTArray *pollActions;

    // have to poll the NIO counters fast enough to avoid 32-bit rollover
    // of the bytes counters.  On a 10Gbps interface they can wrap in
    // less than 5 seconds.  On a virtual interface the data rate could be
    // higher still. The program may decide to turn this off. For example,
    // if it finds evidence that the counters are already 64-bit in the OS,
    // or if it decides that all interface speeds are limited to 1Gbps or less.
    time_t nio_last_update;
    time_t nio_polling_secs;
#define HSP_NIO_POLLING_SECS_32BIT 3
    time_t next_nio_poll;

    // refresh cycles
    bool refreshAdaptorList; // request flag
    uint32_t refreshAdaptorListSecs; // poll interval
    time_t next_refreshAdaptorList; // deadline

    bool refreshVMList; // request flag
    uint32_t refreshVMListSecs; // poll interval (default)
    uint32_t forgetVMSecs; // age-out idle VM or container (default)

    // 64-bit diskIO accumulators
    HSPDiskIO diskIO;

    // UDP send sockets
    int socket4;
    int socket6;

    // physical host / hypervisor vnode characteristics
    uint32_t cpu_mhz;
    uint32_t cpu_cores;
    uint64_t mem_total;
    uint64_t mem_free;

    // vm/container dsIndex allocation
    UTHash *vmsByUUID;
    UTHash *vmsByDsIndex;

    // local IP addresses
    UTHash *localIP;
    UTHash *localIP6;

    // handshake countdown
    int config_shake_countdown;
  } HSP;

  // expose some config parser fns
  int HSPReadConfigFile(HSP *sp);
  HSPSFlowSettings *newSFlowSettings(void);
  HSPCollector *newCollector(HSPSFlowSettings *sFlowSettings);
  void clearCollectors(HSPSFlowSettings *settings);
  void freeSFlowSettings(HSPSFlowSettings *sFlowSettings);
  void setApplicationSampling(HSPSFlowSettings *settings, char *app, uint32_t n);
  void setApplicationPolling(HSPSFlowSettings *settings, char *app, uint32_t secs);
  void clearApplicationSettings(HSPSFlowSettings *settings);
  int lookupApplicationSettings(HSPSFlowSettings *settings, char *prefix, char *app, uint32_t *p_sampling, uint32_t *p_polling);
  uint32_t lookupPacketSamplingRate(SFLAdaptor *adaptor, HSPSFlowSettings *settings);
  uint32_t agentAddressPriority(HSP *sp, SFLAddress *addr, int vlan, int loopback);
  int selectAgentAddress(HSP *sp, int *p_changed);
  void addAgentCIDR(HSPSFlowSettings *settings, HSPCIDR *cidr);
  void clearAgentCIDRs(HSPSFlowSettings *settings);

  // read functions
  int readInterfaces(HSP *sp, bool full_discovery, uint32_t *p_added, uint32_t *p_removed, uint32_t *p_cameup, uint32_t *p_wentdown, uint32_t *p_changed);
  const char *devTypeName(EnumHSPDevType devType);
  int readCpuCounters(SFLHost_cpu_counters *cpu);
  int readMemoryCounters(SFLHost_mem_counters *mem);
  int readDiskCounters(HSP *sp, SFLHost_dsk_counters *dsk);
  int readNioCounters(HSP *sp, SFLHost_nio_counters *nio, char *devFilter, SFLAdaptorList *adList);
  HSPAdaptorNIO *getAdaptorNIO(SFLAdaptorList *adaptorList, char *deviceName);
  void updateBondCounters(HSP *sp, SFLAdaptor *bond);
  void readBondState(HSP *sp);
  void syncPolling(HSP *sp);
  void syncBondPolling(HSP *sp);
  int accumulateNioCounters(HSP *sp, SFLAdaptor *adaptor, SFLHost_nio_counters *ctrs, HSP_ethtool_counters *et_ctrs);
  void updateNioCounters(HSP *sp, SFLAdaptor *adaptor);
  int readHidCounters(HSP *sp, SFLHost_hid_counters *hid, char *hbuf, int hbufLen, char *rbuf, int rbufLen);
  int configSwitchPorts(HSP *sp);
  int readTcpipCounters(HSP *sp, SFLHost_ip_counters *c_ip, SFLHost_icmp_counters *c_icmp, SFLHost_tcp_counters *c_tcp, SFLHost_udp_counters *c_udp);
  void flushCounters(EVMod *mod);

  // capabilities
  void retainRootRequest(EVMod *mod, char *reason);
  
  // adaptors
  SFLAdaptor *nioAdaptorNew(char *dev, u_char *macBytes, uint32_t ifIndex);
#define ADAPTOR_NIO(ad) ((HSPAdaptorNIO *)(ad)->userData)
  void adaptorAddOrReplace(UTHash *ht, SFLAdaptor *ad);
  SFLAdaptor *adaptorByName(HSP *sp, char *dev);
  SFLAdaptor *adaptorByMac(HSP *sp, SFLMacAddress *mac);
  SFLAdaptor *adaptorByIndex(HSP *sp, uint32_t ifIndex);
  SFLAdaptor *adaptorByPeerIndex(HSP *sp, uint32_t ifIndex);
  void deleteAdaptor(HSP *sp, SFLAdaptor *ad, int freeFlag);
  int deleteMarkedAdaptors(HSP *sp, UTHash *adaptorHT, int freeFlag);
  int deleteMarkedAdaptors_adaptorList(HSP *sp, SFLAdaptorList *adList);
  char *adaptorStr(SFLAdaptor *ad, char *buf, int bufLen);
  void adaptorHTPrint(UTHash *ht, char *prefix);
  void setAdaptorSpeed(HSP *sp, SFLAdaptor *adaptor, uint64_t speed);

  // readPackets.c
#define HSP_SAMPLEOPT_BRIDGE      0x0001
#define HSP_SAMPLEOPT_DEV_SAMPLER 0x0002
#define HSP_SAMPLEOPT_DEV_POLLER  0x0004
#define HSP_SAMPLEOPT_IF_SAMPLER  0x0008
#define HSP_SAMPLEOPT_IF_POLLER   0x0010
#define HSP_SAMPLEOPT_ULOG        0x0020
#define HSP_SAMPLEOPT_NFLOG       0x0040
#define HSP_SAMPLEOPT_PCAP        0x0080
#define HSP_SAMPLEOPT_OS10        0x0100
#define HSP_SAMPLEOPT_CUMULUS     0x0200
#define HSP_SAMPLEOPT_INGRESS     0x0400
#define HSP_SAMPLEOPT_EGRESS      0x0800
#define HSP_SAMPLEOPT_DIRN_HOOK   0x1000
#define HSP_SAMPLEOPT_ASIC        0x2000

  void takeSample(HSP *sp, SFLAdaptor *ad_in, SFLAdaptor *ad_out, SFLAdaptor *ad_tap, uint32_t options, uint32_t hook, const u_char *mac_hdr, uint32_t mac_len, const u_char *cap_hdr, uint32_t cap_len, uint32_t pkt_len, uint32_t drops, uint32_t sampling_n);
  void *pendingSample_calloc(HSPPendingSample *ps, size_t len);
  void holdPendingSample(HSPPendingSample *ps);
  void releasePendingSample(HSP *sp, HSPPendingSample *ps);
  SFLPoller *forceCounterPolling(HSP *sp, SFLAdaptor *adaptor);

  // VM lifecycle
  HSPVMState *getVM(EVMod *mod, char *uuid, bool create, size_t objSize, EnumVMType vmType, getCountersFn_t getCountersFn);
  void removeAndFreeVM(EVMod *mod, HSPVMState *state);

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* HSFLOWD_H */
