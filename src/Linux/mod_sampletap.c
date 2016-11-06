/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */

#if defined(__cplusplus)
extern "C" {
#endif

#include "hsflowd.h"
#include <linux/types.h>
#include <linux/netlink.h>
#include <net/if.h>
#define HSP_READPACKET_BATCH_TAP 10000
/* Set this to 65K+ to make sure we handle the
   case where virtual port TSOs coallesce packets
   (ignoring MTU constraints). */
#define HSP_MAX_TAP_MSG_BYTES 65536 + 128
#define MAX_IFE_LOG_MSG 400
#define IFE_SEQUENCES_INIT_VAL 40

#include <linux/if.h>
#include <linux/if_tun.h>
#include <ife.h>
#include <sys/ioctl.h>


  typedef struct _HSP_mod_SAMPLETAP {
    EVBus *packetBus;
    bool sampletap_configured;
    // sampletap packet sampling
    UTHash *sequences;
    uint32_t subSamplingRate;
    uint32_t actualSamplingRate;
  } HSP_mod_SAMPLETAP;

  typedef struct _sampletapSeq {
	  uint32_t sampler_id;
	  uint32_t seq;
  } sampletapSeq;

  /*_________________---------------------------__________________
    _________________      readPackets          __________________
    -----------------___________________________------------------
  */

  static uint32_t calcDrops(EVMod *mod, uint32_t seq, uint32_t sampler_id) {
    HSP_mod_SAMPLETAP *mdata = (HSP_mod_SAMPLETAP *)mod->data;
    sampletapSeq key;
    sampletapSeq *seqEntry;
    int dropped;

    key.sampler_id = sampler_id;
    seqEntry = UTHashGet(mdata->sequences, &key);
    if (!seqEntry) {
      myLog(LOG_DEBUG, "Creating new sampler %u with init seq %u", sampler_id, seq);
      seqEntry = (sampletapSeq *)my_calloc(sizeof(sampletapSeq));
      seqEntry->sampler_id = sampler_id;
      seqEntry->seq = seq;
      UTHashAdd(mdata->sequences, seqEntry);
      dropped = 0;
    } else {
      dropped = seq - seqEntry->seq - 1;
      seqEntry->seq = seq;
      UTHashAdd(mdata->sequences, seqEntry);
    }

    return dropped;
  }

  static void readPackets_tap(EVMod *mod, EVSocket *sock, void *magic)
  {
    HSP_mod_SAMPLETAP *mdata = (HSP_mod_SAMPLETAP *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);
    static uint32_t MySkipCount=1;
    struct ife_attr *attrs[__IFE_META_MAX] = { 0 };

    int batch = 0;

    if(sp->sFlowSettings == NULL) {
      // config was turned off
      return;
    }

    if(sock) {
      for( ; batch < HSP_READPACKET_BATCH_TAP; batch++) {
        u_char buf[HSP_MAX_TAP_MSG_BYTES];
        ssize_t num_read;

        num_read = read(sock->fd, buf, HSP_MAX_TAP_MSG_BYTES);
        if (num_read <= 0) break;

        if(--MySkipCount == 0) {
          /* reached zero. Set the next skip */
#ifdef HSP_SWITCHPORT_CONFIG
          MySkipCount = 1;
#else
          MySkipCount = sfl_random((2 * mdata->subSamplingRate) - 1);
#endif
          /* and take a sample */
          u_char *payload = ife_packet_parse(buf, num_read, attrs);
          if(!payload) continue;

          uint32_t ifin_phys = 0;
	  if (ife_attr_valid_num(attrs[IFE_META_IN_IFINDEX]))
	    ifin_phys = ife_get_attr_num(attrs[IFE_META_IN_IFINDEX]);

          uint32_t ifout_phys = 0;
	  if (ife_attr_valid_num(attrs[IFE_META_OUT_IFINDEX]))
	    ifout_phys = ife_get_attr_num(attrs[IFE_META_OUT_IFINDEX]);

          uint32_t origSize = num_read;
	  if (ife_attr_valid_num(attrs[IFE_META_ORIGSIZE]))
	    origSize = ife_get_attr_num(attrs[IFE_META_ORIGSIZE]);

          uint32_t sampleSize = num_read - (uint32_t)(payload - buf);

          uint32_t droppedSamples = 0;
	  if (ife_attr_valid_num(attrs[IFE_META_SEQ]) &&
	      ife_attr_valid_num(attrs[IFE_META_SAMPLER_ID]))
	  {
	    droppedSamples = calcDrops(mod,
				       ife_get_attr_num(attrs[IFE_META_SEQ]),
				       ife_get_attr_num(attrs[IFE_META_SAMPLER_ID]));
	  }

          u_char *mac_hdr = payload;
          uint16_t mac_len = ETH_HLEN;

          if(getDebug() > 1) {
            myLog(LOG_INFO, "TAP in: %u out: %u drops: %u\n",
                ifin_phys,
                ifout_phys,
		droppedSamples);
          }

          takeSample(sp,
                     adaptorByIndex(sp, ifin_phys),
                     adaptorByIndex(sp, ifout_phys),
                     NULL,
		     HSP_SAMPLEOPT_INGRESS,
		     0,
                     mac_hdr,
                     mac_len,
                     payload,
                     sampleSize, /* length of captured payload */
                     origSize, /* length of packet (pdu) */
                     droppedSamples,
                     mdata->actualSamplingRate);
        }
      }
    }
  }

  /*_________________---------------------------__________________
    _________________     openTap               __________________
    -----------------___________________________------------------
  */

  static bool prepareFD(int fd)
  {
      // set the socket to non-blocking
      int fdFlags = fcntl(fd, F_GETFL);
      fdFlags |= O_NONBLOCK;
      if(fcntl(fd, F_SETFL, fdFlags) < 0) {
        myLog(LOG_ERR, "FD fcntl(O_NONBLOCK) failed: %s", strerror(errno));
        return NO;
      }

      // make sure it doesn't get inherited, e.g. when we fork a script
      fdFlags = fcntl(fd, F_GETFD);
      fdFlags |= FD_CLOEXEC;
      if(fcntl(fd, F_SETFD, fdFlags) < 0) {
        myLog(LOG_ERR, "FD fcntl(F_SETFD=FD_CLOEXEC) failed: %s", strerror(errno));
        return NO;
      }

      return YES;
  }

  static int openTap(EVMod *mod)
  {
    HSP *sp = (HSP *)EVROOTDATA(mod);
    const char *clonedev = "/dev/net/tun";
    struct ifreq ifr;
    int fd, err;

    fd = open(clonedev, O_RDWR);
    if(fd < 0) return fd;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, sp->sampletap.tapdev, IFNAMSIZ);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
      close(fd);
      return err;
    }

    if (!prepareFD(fd)) {
      return -1;
    }

    return fd;
  }


  /*_________________---------------------------__________________
    _________________     setSamplingRate       __________________
    -----------------___________________________------------------
  */

  static void setSamplingRate(EVMod *mod) {
    HSP_mod_SAMPLETAP *mdata = (HSP_mod_SAMPLETAP *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    uint32_t samplingRate = sp->sFlowSettings->samplingRate;

    // set defaults assuming we will get 1:1 on SAMPLETAP and do our own sampling.
    mdata->subSamplingRate = samplingRate;
    mdata->actualSamplingRate = samplingRate;

    if(sp->hardwareSampling) {
      // all sampling is done in the hardware
      mdata->subSamplingRate = 1;
      return;
    }

    // calculate the tap sub-sampling rate to use.  We may get the local tap sampling-rate from
    // the probability setting in the config file and the desired sampling rate from DNS-SD, so
    // that's why we have to reconcile the two here.
    uint32_t tapsr = sp->sampletap.rate;
    if(tapsr > 1) {
      // use an integer divide to get the sub-sampling rate, but make sure we round up
      mdata->subSamplingRate = (samplingRate + tapsr - 1) / tapsr;
      // and pre-calculate the actual sampling rate that we will end up applying
      mdata->actualSamplingRate = mdata->subSamplingRate * tapsr;
    }
  }

  /*_________________---------------------------__________________
    _________________    evt_config_changed     __________________
    -----------------___________________________------------------
  */

  static void evt_config_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    HSP_mod_SAMPLETAP *mdata = (HSP_mod_SAMPLETAP *)mod->data;
    HSP *sp = (HSP *)EVROOTDATA(mod);

    if(sp->sFlowSettings == NULL)
      return; // no config (yet - may be waiting for DNS-SD)

    setSamplingRate(mod);

    if(mdata->sampletap_configured) {
      // already configured from the first time (when we still had root privileges)
      return;
    }

    if(sp->sampletap.tapdev) {
      // sampletap dev is set, so open the tap file while we are still root
      int fd = openTap(mod);
      if(fd > 0)
	EVBusAddSocket(mod, mdata->packetBus, fd, readPackets_tap, NULL);
    }

    mdata->sampletap_configured = YES;
  }

  /*_________________---------------------------__________________
    _________________    evt_intfs_changed      __________________
    -----------------___________________________------------------
  */

  static void evt_intfs_changed(EVMod *mod, EVEvent *evt, void *data, size_t dataLen) {
    setSamplingRate(mod);
  }

  /*_________________---------------------------__________________
    _________________    module init            __________________
    -----------------___________________________------------------
  */

  static void ife_logger(enum ife_log_level ife_level, const char *file,
			 int line, const char *fn, const char *format,
			 va_list args)
  {
	  int level;
	  char str[MAX_IFE_LOG_MSG];

	  switch (ife_level) {
	  case IFE_LOG_DEBUG:
		  level = LOG_DEBUG;
		  break;
	  case IFE_LOG_INFO:
		  level = LOG_INFO;
		  break;
	  case IFE_LOG_WARN:
		  level = LOG_WARNING;
		  break;
	  case IFE_LOG_ERR:
		  level = LOG_ERR;
		  break;
	  default:
		  level = LOG_INFO;
	  }

	  vsprintf(str, format, args);
	  myLog(level, "libife: %s", str);
  }

  void mod_sampletap(EVMod *mod) {
    mod->data = my_calloc(sizeof(HSP_mod_SAMPLETAP));
    HSP_mod_SAMPLETAP *mdata = (HSP_mod_SAMPLETAP *)mod->data;
    mdata->packetBus = EVGetBus(mod, HSPBUS_PACKET, YES);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_CONFIG_CHANGED), evt_config_changed);
    EVEventRx(mod, EVGetEvent(mdata->packetBus, HSPEVENT_INTFS_CHANGED), evt_intfs_changed);

    mdata->sequences = UTHASH_NEW(sampletapSeq, sampler_id, UTHASH_DFLT);

    /* init libife logging */
    ife_set_log_level(IFE_LOG_INFO);
    ife_set_log_func(ife_logger);
  }

#if defined(__cplusplus)
} /* extern "C" */
#endif
