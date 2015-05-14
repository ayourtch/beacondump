#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include "ieee802_11_radio.h"

int ieee80211_field_size[32] = {
  sizeof(uint64_t),   // IEEE80211_RADIOTAP_TSFT
  sizeof(uint8_t),    // IEEE80211_RADIOTAP_FLAGS
  sizeof(uint8_t),    // IEEE80211_RADIOTAP_RATE
  2*sizeof(uint16_t), // IEEE80211_RADIOTAP_CHANNEL
  sizeof(uint16_t),   // IEEE80211_RADIOTAP_FHSS
  sizeof(int8_t),    // IEEE80211_RADIOTAP_DBM_ANTSIGNAL
  sizeof(int8_t),    // IEEE80211_RADIOTAP_DBM_ANTNOISE
  sizeof(uint16_t),   // IEEE80211_RADIOTAP_LOCK_QUALITY
  sizeof(uint16_t),   // IEEE80211_RADIOTAP_TX_ATTENUATION
  sizeof(uint16_t),   // IEEE80211_RADIOTAP_DB_TX_ATTENUATION
  sizeof(int8_t),     // IEEE80211_RADIOTAP_DBM_TX_POWER
  sizeof(uint8_t),     // IEEE80211_RADIOTAP_ANTENNA
  sizeof(uint8_t),    // IEEE80211_RADIOTAP_DB_ANTSIGNAL
  sizeof(uint8_t),    // IEEE80211_RADIOTAP_DB_ANTNOISE
};

void *get80211field(const u_char *pkt,
                    enum ieee80211_radiotap_type field)
{
  struct ieee80211_radiotap_header* hdr = (struct ieee80211_radiotap_header*)pkt;
  int i;
  int offs = sizeof(struct ieee80211_radiotap_header);
  char *pc = (char *)hdr;
  for(i = 0; i < field; i++) {
    if(hdr->it_present & (1 << i)) {
      offs += ieee80211_field_size[i];
    }
  }
  if((ieee80211_field_size[field] > 1) && (offs %2)) {
    offs++;
  }
  pc = pc + offs;
  return (void *)pc;
}

void *get80211payload(const u_char *pkt) {
  struct ieee80211_radiotap_header* hdr = (struct ieee80211_radiotap_header*)pkt;
  char *pc = (char *)hdr;
  return pc + hdr->it_len;
}

void hex(void *ptr, int len) {
  int i = 0;
  uint8_t *pc = ptr;
  int val = -1;
  char str[20];
  memset(str, 0, sizeof(str));
  while(len > 0) {
    do {
      if(0 == i%16) {
	printf("%04x ", i);
      }
      val = len > 0 ? *pc : -1;
      if (val >= 0) {
        printf("%02x ", val );
      } else {
        printf("   ");
      }
      str[i%16] = (val > 0x40 && val < 0x7f) ? val : '.';
      pc++;
      i++;
      len--;
      if(0 == i%16) {
	printf("  %s\n", str);
      }
    } while (i%16);  
  }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
	    const u_char *packet) {
    uint16_t *pfreq;
    uint64_t *pts;

    uint64_t curr_ts;

    uint8_t *prate;
    uint8_t *pflags;
    int8_t *psignal, *pnoise;
    struct timeval tv;

    uint8_t *pc = get80211payload(packet);
    uint8_t *bss = pc + 16;

    uint16_t *pseq = (uint16_t *)(bss+6);
    uint8_t *ptag = bss+20;
    char bssid[256];

    gettimeofday(&tv,NULL);

    curr_ts = 1000000 * tv.tv_sec + tv.tv_usec;
    if(*pc != 0x80) {
      // Not a beacon
      return;
    }

    pfreq = get80211field(packet, IEEE80211_RADIOTAP_CHANNEL);
    prate = get80211field(packet, IEEE80211_RADIOTAP_RATE);
    pflags = get80211field(packet, IEEE80211_RADIOTAP_FLAGS);
    pts = get80211field(packet, IEEE80211_RADIOTAP_TSFT);
    psignal = get80211field(packet, IEEE80211_RADIOTAP_DBM_ANTSIGNAL);
    pnoise = get80211field(packet, IEEE80211_RADIOTAP_DBM_ANTNOISE);
    if (*pflags & 0x40) {
      // Bad FCS
      return;
    }

    if(0 == *ptag) {
      int i;
      memset(bssid, 0, sizeof(bssid));
      memcpy(bssid, ptag+2, *(ptag+1));
      for(i=0; i<*(ptag+1); i++) {
        if(((uint8_t)bssid[i] >= 0x80) || (bssid[i] < 0x20)) {
          bssid[i] = '.';
        }
      }
      bssid[64] = 0;
    } else {
      memset(bssid, 0, sizeof(bssid));
    }

    printf("%20lld len %-5d freq %4d rate %-5d s/n: %d %d BSS %02x%02x%02x%02x%02x%02x | %s\n",
                 curr_ts, header->len, *pfreq, 500*(*prate), *psignal, *pnoise,
                 bss[0],bss[1],bss[2],bss[3],bss[4],bss[5], bssid);
    fflush(stdout);
    
    // hex((void *)packet, header->len);

    
}



void capture(char *dev) {
  pcap_t *pcap;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr header;	/* The header that pcap gives us */
  const u_char *packet;		/* The actual packet */

  if(NULL == dev) {
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
      fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
      exit(1);
    }
  }

  pcap = pcap_create(dev, errbuf);
  pcap_set_rfmon(pcap, 1);
  pcap_set_promisc(pcap, 1);
  pcap_set_buffer_size(pcap, 1 * 1024 * 1024);
  pcap_set_timeout(pcap, 1);
  pcap_set_snaplen(pcap, 16384);
  pcap_activate(pcap);    
  if(DLT_IEEE802_11_RADIO == pcap_datalink(pcap)) {
    pcap_loop(pcap, 0, got_packet, 0);
  } else {
    fprintf(stderr, "Could not initialize a IEEE802_11_RADIO packet capture for interface %s\n", dev);
  }
}

int main(int argc, char *argv[]) {
  if(argc > 1) {
    capture(argv[1]);
  } else {
    capture(NULL);
  }
}
