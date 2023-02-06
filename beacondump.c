#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include "ieee802_11_radio.h"


typedef struct {
   int freq;
   int channel;
} one_freq2channel_t;

one_freq2channel_t freq2channel[] = {
{ 5160, 32 },
{ 5170, 34 },
{ 5180, 36 },
{ 5190, 38 },
{ 5200, 40 },
{ 5210, 42 },
{ 5220, 44 },
{ 5230, 46 },
{ 5240, 48 },
{ 5250, 50 },
{ 5260, 52 },
{ 5270, 54 },
{ 5280, 56 },
{ 5290, 58 },
{ 5300, 60 },
{ 5310, 62 },
{ 5320, 64 },
{ 5340, 68 },
{ 5480, 96 },
{ 5500, 100 },
{ 5510, 102 },
{ 5520, 104 },
{ 5530, 106 },
{ 5540, 108 },
{ 5550, 110 },
{ 5560, 112 },
{ 5570, 114 },
{ 5580, 116 },
{ 5590, 118 },
{ 5600, 120 },
{ 5610, 122 },
{ 5620, 124 },
{ 5630, 126 },
{ 5640, 128 },
{ 5660, 132 },
{ 5670, 134 },
{ 5680, 136 },
{ 5690, 138 },
{ 5700, 140 },
{ 5710, 142 },
{ 5720, 144 },
{ 5745, 149 },
{ 5755, 151 },
{ 5765, 153 },
{ 5775, 155 },
{ 5785, 157 },
{ 5795, 159 },
{ 5805, 161 },
{ 5815, 163 },
{ 5825, 165 },
{ 5835, 167 },
{ 5845, 169 },
{ 5855, 171 },
{ 5865, 173 },
{ 5875, 175 },
{ 5885, 177 },
{ 5900, 180 },
{ 5910, 182 },
{ 5920, 184 },
{ 5935, 187 },
{ 5940, 188 },
{ 5945, 189 },
{ 5960, 192 },
{ 5980, 196 },
  { 0, 0 },
};

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

int convert_freq2_channel(int freq) {
  int i = 0;
  while (freq2channel[i].channel) {
    if (freq == freq2channel[i].freq) {
      return freq2channel[i].channel;
    }
    i++;
  }
  return freq;
}

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

char **EXCLUDE_SSID = NULL;
int EXCLUDE_SSID_COUNT = 0;

char *BLACK = "\x1b[30m";
char *GREEN = "\x1b[32m";
char *YELLOW= "\x1b[33m";
char *RED = "\x1b[31m";
char *BRIGHT_RED = "\x1b[31;1m";
char *RESET= "\x1b[0m";

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
    int i;

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

    for(i=0; i<EXCLUDE_SSID_COUNT; i++) {
        if(0 == strncmp(EXCLUDE_SSID[i], bssid, sizeof(bssid))) {
          // we do not want to print this
          return;
        }
    }
/*
    printf("%20lld len %-5d freq %4d rate %-5d s/n: %d %d seq %03x BSS %02x%02x%02x%02x%02x%02x | %s\n",
                 curr_ts, header->len, *pfreq, 500*(*prate), *psignal, *pnoise, *pseq >> 4,
                 bss[0],bss[1],bss[2],bss[3],bss[4],bss[5], bssid);
*/
    char *color_start = "";
    char *color_end = RESET;
    if (*psignal > -40) {
      color_start = BRIGHT_RED;
    } else if (*psignal > -50) {
      color_start = YELLOW;
    }
    printf("%20lld channel %4d %ssignal%s: %d noise: %d BSS %02x%02x%02x%02x%02x%02x | %s\n",
                 curr_ts, convert_freq2_channel(*pfreq), color_start, color_end, *psignal, *pnoise,
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
    perror("wifi");
  }
}

int main(int argc, char *argv[]) {
  if(argc > 1) {
    if (argc > 2) {
	EXCLUDE_SSID = argv + 2;
        EXCLUDE_SSID_COUNT = argc - 2;
    }
    capture(argv[1]);

  } else {
    capture(NULL);
  }
}
