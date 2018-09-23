/*******************************************************************************************************************/
// U DRIVER - AMP scan monitor with payload capture
// gcc -static -Wall udriver.c -lGeoIP -lm -lpcap -o udriver
// -Estella Mystagic
/*******************************************************************************************************************/
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <math.h>

#include "GeoIP.h"
#include "GeoIPCity.h"

/*******************************************************************************************************************/
#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN  6
/*******************************************************************************************************************/
struct sniff_ethernet {
  u_char  ether_dhost[ETHER_ADDR_LEN];
  u_char  ether_shost[ETHER_ADDR_LEN];
  u_short ether_type;
};
/*******************************************************************************************************************/
struct sniff_ip {
  u_char  ip_vhl;
  u_char  ip_tos;
  u_short ip_len;
  u_short ip_id;
  u_short ip_off;
  #define IP_RF 0x8000
  #define IP_DF 0x4000
  #define IP_MF 0x2000
  #define IP_OFFMASK 0x1fff
  u_char  ip_ttl;
  u_char  ip_p;
  u_short ip_sum;
  struct  in_addr ip_src,ip_dst;
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
/*******************************************************************************************************************/
/* TCP header */
typedef u_int tcp_seq;
struct sniff_tcp {
  u_short th_sport;
  u_short th_dport;
  tcp_seq th_seq;
  tcp_seq th_ack;
  u_char  th_offx2;
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
  u_char  th_flags;
  #define TH_FIN  0x01
  #define TH_SYN  0x02
  #define TH_RST  0x04
  #define TH_PUSH 0x08
  #define TH_ACK  0x10
  #define TH_URG  0x20
  #define TH_ECE  0x40
  #define TH_CWR  0x80
  #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win;
  u_short th_sum;
  u_short th_urp;
};
/*******************************************************************************************************************/
struct sniff_udp {
  uint16_t sport;
  uint16_t dport;
  uint16_t udp_length;
  uint16_t udp_sum;
};
/*******************************************************************************************************************/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_app_usage(void);
/**************************************************************************************************/
static const char * _mk_NA( const char * p ){ return p ? p : "N/A"; }
static const char * _mk_UU( const char * u ){ return u ? u : "UU"; }
/**************************************************************************************************/
// Get Country Code
static char *grabcountry(char *ipaddy) {
  GeoIP *gx;
  const char *remote_country;
  gx = GeoIP_open("/GeoIP/GeoIP.dat", GEOIP_STANDARD);
  if (gx == NULL) {
    fprintf(stderr, "Error opening GeoIP.dat database\n");
    exit(1);
  }
  remote_country = GeoIP_country_code_by_name(gx, (const char *) ipaddy);
  GeoIP_delete(gx);
  return (char *) remote_country;
}
/**************************************************************************************************/
// Get ASN Router Information
static char *grabasn(char *ipaddy) {
  GeoIP *ga;
  const char *asn;
  ga = GeoIP_open("/GeoIP/GeoIPASNum.dat", GEOIP_STANDARD);
  if (ga == NULL) {
    fprintf(stderr, "Error opening GeoIPASNum.dat database\n");
    exit(1);
  }
  asn = GeoIP_org_by_addr(ga, (const char *) ipaddy);
  GeoIP_delete(ga);
  return (char *) asn;
}
/**************************************************************************************************/
/* see also: http://en.wikipedia.org/wiki/Great-circle_distance */
double calc_distance(float latitude, float longitude, float geo_lat, float geo_long) {
  double distance;
  float earth = 6367.46;
  double la1 = latitude * M_PI / 180.0, la2 = geo_lat * M_PI / 180.0, lo1 = longitude * M_PI / 180.0, lo2 = geo_long * M_PI / 180.0;
  distance = atan2(sqrt(pow(cos(la2) * sin(lo1-lo2), 2.0) + pow(cos(la1) * sin(la2) - sin(la1) * cos(la2) * cos(lo1-lo2), 2.0)), sin(la1) * sin(la2) + cos(la1) * cos(la2) * cos(lo1-lo2));
  if (distance < 0.0) { distance += 2 * M_PI; }
  distance *= earth;
  return distance;
}
/*******************************************************************************************************************/
double calc_bearing(float latitude, float longitude, float geo_lat, float geo_long) {
  double bearing;
  static double golden_ratio = 180.0 / M_PI;
  double la1 = latitude * M_PI / 180.0, la2 = geo_lat * M_PI / 180.0, lo1 = longitude * M_PI / 180.0, lo2 = geo_long * M_PI / 180.0;
  bearing = atan2(sin(lo2-lo1) * cos(la2), (cos(la1) * sin(la2)) - sin(la1) * cos(la2) * cos(lo2-lo1)) * golden_ratio;
  if (bearing < 0.f) { bearing += 360.f; }
  return bearing;
}
/*******************************************************************************************************************/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  const struct sniff_ethernet *ethernet;
  const struct sniff_ip *ip;
  const struct sniff_udp *udp;
  int i;
  int size_ip;
  int size_udp;
  int size_payload;
  const char *payload;
  const u_char *ch;  
  ethernet = (struct sniff_ethernet*)(packet);
  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip)*4;
  if (size_ip < 20) { return; }
  udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
  size_udp = ntohs(udp->udp_length);
  if (size_udp < 8) { return; }

  time_t timer;
  char timestamp[26];
  struct tm* tm_info;
  time(&timer);
  tm_info = localtime(&timer);
  strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);

  char **ret;
  GeoIP *gi;
  GeoIPRecord *gir;
  const char *time_zone = NULL;
  double distance, bearing, miles;
  float mylat = 34.0459947, mylong = -118.261182, milesconversion = 0.621371192; // Edit to your lat & long

  gi = GeoIP_open("/GeoIP/GeoLiteCity.dat", GEOIP_INDEX_CACHE);
  if (gi == NULL) { 
    fprintf(stdout, "[%s] UDP AMP SCAN - Port: %d, IP: %s\n", timestamp, ntohs(udp->dport), inet_ntoa(ip->ip_src));    
    return; 
  }
  gir = GeoIP_record_by_name(gi, (const char *) inet_ntoa(ip->ip_src));
  if (gir != NULL) {
    ret = GeoIP_range_by_ip(gi, (const char *) inet_ntoa(ip->ip_src));
    time_zone = GeoIP_time_zone_by_country_and_region(gir->country_code, gir->region);
    distance = calc_distance(mylat, mylong, gir->latitude, gir->longitude);
    bearing = calc_bearing(mylat, mylong, gir->latitude, gir->longitude);
    miles = distance * milesconversion;
    fprintf(stdout, "[%s] UDP AMP SCAN - Port: %d, IP: %s [%s], ASN: %s\n", timestamp, ntohs(udp->dport), inet_ntoa(ip->ip_src), _mk_UU(grabcountry(inet_ntoa(ip->ip_src))), _mk_NA(grabasn(inet_ntoa(ip->ip_src))));
    fprintf(stdout, "[%s] UDP AMP SCAN - Port: %d, IP: %s [%s], METADATA: - City: %s, Region: %s (%s), %s [%s]\n", 
    timestamp, ntohs(udp->dport), inet_ntoa(ip->ip_src), _mk_UU(grabcountry(inet_ntoa(ip->ip_src))), 
    _mk_NA(gir->city), _mk_NA(GeoIP_region_name_by_code(gir->country_code, gir->region)), _mk_NA(gir->region), _mk_NA(gir->postal_code), gir->country_name);
    fprintf(stdout, "[%s] UDP AMP SCAN - Port: %d, IP: %s [%s], METADATA: - Coordinates : [%f, %f], distance %.3f miles (%.3f km), bearing %.2f degrees\n", timestamp, ntohs(udp->dport), inet_ntoa(ip->ip_src), _mk_UU(grabcountry(inet_ntoa(ip->ip_src))), gir->latitude, gir->longitude, miles, distance, bearing);
    GeoIP_range_by_ip_delete(ret);
    GeoIPRecord_delete(gir);    
  } else {
    fprintf(stdout, "[%s] UDP AMP SCAN - Port: %d, IP: %s [%s], ASN: %s\n", timestamp, ntohs(udp->dport), inet_ntoa(ip->ip_src), _mk_UU(grabcountry(inet_ntoa(ip->ip_src))), _mk_NA(grabasn(inet_ntoa(ip->ip_src))));
  }

  payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + 8);
  size_payload = ntohs(ip->ip_len) - (size_ip + 8);
  if (size_payload > 0) {
    fprintf(stdout, "[%s] UDP AMP SCAN - Port: %d, IP: %s [%s], Payload (%d): ", timestamp, ntohs(udp->dport), inet_ntoa(ip->ip_src), _mk_UU(grabcountry(inet_ntoa(ip->ip_src))), size_payload);
    ch = payload;
    for(i = 0; i < size_payload; i++) { printf("\\x%02X", *ch); ch++; }
    printf("\n");
  }
  
  GeoIP_delete(gi);
  return;
}
/*******************************************************************************************************************/
int main(int argc, char **argv) {
  char *dev = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  char filter_exp[] = "udp and dst net 10.0.0.0/24 and (dst port 7 or dst port 17 or dst port 19 or dst port 53 or dst port 69 or dst port 111 or dst port 123 or dst port 137 or dst port 161 or dst port 177 or dst port 389 or dst port 500 or dst port 520 or dst port 523 or dst port 1434 or dst port 1701 or dst port 1900 or dst port 2123 or dst port 5060 or dst port 5093 or dst port 5351 or dst port 5353 or dst port 6429 or dst port 7778 or dst port 9987 or dst port 11211 or dst port 15742 or dst port 27015 or dst port 27960 or dst port 44818 or dst port 47808 or dst port 49287 or dst port 53413 or dst port 61530)"; // EDIT for your subnet.
  struct bpf_program fp;
  bpf_u_int32 mask;
  bpf_u_int32 net;

  if (argc == 2) {
    dev = argv[1];
  } else if (argc > 2) {
    fprintf(stderr, "error: unrecognized command-line options\n\n");
    exit(EXIT_FAILURE);
  } else {
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
      fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
      exit(EXIT_FAILURE);
    }
  }

  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n",  dev, errbuf);
    net = 0;
    mask = 0;
  }

  handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    exit(EXIT_FAILURE);
  }

  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "%s is not an Ethernet\n", dev);
    exit(EXIT_FAILURE);
  }

  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  pcap_loop(handle, 0, got_packet, NULL);

  pcap_freecode(&fp);
  pcap_close(handle);
        
  return 0;
}
/*******************************************************************************************************************/
// EOF
