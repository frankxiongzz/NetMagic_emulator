/*
 * emulator.h
 *
 *  Created on: Apr 8, 2016
 *      Author: magiclab
 */

#ifndef EMULATOR_H_
#define EMULATOR_H_

#include <pcap.h>
#include <libnet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

#define ETH_LEN 14
#define IP_LEN 20
#define NMAC_LEN 10
#define NMAC_PROTO 253
#define NMAC_SLEEP_TIME 2
#define NMAC_WAIT_TIME 2000   //与NetMagic相连至少需要等2.5秒

struct Nmac_Header {
    u_int8_t count;
    u_int8_t reserve8_A;
    u_int16_t seq;
    u_int16_t reserve16_B;
    u_int8_t nmac_type;
    u_int16_t parameter;
    u_int8_t reserve8_C;
}__attribute__((packed));

struct netmagic_handle {
    struct libnet_ether_addr *host_mac;
    struct libnet_ether_addr netmagic_mac;
    u_int32_t host_ip;
    u_int32_t netmagic_ip;
    libnet_t *libnet_handle;
    pcap_t *pcap_handle;
} nmac_handle;

struct end_point_msg {
	struct libnet_ether_addr src_mac;
	struct libnet_ether_addr dest_mac;
	u_int32_t src_ip;
	u_int32_t dest_ip;
	u_int16_t seq;
};

enum NMAC_PKT_TYPE {
	NMAC_CON = 0x01,
	NMAC_RD = 0x03,
	NMAC_WR = 0x04,
	NMAC_RD_REP = 0x05,
	NMAC_WR_REP = 0x06,
};

enum NMAC_MSG_TYPE
{
    NMAC_SUCCESS = 0,
    NMAC_ERROR_SEND = -1,
    NMAC_ERROR_TIMEOUT = -2,
    NMAC_ERROR_INIT = -3,
};

void parsing_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet);
int nmac_con_reply(struct end_point_msg end_point);
int nmac_rd_reply(struct end_point_msg end_point, int rd_num);
int nmac_wr_reply(struct end_point_msg end_point);

#endif /* EMULATOR_H_ */
