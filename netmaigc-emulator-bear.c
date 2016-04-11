/*
 ============================================================================
 Name        : netmaigc-emulator-bear.c
 Author      : 
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include "emulator.h"

int main(void) {
	char dev[100] = "eth0";
	nmac_ini(dev);

	return 0;
}

void parsing_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet){
	struct ether_header *eth_hdr = (struct ether_header *) (packet);
	struct iphdr *ip_hdr = (struct iphdr *) (packet + ETH_LEN);
	struct Nmac_Header *nmac_hdr = (struct Nmac_Header*) (packet + ETH_LEN + IP_LEN);
	struct end_point_msg end_point;
	end_point.seq = nmac_hdr->seq;
	end_point.dest_ip = ip_hdr->saddr;
	end_point.src_ip = ip_hdr->daddr;
	int i;
	for (i = 0; i < 6; i++) {
		end_point.dest_mac.ether_addr_octet[i] = eth_hdr->ether_shost[i];
		end_point.src_mac.ether_addr_octet[i] = eth_hdr->ether_dhost[i];
	}
	switch (nmac_hdr->nmac_type) {
		case NMAC_CON: {
			if (nmac_con_reply(end_point) > 0) {
				printf("send nmac con reply\n");
			}
			break;
		}
		case NMAC_WR: {
			if (nmac_wr_reply(end_point) > 0) {
				printf("send nmac write reply\n");
			}
			break;
		}
		case NMAC_RD: {
			if (nmac_rd_reply(end_point, htons(nmac_hdr->parameter)) > 0) {
				printf("send nmac write reply\n");
			}
			break;
		}
	}
}




int nmac_ini(char *dev){
	int i;
	struct bpf_program bpf_filter;
	char bpf_filter_string[50] = "ip proto 253 and ip dst 136.136.136.136";
	char dest_ip[100] = "136.136.136.136";
	char errbuf[255];

	nmac_handle.pcap_handle = pcap_open_live(dev, BUFSIZ, 0, NMAC_WAIT_TIME, errbuf);
	if (nmac_handle.pcap_handle == NULL)
	{
		printf("pcap error!pcap_open_live(): %s\n", errbuf);
		return NMAC_ERROR_INIT;
	}
	nmac_handle.libnet_handle = libnet_init(LIBNET_LINK, dev, errbuf);
	if (nmac_handle.libnet_handle == NULL)
	{
		printf("libnet_error!libnet_init(): %s\n", errbuf);
		return NMAC_ERROR_INIT;
	}
	nmac_handle.host_mac = libnet_get_hwaddr(nmac_handle.libnet_handle);
	nmac_handle.host_ip = libnet_get_ipaddr4(nmac_handle.libnet_handle);
	nmac_handle.netmagic_ip = libnet_name2addr4(nmac_handle.libnet_handle, dest_ip, LIBNET_DONT_RESOLVE);
	for(i=0; i<6; i++)
	{
		nmac_handle.netmagic_mac.ether_addr_octet[i] = 0x88;
	}
//	char *my_ip = libnet_addr2name4(nmac_handle.host_ip, LIBNET_DONT_RESOLVE);
//	strcat(bpf_filter_string, my_ip);
	pcap_compile(nmac_handle.pcap_handle, &bpf_filter, bpf_filter_string, 0, nmac_handle.host_ip);
	pcap_setfilter(nmac_handle.pcap_handle, &bpf_filter);

	pcap_loop(nmac_handle.pcap_handle, -1, parsing_callback, NULL);
	return NMAC_SUCCESS;
}

int nmac_con_reply(struct end_point_msg end_point){

	u_char *payload;
	payload = (u_char*)malloc(1480 * sizeof(u_char));
	libnet_ptag_t ip_protocol_tag = 0;
	libnet_ptag_t ether_protocol_tag = 0;
	u_int16_t payload_size;
	struct Nmac_Header nmac_head;
	nmac_head.count = 1;
	nmac_head.reserve8_A  = 0;
	nmac_head.seq = end_point.seq;
	nmac_head.reserve16_B = 0;
	nmac_head.nmac_type = NMAC_CON;
	nmac_head.parameter = htons(1);
	nmac_head.reserve8_C = 0;

	memcpy(payload, &nmac_head, sizeof(struct Nmac_Header));
	payload_size = sizeof(struct Nmac_Header);
	ip_protocol_tag = libnet_build_ipv4(
			LIBNET_IPV4_H + payload_size,
			0,
			0,
			0,
			64,
			NMAC_PROTO,
			0,
			end_point.src_ip,
			end_point.dest_ip,
			payload,
			payload_size,
			nmac_handle.libnet_handle,
			ip_protocol_tag);
	ether_protocol_tag = libnet_build_ethernet(
			end_point.dest_mac.ether_addr_octet,
			end_point.src_mac.ether_addr_octet,
			ETHERTYPE_IP,
			NULL,
			0,
			nmac_handle.libnet_handle,
			ether_protocol_tag);
	payload_size = libnet_write(nmac_handle.libnet_handle);
	libnet_clear_packet(nmac_handle.libnet_handle);
	if (payload_size > 0) {
		return NMAC_SUCCESS;
	}
	return NMAC_ERROR_SEND;
}

int nmac_wr_reply(struct end_point_msg end_point){

	printf("1\n");
	u_char *payload;
	payload = (u_char*) malloc(1480 * sizeof(u_char));
	libnet_ptag_t ip_protocol_tag = 0;
	libnet_ptag_t ether_protocol_tag = 0;
	u_int16_t payload_size;
	struct Nmac_Header write_reply;
	write_reply.count = 1;
	write_reply.reserve8_A  = 0;
	write_reply.seq = end_point.seq;
	write_reply.reserve16_B = 0;
	write_reply.nmac_type = NMAC_WR_REP;
	write_reply.parameter = 0;
	write_reply.reserve8_C = 0;
	memcpy(payload, &write_reply, sizeof(struct Nmac_Header));
	payload_size = sizeof(struct Nmac_Header);
	ip_protocol_tag = libnet_build_ipv4(
			LIBNET_IPV4_H + payload_size,
			0,
			0,
			0,
			64,
			NMAC_PROTO,
			0,
			end_point.src_ip,
			end_point.dest_ip,
			payload,
			payload_size,
			nmac_handle.libnet_handle,
			ip_protocol_tag);
	ether_protocol_tag = libnet_build_ethernet(
			end_point.dest_mac.ether_addr_octet,
			end_point.src_mac.ether_addr_octet,
			ETHERTYPE_IP,
			NULL,
			0,
			nmac_handle.libnet_handle,
			ether_protocol_tag);
	payload_size = libnet_write(nmac_handle.libnet_handle);
	libnet_clear_packet(nmac_handle.libnet_handle);
	if (payload_size > 0) {
		return NMAC_SUCCESS;
	}
	return NMAC_ERROR_SEND;
}

int nmac_rd_reply(struct end_point_msg end_point, int rd_num){
    u_char *payload;
    payload = (u_char*)malloc(1480 * sizeof(u_char));
    libnet_ptag_t ip_protocol_tag = 0;
    libnet_ptag_t ether_protocol_tag = 0;
    u_int16_t payload_size;
    struct Nmac_Header read_reply;

    read_reply.count = 1;
    read_reply.reserve8_A  = 0;
    read_reply.seq = end_point.seq;
    read_reply.reserve16_B = 0;
    read_reply.nmac_type = NMAC_RD_REP;
    read_reply.parameter = rd_num;
    read_reply.reserve8_C = 0;
    printf("%d\n", rd_num);
    int i;
    u_int32_t *data_net;
	data_net = (u_int32_t*) malloc(rd_num * sizeof(u_int32_t));
	for (i = 0; i < rd_num; i++){
		data_net[i] = htonl(i);
	}
    memcpy(payload, &read_reply, sizeof(struct Nmac_Header));
    memcpy(payload + sizeof(struct Nmac_Header), data_net, rd_num * sizeof(u_int32_t));
    payload_size = sizeof(struct Nmac_Header) + rd_num * sizeof(u_int32_t);
    ip_protocol_tag = libnet_build_ipv4(
                LIBNET_IPV4_H + payload_size,
                0,
                0,
                0,
                64,
                NMAC_PROTO,
                0,
				end_point.src_ip,
				end_point.dest_ip,
                payload,
                payload_size,
                nmac_handle.libnet_handle,
                ip_protocol_tag);
        ether_protocol_tag = libnet_build_ethernet(
    			end_point.dest_mac.ether_addr_octet,
    			end_point.src_mac.ether_addr_octet,
                ETHERTYPE_IP,
                NULL,
                0,
                nmac_handle.libnet_handle,
                ether_protocol_tag);

    payload_size = libnet_write(nmac_handle.libnet_handle);
    libnet_clear_packet(nmac_handle.libnet_handle);
	if (payload_size > 0) {
		return NMAC_SUCCESS;
	}
	return NMAC_ERROR_SEND;
}

