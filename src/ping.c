
#include <sys/types.h>
#include <sys/endian.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef DEBUG
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#endif

#include "datapath.h"

struct ping_state {
	uint64_t mac;
	struct timeval t;
	uint32_t count;
	int pad;
};

#define AE_REQUEST		0x0100040600080100UL
#define AE_REPLY		0x0200040600080100UL

struct arphdr_ether {
	union {
		uint64_t data;
		struct arphdr fields;
	} ae_hdr;
	uint8_t	ae_sha[ETHER_ADDR_LEN];
	uint32_t	ae_spa;
	uint8_t	ae_tha[ETHER_ADDR_LEN];
	uint32_t	ae_tpa;
} __packed;

static int
client_dispatch(char *rxbuf, char *txbuf, path_state_t *ps, void *arg)
{
	struct ether_header *deh = (struct ether_header *)txbuf;
	struct arphdr_ether *dae = (struct arphdr_ether *)(txbuf + ETHER_HDR_LEN);
	struct ether_header *seh = (struct ether_header *)rxbuf;
	struct arphdr_ether *sae = (struct arphdr_ether *)(rxbuf + ETHER_HDR_LEN);
	struct ping_state *state = arg;
	struct timeval t0, delta;
	char buf[16];
	uint16_t op;
	uint8_t *m; 
	
	if (rxbuf != NULL) {
		m = seh->ether_shost;
		op = be16toh(sae->ae_hdr.fields.ar_op);
		snprintf(buf, 16, "op: 0x%02x", op);
		D("got %s from: %02x:%02x:%02x:%02x:%02x:%02x count: %d",
		  op == 2 ? "ARP_REPLY" : buf, m[0], m[1], m[2], m[3], m[4], m[5],
		  sae->ae_spa);
		return (0);
	}

	gettimeofday(&t0, NULL);
	timersub(&t0, &state->t, &delta);
	if (delta.tv_sec < 1)
		return (0);

	state->t.tv_sec = t0.tv_sec;
	state->t.tv_usec = t0.tv_usec;

	memset(&deh->ether_dhost, 0xFF, ETHER_ADDR_LEN);
	memcpy(&deh->ether_shost, &state->mac, ETHER_ADDR_LEN);
	deh->ether_type = htobe16(ETHERTYPE_ARP);
	dae->ae_hdr.data = AE_REQUEST;
	dae->ae_spa = state->count++;
	*(ps->ps_tx_len) = ETHER_HDR_LEN + sizeof(uint64_t);
	D("sent ARP_REQUEST");
	return (1);
}

static int
server_dispatch(char *rxbuf, char *txbuf, path_state_t *ps, void *arg)
{
	struct ether_header *deh = (struct ether_header *)txbuf;
	struct arphdr_ether *dae = (struct arphdr_ether *)(txbuf + ETHER_HDR_LEN);
	struct ether_header *seh = (struct ether_header *)rxbuf;
	struct arphdr_ether *sae = (struct arphdr_ether *)(rxbuf + ETHER_HDR_LEN);
	struct ping_state *state = arg;

	if (sae->ae_hdr.data != AE_REQUEST) {
		printf("got unrecognized packet, 0x%016lX\n", sae->ae_hdr.data);
		return (0);
	} else {
		uint8_t *m = seh->ether_shost;
		D("got ARP_REQUEST from: %02x:%02x:%02x:%02x:%02x:%02x count: %d",
		  m[0], m[1], m[2], m[3], m[4], m[5], sae->ae_spa);
	}
	memcpy(&deh->ether_dhost, seh->ether_shost, ETHER_ADDR_LEN);
	memcpy(&deh->ether_shost, &state->mac, ETHER_ADDR_LEN);
	deh->ether_type = htobe16(ETHERTYPE_ARP);
	dae->ae_hdr.data = AE_REPLY;
	dae->ae_spa = sae->ae_spa;
	*(ps->ps_tx_len) = ETHER_HDR_LEN + sizeof(uint64_t);
	return (1);
}

static uint64_t
mac_parse(char *input)
{
	char *idx, *mac = strdup(input);
	const char *del = ":";
	uint64_t mac_num = 0;
	uint8_t *mac_nump = (uint8_t *)&mac_num;
	int i;

	for (i = 0; ((idx = strsep(&mac, del)) != NULL) && i < ETHER_ADDR_LEN; i++)
		mac_nump[i] = (uint8_t)strtol(idx, NULL, 16);
	free(mac);
	if (i < ETHER_ADDR_LEN)
		return 0;
	return	mac_num;
}

static void
usage(char *name)
{
	printf("usage: %s [-s] [-e <mac addr>] [-p <netmap port>]\n", name);
	exit(1);
}

int
main(int argc, char *const argv[])
{
	int ch;
	char *port = NULL, *macp = NULL;
	uint64_t mac;
	int debug = 0, server = 0;
	dp_args_t port_args;
	struct ping_state state;

	mac = 0;
	bzero(&port_args, sizeof(dp_args_t));
	bzero(&state, sizeof(struct ping_state));
	while ((ch = getopt(argc, argv, "e:p:sd")) != -1) {
		switch (ch) {
			case 's':
				server = 1;
				break;
			case 'e':
				macp = optarg;
				break;
			case 'd':
				debug = 1;
				break;
			case 'p':
				port = optarg;
			case '?':
			default:
				usage(argv[0]);
		}
	}
	if (macp == NULL) {
		if (server) {
			mac = mac_parse("CA:FE:00:00:BA:BE");
		} else {
			mac = mac_parse("CA:FE:00:00:BE:EF");
		}
	}
	if (port == NULL) {
		if (server) {
			port = "vale_a:0";
		} else {
			port = "vale_a:1";
		}
	}
	state.mac = mac;
	port_args.da_pa_name = port;
	if (debug)
		port_args.da_flags = DA_DEBUG;
	if (server) {
		port_args.da_rx_dispatch = server_dispatch;
		port_args.da_poll_timeout = 10000;
	} else {
		port_args.da_tx_dispatch = client_dispatch;
		port_args.da_rx_dispatch = client_dispatch;
		port_args.da_poll_timeout = 1000;

	}
	run_datapath(&port_args, &state);
	return 0;
}
