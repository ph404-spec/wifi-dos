/*
 * Frame Spammer
 * send a raw frame multiple times using a wireless ethernet adapter
 * Copyright (c) 2007, Matej Sustr
 *
 * Code based on:
 * Raw Covert: an IEEE 802.11 Covert Channel
 * Copyright (c) 2005-2006, Laurent Butti
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <stdint.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <getopt.h>

#include <unistd.h>	// usleep()


int close(int sock);
int usage(char *arg0);

const char *appname = "Frame Spammer";
const char *desc = "send an IEEE802.11 raw frame multiple times";
const char *date = "2007";
const char *author = "Matej Sustr";
const char *version = "0";

#define PRISM_HEADER 144

#define ARPHRD_IEEE80211 801
#define ARPHRD_IEEE80211_PRISM 802

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

int ctrl_c = 0;
int sock = 0;
char *ifname = NULL;

/* frame to send */
u8 frame_send[4096];
int frame_size;

/* options */
int num = 0;		//resend this many times (0=virtually infinite)
int delay = 10000;	//default delay


static void sighandler (int sig)
{
	if (sig == SIGINT) {
		ctrl_c++;
		fprintf(stderr, "Info:\tUser interrupt\n");
	}
}

static int open_sock (char *ifname, int sock)
{
	struct sockaddr_ll ll_addr;
	struct ifreq ifr;

	sock = socket (PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock == -1) {
		fprintf(stderr, "Error:\tSocket failed\n");
		return (-1);
	}

	ll_addr.sll_family = AF_PACKET;
	ll_addr.sll_protocol = 0;
	ll_addr.sll_halen = ETH_ALEN;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
		fprintf(stderr, "Error:\tioctl(SIOCGIFINDEX) failed\n");
		return (-1);
	}

	ll_addr.sll_ifindex = ifr.ifr_ifindex;

	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
		fprintf(stderr, "Error:\tioctl(SIOCGIFHWADDR) failed\n");
		return (-1);
	}

	memcpy(ll_addr.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	if (ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211 &&
	    ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_PRISM) {
		fprintf( stderr, "Error:\tbad linktype\n");
		return (-1);
	}

	if (bind (sock, (struct sockaddr *)&ll_addr, sizeof(ll_addr)) == -1) {
		fprintf(stderr, "Error:\tbind failed\n");
		close(sock);
		return (-1);
	}

	return sock;
}


// read input and store it in sending buffer
int read_input (void) {
	int l;

	frame_size = 0;
	while ((l = read(0, frame_send+frame_size, 1)) > 0 \
	    && !ctrl_c && frame_size < 4096)
		frame_size += l;
        
	if (!frame_size && !ctrl_c){
		fprintf(stderr, "Error:\tno frame to send\n");
		return 0;
	}
    
	return 1;
}

// send the frame multiple times
int send_frames (void) {
	if (num > 1)
		fprintf(stderr, "Info:\tSending %d frames (delay %d us)\n", num, delay);
	else if (num > 0)
		fprintf(stderr, "Info:\tSending 1 frame\n");
	else
		fprintf(stderr, "Info:\tSending many frames (delay %d us)\n", delay);

	int i = 0;
	while (ctrl_c == 0) {
		if (write(sock, frame_send, frame_size) < 0 )
			fprintf(stderr, "!");
		i++;

		if (!(i%100)) fprintf(stderr, ".");
		if (i == num) break;
		usleep(delay);
	}
	return 1;
}


int main (int argc, char **argv)
{
	/* options */
	char c;

	/* Retrieve command line options */
	while ((c = getopt(argc, argv, "hi:n:d:")) != EOF)
	switch(c) {
	case 'h':
		usage(argv[0]);
		return -1;
	case 'i':
		if (optarg) {
			ifname = optarg;
			break;
		} else {
			usage(argv[0]);
				return -1;
			}
		case 'n':
		if (optarg) {
			num = atoi(optarg);
			break;
		} else {
			usage(argv[0]);
			return -1;
		}
	case 'd':
		if (optarg) {
			delay = atoi(optarg);
			break;
		} else {
			usage(argv[0]);
			return -1;
		}
	default:
		usage(argv[0]);
		return -1;
	}

	printf( "\n%s, version %s -- %s"
		"\nCopyright (c) %s, %s\n\n"
		, appname, version, desc, date, author);

	if (ifname == NULL) {
		fprintf(stderr, "Error:\tIfname must be specified\n");
		usage(argv[0]);
		return -1;
	}

	/* Open raw socket */
	sock = open_sock (ifname, sock);

	if (sock == -1 ) {
		fprintf(stderr,
		"Error:\tCannot open socket\n"
		"Info:\tMust be root with an 802.11 card with RFMON enabled\n");
		return -1;
	}

	/* Get input */
	signal(SIGINT, sighandler); 
	if (!read_input()){
		usage(argv[0]);
		return -1;
	}
	
	/* Send it */
	if (!ctrl_c)
		send_frames();

	fprintf(stderr, "Info:\tTerminated\n");
	
	return 0;
}

int usage (char *arg0)
{
	printf("usage: %s [-h] -i <ifname> [-n <num>] [-d <delay>] < packet\n"
		"\tpacket\t\tfile containing the packet to send\n"
		"\t-h\t\tdisplay this message\n"
		"\t-i <ifname>\tselect interface for raw injection\n"
		"\t-n <num>\tnumber of repetitions (default = infinite)\n"
		"\t-d <delay>\tdelay between resending [microsec] (default = 10000)\n"
		"\n", arg0);
	return -1;
}
