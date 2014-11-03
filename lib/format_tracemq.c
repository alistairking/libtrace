/*
 * This file is part of libtrace
 *
 * Copyright (c) 2007,2008,2009,2010 The University of Waikato, Hamilton, 
 * New Zealand.
 *
 * Authors: Daniel Lawson 
 *          Perry Lorier
 *          Shane Alcock
 *          
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND 
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libtrace; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id$
 *
 */


#define _GNU_SOURCE

#include "config.h"
#include "common.h"
#include "libtrace.h"
#include "libtrace_int.h"
#include "format_helper.h"
#include "tracemq_protocol.h"

#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <czmq.h>

#ifndef WIN32
# include <netdb.h>
#endif

#define TRACEMQ_INFO ((struct tracemq_format_data_t*)libtrace->format_data)

/** @todo make configurable */
#define RX_RECORD_BUFFER 20000000

struct tracemq_format_data_t {
	/* TraceMQ URI of the host to connect to */
	char *uri;
        /* ZMQ context */
        zctx_t *context;
        /* ZMQ socket */
        void *socket;

	/* Header for the packet currently being received */
	tracemq_header_t tracemq_hdr;

	/* ZMQ msg for the packet buffer last received */
        zmq_msg_t msgbuf;
        int msgbuf_init;

	/* Dummy traces that can be assigned to the received packets to ensure
	 * that the appropriate functions can be used to process them */
	/* TODO - figure out if this can be a union */
	libtrace_t *dummy_duck;
	libtrace_t *dummy_erf;
	libtrace_t *dummy_pcap;
	libtrace_t *dummy_linux;
	libtrace_t *dummy_ring;
	libtrace_t *dummy_bpf;
};

/* Connects to a TraceMQ server 
 *
 * Returns -1 if an error occurs
 */
static int tracemq_connect(libtrace_t *libtrace) {
	assert(TRACEMQ_INFO->context != NULL);
	assert(TRACEMQ_INFO->uri != NULL);

        if ((TRACEMQ_INFO->socket =
	     zsocket_new(TRACEMQ_INFO->context, ZMQ_SUB)) == NULL) {
                trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
			      "Could not create ZMQ socket");
		return -1;
        }

	zsocket_set_rcvhwm(TRACEMQ_INFO->socket, RX_RECORD_BUFFER);

	if (zsocket_connect(TRACEMQ_INFO->socket,
			    "%s", TRACEMQ_INFO->uri) == -1) {
                trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
			      "Could not connect to %s",
			      TRACEMQ_INFO->uri);
		return -1;
        }

	/* subscribe to all messages */
	zsocket_set_subscribe(TRACEMQ_INFO->socket, "");

	return 0;
}

static void tracemq_init_format_data(libtrace_t *libtrace) {
        libtrace->format_data = malloc(sizeof(struct tracemq_format_data_t));

	TRACEMQ_INFO->dummy_duck = NULL;
	TRACEMQ_INFO->dummy_erf = NULL;
	TRACEMQ_INFO->dummy_pcap = NULL;
	TRACEMQ_INFO->dummy_linux = NULL;
	TRACEMQ_INFO->dummy_ring = NULL;
	TRACEMQ_INFO->dummy_bpf = NULL;

	TRACEMQ_INFO->uri = NULL;
	TRACEMQ_INFO->context = NULL;
	TRACEMQ_INFO->socket = NULL;
        TRACEMQ_INFO->msgbuf_init = 0;
}

static int tracemq_init_input(libtrace_t *libtrace) {
        char *uridata = libtrace->uridata;

	tracemq_init_format_data(libtrace);

	if((TRACEMQ_INFO->context = zctx_new()) == NULL) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
			      "Failed to create 0MQ context");
		return -1;
	}

	/* If the user specifies "tracemq:" then assume the default uri
	   (tcp://localhost:7600) */
        if (strlen(uridata) == 0) {
	        TRACEMQ_INFO->uri = strdup(TRACEMQ_DEFAULT_URI);
        } else {
                TRACEMQ_INFO->uri = strdup(uridata);
        }

	return 0;
}

static int tracemq_start_input(libtrace_t *libtrace) {
	/* subscribe to the flood */
	if (tracemq_connect(libtrace) == -1)
		return -1;

	/* indicate that we have no valid packet data */
	TRACEMQ_INFO->tracemq_hdr.type = TRACE_RT_LAST;

	return 0;
}

static int tracemq_pause_input(libtrace_t *libtrace) {
        if(TRACEMQ_INFO->msgbuf_init != 0) {
                zmq_msg_close(&TRACEMQ_INFO->msgbuf);
                TRACEMQ_INFO->msgbuf_init = 0;
        }

	/* close the socket */
	zsocket_destroy(TRACEMQ_INFO->context, TRACEMQ_INFO->socket);
	TRACEMQ_INFO->socket = NULL;
	/* destroy the context */
	zctx_destroy(&TRACEMQ_INFO->context);
	return 0;
}

static int tracemq_fin_input(libtrace_t *libtrace) {
        if(TRACEMQ_INFO->msgbuf_init != 0) {
                zmq_msg_close(&TRACEMQ_INFO->msgbuf);
                TRACEMQ_INFO->msgbuf_init = 0;
        }

	free(TRACEMQ_INFO->uri);
	TRACEMQ_INFO->uri = NULL;

	/* Make sure we clean up any dummy traces that we have been using */
	if (TRACEMQ_INFO->dummy_duck)
		trace_destroy_dead(TRACEMQ_INFO->dummy_duck);

	if (TRACEMQ_INFO->dummy_erf)
		trace_destroy_dead(TRACEMQ_INFO->dummy_erf);

	if (TRACEMQ_INFO->dummy_pcap)
		trace_destroy_dead(TRACEMQ_INFO->dummy_pcap);

	if (TRACEMQ_INFO->dummy_linux)
		trace_destroy_dead(TRACEMQ_INFO->dummy_linux);

	if (TRACEMQ_INFO->dummy_ring)
		trace_destroy_dead(TRACEMQ_INFO->dummy_ring);

	if (TRACEMQ_INFO->dummy_bpf)
		trace_destroy_dead(TRACEMQ_INFO->dummy_bpf);
	free(libtrace->format_data);
        return 0;
}


/* Sets the trace format for the packet to match the format it was originally
 * captured in, rather than the TraceMQ format */
static int tracemq_set_format(libtrace_t *libtrace, libtrace_packet_t *packet)
{
	/* We need to assign the packet to a "dead" trace */

	/* Try to minimize the number of corrupt packets that slip through
	 * while making it easy to identify new pcap DLTs */
	if (packet->type > TRACE_RT_DATA_DLT &&
	    packet->type < TRACE_RT_DATA_DLT_END) {
		if (!TRACEMQ_INFO->dummy_pcap) {
			TRACEMQ_INFO->dummy_pcap =
				trace_create_dead("pcapfile:-");
		}
		packet->trace = TRACEMQ_INFO->dummy_pcap;
		return 0;
	}

	if (packet->type > TRACE_RT_DATA_BPF &&
	    packet->type < TRACE_RT_DATA_BPF_END) {

		if (!TRACEMQ_INFO->dummy_bpf) {
			TRACEMQ_INFO->dummy_bpf = trace_create_dead("bpf:-");
			/* This may fail on a non-BSD machine */
			if (trace_is_err(TRACEMQ_INFO->dummy_bpf)) {
				trace_perror(TRACEMQ_INFO->dummy_bpf,
					     "Creating dead bpf trace");
				return -1;
			}
		}
		packet->trace = TRACEMQ_INFO->dummy_bpf;
		return 0;
	}

	switch (packet->type) {
		case TRACE_RT_DUCK_2_4:
		case TRACE_RT_DUCK_2_5:
			if (!TRACEMQ_INFO->dummy_duck) {
				TRACEMQ_INFO->dummy_duck =
					trace_create_dead("duck:dummy");
			}
			packet->trace = TRACEMQ_INFO->dummy_duck;
			break;
		case TRACE_RT_DATA_ERF:
			if (!TRACEMQ_INFO->dummy_erf) {
				TRACEMQ_INFO->dummy_erf =
					trace_create_dead("erf:-");
			}
			packet->trace = TRACEMQ_INFO->dummy_erf;
			break;
		case TRACE_RT_DATA_LINUX_NATIVE:
			if (!TRACEMQ_INFO->dummy_linux) {
				TRACEMQ_INFO->dummy_linux =
					trace_create_dead("int:");
				/* This may fail on a non-Linux machine */
				if (trace_is_err(TRACEMQ_INFO->dummy_linux)) {
					trace_perror(TRACEMQ_INFO->dummy_linux,
						     "Creating dead int trace");
					return -1;
				}
			}
			packet->trace = TRACEMQ_INFO->dummy_linux;
			break;
		case TRACE_RT_DATA_LINUX_RING:
			if (!TRACEMQ_INFO->dummy_ring) {
				TRACEMQ_INFO->dummy_ring =
					trace_create_dead("ring:");
				/* This may fail on a non-Linux machine */
				if (trace_is_err(TRACEMQ_INFO->dummy_ring)) {
					trace_perror(TRACEMQ_INFO->dummy_ring,
						     "Creating dead int trace");
					return -1;
				}
			}
			packet->trace = TRACEMQ_INFO->dummy_ring;
			break;
		case TRACE_RT_STATUS:
		case TRACE_RT_METADATA:
			/* Just use the RT trace! */
			packet->trace = libtrace;
			break;
		case TRACE_RT_DATA_LEGACY_ETH:
		case TRACE_RT_DATA_LEGACY_ATM:
	        case TRACE_RT_DATA_LEGACY_POS:
			printf("Sending legacy over TraceMQ is currently "
			       "not supported\n");
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
				      "Legacy packet cannot be sent over "
				      "TraceMQ");
			return -1;
		default:
			printf("Unrecognised format: %u\n", packet->type);
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET,
				      "Unrecognised packet format");
			return -1;
	}
	return 0; /* success */
}

#if 0
/* Shouldn't need to call this too often */
static int tracemq_prepare_packet(libtrace_t *libtrace,
				  libtrace_packet_t *packet,
				  void *buffer,
				  libtrace_rt_types_t tracemq_type,
				  uint32_t flags) {

	if (packet->buffer != buffer &&
	    packet->buf_control == TRACE_CTRL_PACKET) {
                free(packet->buffer);
        }

        if ((flags & TRACE_PREP_OWN_BUFFER) == TRACE_PREP_OWN_BUFFER) {
                packet->buf_control = TRACE_CTRL_PACKET;
        } else {
                packet->buf_control = TRACE_CTRL_EXTERNAL;
	}

        packet->buffer = buffer;
        packet->header = NULL;
        packet->type = tracemq_type;
	packet->payload = buffer;

	if (libtrace->format_data == NULL) {
		tracemq_init_format_data(libtrace);
	}

	return 0;
}
#endif

/* Reads the body of a TraceMQ packet from the network */
static int tracemq_read_data_packet(libtrace_t *libtrace,
				    libtrace_packet_t *packet) {
	size_t buffer_len = 0;

	uint32_t prep_flags = 0;
	prep_flags |= TRACE_PREP_DO_NOT_OWN_BUFFER;
        prep_flags |= TRACE_PREP_DO_NOT_FIX_AGAIN;

	/* if this is called, we already have read the message, we just
	   need to pop the next frame */

        if(zmq_msg_recv(&TRACEMQ_INFO->msgbuf, TRACEMQ_INFO->socket, 0) < 0) {
                return -1;
        }

	packet->buffer = zmq_msg_data(&TRACEMQ_INFO->msgbuf);
	buffer_len = zmq_msg_size(&TRACEMQ_INFO->msgbuf);

	/* Convert to the original capture format */
	if (tracemq_set_format(libtrace, packet) < 0) {
		fprintf(stderr, "could not set format\n");
		return -1;
        }

	/* Update payload pointers and packet type to match the original
	 * format */
	if (trace_prepare_packet(packet->trace, packet, packet->buffer,
				 packet->type, prep_flags)) {
		fprintf(stderr, "could not prepare packet\n");
		return -1;
	}

	return buffer_len;
}

#ifdef DEBUG
static uint64_t packets_rx = 0;
#endif

/* Reads a TraceMQ packet from the network.
 * It reads a new message from ZMQ, decodes the tracemq_header, and then
 * calls the appropriate handler function for the message type
 */
static int tracemq_read_packet_versatile(libtrace_t *libtrace,
					 libtrace_packet_t *packet) {
	size_t br = 0;

	libtrace_rt_types_t switch_type;

	if (zctx_interrupted) {
		return 0;
	}

	/* indicate that the packet buffer is not owned by the packet
	   ( it is owned by the frame that we will free later ) */
	if (packet->buf_control == TRACE_CTRL_PACKET) {
		packet->buf_control = TRACE_CTRL_EXTERNAL;
		free(packet->buffer);
		packet->buffer = NULL;
	}

	/* free the last buffer frame if any */
	if(TRACEMQ_INFO->msgbuf_init != 0) {
		zmq_msg_close(&TRACEMQ_INFO->msgbuf);
	}
        /* get ready to read payload */
        if(zmq_msg_init(&TRACEMQ_INFO->msgbuf) != 0) {
                return -1;
        }
        TRACEMQ_INFO->msgbuf_init = 1;

	/** @todo try not using czmq msg (or czmq at all) to remove overhead */

	/* read the next message from ZMQ */
        if(zmq_recv(TRACEMQ_INFO->socket,
                    &(TRACEMQ_INFO->tracemq_hdr), sizeof(tracemq_header_t), 0)
           != sizeof(tracemq_header_t)) {
                /* interrupted, probably */
                /** @todo check errno */
                if (zctx_interrupted) {
                        return 0;
                }
                return -1;
          }

        if(zsocket_rcvmore(TRACEMQ_INFO->socket) == 0) {
                /* missing payload */
                return -1;
        }

	packet->type = TRACEMQ_INFO->tracemq_hdr.type;

#ifdef DEBUG
	packets_rx++;
	if (packets_rx % 1000000 == 0) {
		fprintf(stderr,
			"received %"PRIu64" packets, current seq no is %"PRIu32"\n",
			packets_rx, TRACEMQ_INFO->tracemq_hdr.sequence);
	}
#endif

	/* All data-bearing packets (as opposed to internal messages)
	 * should be treated the same way when it comes to reading the rest
	 * of the packet */
	if (packet->type >= TRACE_RT_DATA_SIMPLE) {
		switch_type = TRACE_RT_DATA_SIMPLE;
	} else {
		switch_type = packet->type;
	}

	switch(switch_type) {
		case TRACE_RT_DATA_SIMPLE:
		case TRACE_RT_DUCK_2_4:
		case TRACE_RT_DUCK_2_5:
		case TRACE_RT_STATUS:
		case TRACE_RT_METADATA:
			br = tracemq_read_data_packet(libtrace, packet);
			break;
		case TRACE_RT_END_DATA:
		case TRACE_RT_KEYCHANGE:
		case TRACE_RT_LOSTCONN:
		case TRACE_RT_CLIENTDROP:
		case TRACE_RT_SERVERSTART:
			/* All these have no payload */
		case TRACE_RT_PAUSE_ACK:
			/* XXX: Add support for this */
		case TRACE_RT_OPTION:
			/* XXX: Add support for this */
		default:
			printf("Bad rt type for client receipt: %d\n",
			       switch_type);
			return -1;
	}

	/* Return the number of bytes read from the stream */
	return br;
}

/* Reads the next available packet in a blocking fashion */
static int tracemq_read_packet(libtrace_t *libtrace,
			  libtrace_packet_t *packet) {
	return tracemq_read_packet_versatile(libtrace,packet);
}

/* This should only get called for TraceMQ messages - TraceMQ-encapsulated data
 * records should be converted to the appropriate capture format */
static int tracemq_get_capture_length(const libtrace_packet_t *packet) {
	switch (packet->type) {
		case TRACE_RT_STATUS:
			return sizeof(tracemq_status_t);
		case TRACE_RT_HELLO:
			return 0;
		case TRACE_RT_START:
			return 0;
		case TRACE_RT_ACK:
			return 0;
		case TRACE_RT_END_DATA:
			return 0;
		case TRACE_RT_CLOSE:
			return 0;
		case TRACE_RT_DENY_CONN:
			return sizeof(tracemq_deny_conn_t);
		case TRACE_RT_PAUSE:
			return 0;
		case TRACE_RT_PAUSE_ACK:
			return 0;
		case TRACE_RT_OPTION:
			return 0; /* FIXME */
		case TRACE_RT_KEYCHANGE:
			return 0;
		case TRACE_RT_LOSTCONN:
			return 0;
		case TRACE_RT_SERVERSTART:
			return 0;
		case TRACE_RT_CLIENTDROP:
			return 0;
		case TRACE_RT_METADATA:
		        return 0;
		default:
			printf("Unknown type: %d\n", packet->type);

	}
	return 0;
}

/* TraceMQ messages do not have a wire length because they were not captured
 * from the wire - they were generated by the capture process */
static int tracemq_get_wire_length(UNUSED const libtrace_packet_t *packet) {
	return 0;
}

/* Although TraceMQ messages do contain "framing", this framing is considered to
 * be stripped as soon as the packet is read by the RT client */
static int tracemq_get_framing_length(UNUSED const libtrace_packet_t *packet) {
	return 0;
}

static libtrace_linktype_t tracemq_get_link_type(
				       UNUSED const libtrace_packet_t *packet) {
	/* TraceMQ messages don't have a link type */
	return TRACE_TYPE_NONDATA;
}

static void tracemq_help(void) {
        printf("TraceMQ format module\n");
        printf("Supported input URIs:\n");
        printf("\ttracemq:tcp://hostname:port\n");
        printf("\ttracemq: (connects on default uri (tcp://localhost:7600))\n");
        printf("\n");
        printf("\te.g.: tracemq:ipc://tracemq.ipc\n");
        printf("\te.g.: tracemq:tcp://capture.caida.org:7600\n");
        printf("\n");

}

static struct libtrace_format_t tracemq = {
        "tracemq",
        "$Id$",
        TRACE_FORMAT_TRACEMQ,
	NULL,				/* probe filename */
	NULL,				/* probe magic */
        tracemq_init_input,            	/* init_input */
        NULL,                           /* config_input */
        tracemq_start_input,           	/* start_input */
	tracemq_pause_input,		/* pause */
        NULL,                           /* init_output */
        NULL,                           /* config_output */
        NULL,                           /* start_output */
        tracemq_fin_input,             	/* fin_input */
        NULL,                           /* fin_output */
        tracemq_read_packet,           	/* read_packet */
#if 0
	tracemq_prepare_packet,		/* prepare_packet */
#else
	NULL,
#endif
	NULL,				/* fin_packet */
        NULL,                           /* write_packet */
        tracemq_get_link_type,	        /* get_link_type */
        NULL,  		            	/* get_direction */
        NULL,              		/* set_direction */
        NULL,          			/* get_erf_timestamp */
        NULL,                           /* get_timeval */
	NULL,				/* get_timespec */
        NULL,                           /* get_seconds */
	NULL,				/* seek_erf */
	NULL,				/* seek_timeval */
	NULL,				/* seek_seconds */
        tracemq_get_capture_length,    	/* get_capture_length */
	tracemq_get_wire_length,        /* get_wire_length */
        tracemq_get_framing_length, 	/* get_framing_length */
        NULL,         			/* set_capture_length */
	NULL,				/* get_received_packets */
	NULL,				/* get_filtered_packets */
	NULL,				/* get_dropped_packets */
	NULL,				/* get_captured_packets */
	NULL,                   	/* get_fd */
	NULL,                           /* trace_event */
        tracemq_help,			/* help */
	NULL				/* next pointer */
};

void tracemq_constructor(void) {
	register_format(&tracemq);
}
