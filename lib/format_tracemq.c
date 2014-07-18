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

/* Convert the TraceMQ denial code into a nice printable and coherent string */
static const char *tracemq_deny_reason(enum tracemq_conn_denied_t reason) 
{
	const char *string = 0;

	switch(reason) {
		case TRACEMQ_DENY_FULL:
			string = "Max connections reached on server";
			break;
		case TRACEMQ_DENY_AUTH:
			string = "Authentication failed";
			break;
		default:
			string = "Unknown reason";
	}

	return string;
}

struct tracemq_format_data_t {
	/* TraceMQ URI of the host to connect to */
	char *uri;
        /* ZMQ context */
        zctx_t *context;
        /* ZMQ socket */
        void *socket;

	/* Header for the packet currently being received */
	tracemq_header_t tracemq_hdr;
	/* ZMQ message for the packet currently being recieved (without the
	   tracemq header frame) */
	zmsg_t *msg;

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

/* Sends an TraceMQ ACK to the server to acknowledge receipt of packets */
/** TODO remove the need to send ACKs */
static int tracemq_send_ack(libtrace_t *libtrace, uint32_t seqno)  {
	zframe_t *frame;
        tracemq_header_t ack_msg;

	ack_msg.type     = TRACE_RT_ACK;
	ack_msg.sequence = seqno;

	if(((frame =zframe_new (&ack_msg, sizeof(tracemq_header_t))) == NULL) ||
	   (zframe_send (&frame, TRACEMQ_INFO->socket, 0) == -1)) {
		printf("Failed to send ack to server");
		return -1;
	}

	return 0;
}

/* Connects to a TraceMQ server 
 *
 * Returns -1 if an error occurs
 */
static int tracemq_connect(libtrace_t *libtrace) {
	zmsg_t *msg;

	zframe_t *frame;
	tracemq_header_t tx_hdr;

	zframe_t *rx_hdr_frame;
	tracemq_header_t *rx_hdr;

	uint8_t reason;

	int rc = -1;

	assert(TRACEMQ_INFO->context != NULL);
	assert(TRACEMQ_INFO->uri != NULL);

        if ((TRACEMQ_INFO->socket =
	     zsocket_new(TRACEMQ_INFO->context, ZMQ_REQ)) == NULL) {
                trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
			      "Could not create ZMQ socket");
		return -1;
        }

	if (zsocket_connect(TRACEMQ_INFO->socket, "%s", TRACEMQ_INFO->uri) == -1) {
                trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
			      "Could not connect to %s",
			      TRACEMQ_INFO->uri);
		return -1;
        }

	/* We are connected, now send start message to server */
	tx_hdr.type = TRACE_RT_START;
	tx_hdr.sequence = 0;
	if((frame =
	    zframe_new (&tx_hdr, sizeof(tracemq_header_t))) == NULL) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
			      "Could not allocate message frame");
		return -1;
	}

	if(zframe_send (&frame, TRACEMQ_INFO->socket, 0) == -1) {
		trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
			      "Could not send start message to TraceMQ server");
		goto err;
	}
	/* frame is destroyed after send, safe to reassign or ignore */

	/* now we expect to get a hello message back from the server */
	/* or possibly a denied message */

	/** TODO - change to polling so that we can handle timeouts gracefully */

	if((msg = zmsg_recv (TRACEMQ_INFO->socket)) == NULL) {
		/* interrupted */
		goto err;
	}

	/* a message from the server will always begin with:
	 *  tracemq_header_t
	 *
	 * Then, based on the type, there may be much much more
	 */
	if((rx_hdr_frame = zmsg_pop(msg)) == NULL) {
		goto err;
	}

	rx_hdr = (tracemq_header_t*)zframe_data(rx_hdr_frame);

	switch (rx_hdr->type) {
		case TRACE_RT_DENY_CONN:
			/* Connection was denied */

			/* next frame is the reason */
			if((frame = zmsg_pop(msg)) == NULL) {
				goto err;
			}
			reason = ((tracemq_deny_conn_t*)zframe_data(frame))->reason;

			zframe_destroy(&frame);

			trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
				"Connection attempt is denied: %s",
				tracemq_deny_reason(reason));
			rc = -1;
			break;

		case TRACE_RT_HELLO:
			/* no hello header atm */

			tracemq_send_ack(libtrace, rx_hdr->sequence);

			rc = 0;
			break;

		default:
			trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
					"Unknown message type received: %d",
					rx_hdr->type);
			rc = -1;
			break;
	}

	if(rx_hdr_frame != NULL) {
		zframe_destroy(&frame);
	}
	if(msg != NULL) {
		zmsg_destroy(&msg);
	}
	return rc;

 err:
	trace_set_err(libtrace, TRACE_ERR_INIT_FAILED,
		      "TraceMQ Handshake failed");
	return -1;
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
	TRACEMQ_INFO->msg = NULL;
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

	/* handles sending a hello to the server, and getting back the response */
	if (tracemq_connect(libtrace) == -1)
		return -1;

	/* indicate that we have no valid packet data */
	TRACEMQ_INFO->tracemq_hdr.type = TRACE_RT_LAST;

	return 0;
}

static int tracemq_pause_input(libtrace_t *libtrace) {
	zframe_t *frame;
        tracemq_header_t close_msg;

	close_msg.type = TRACE_RT_CLOSE;

	/* Send a close message to the server */
	if(((frame = zframe_new (&close_msg, sizeof(tracemq_header_t))) == NULL) ||
	   (zframe_send (&frame, TRACEMQ_INFO->socket, 0) == -1)) {
		printf("Failed to send close message to server");
	}

	/* close the socket */
	zsocket_destroy(TRACEMQ_INFO->context, TRACEMQ_INFO->socket);
	TRACEMQ_INFO->socket = NULL;
	/* destroy the context */
	zctx_destroy(&TRACEMQ_INFO->context);
	return 0;
}

static int tracemq_fin_input(libtrace_t *libtrace) {
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

/** AK HAX out, revisit this */
#if 0
/* I've upped this to 10K to deal with jumbo-grams that have not been snapped
 * in any way. This means we have a much larger memory overhead per packet
 * (which won't be used in the vast majority of cases), so we may want to think
 * about doing something smarter, e.g. allocate a smaller block of memory and
 * only increase it as required.
 *
 * XXX Capturing off int: can still lead to packets that are larger than 10K,
 * in instances where the fragmentation is done magically by the NIC. This
 * is pretty nasty, but also very rare.
 */
#define RT_BUF_SIZE (LIBTRACE_PACKET_BUFSIZE * 2)

/* Receives data from an RT server */
static int rt_read(libtrace_t *libtrace, void **buffer, size_t len, int block)
{
        int numbytes;

	assert(len <= RT_BUF_SIZE);

	if (!RT_INFO->pkt_buffer) {
		RT_INFO->pkt_buffer = (char*)malloc((size_t)RT_BUF_SIZE);
		RT_INFO->buf_current = RT_INFO->pkt_buffer;
		RT_INFO->buf_filled = 0;
	}

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif

	if (block)
		block=0;
	else
		block=MSG_DONTWAIT;

	/* If we don't have enough buffer space for the amount we want to
	 * read, move the current buffer contents to the front of the buffer
	 * to make room */
	if (len > RT_INFO->buf_filled) {
		memcpy(RT_INFO->pkt_buffer, RT_INFO->buf_current,
				RT_INFO->buf_filled);
		RT_INFO->buf_current = RT_INFO->pkt_buffer;
#ifndef MSG_NOSIGNAL
#  define MSG_NOSIGNAL 0
#endif
		/* Loop as long as we don't have all the data that we were
		 * asked for */
		while (len > RT_INFO->buf_filled) {
                	if ((numbytes = recv(RT_INFO->input_fd,
                                                RT_INFO->buf_current +
						RT_INFO->buf_filled,
                                                RT_BUF_SIZE-RT_INFO->buf_filled,
                                                MSG_NOSIGNAL|block)) <= 0) {
				if (numbytes == 0) {
					trace_set_err(libtrace, TRACE_ERR_RT_FAILURE,
							"No data received");
					return -1;
				}

                	        if (errno == EINTR) {
                	                /* ignore EINTR in case
                	                 * a caller is using signals
					 */
                	                continue;
                	        }
				if (errno == EAGAIN) {
					/* We asked for non-blocking mode, so
					 * we need to return now */
					trace_set_err(libtrace,
							EAGAIN,
							"EAGAIN");
					return -1;
				}

                        	perror("recv");
				trace_set_err(libtrace, errno,
						"Failed to read data into rt recv buffer");
                        	return -1;
                	}
			RT_INFO->buf_filled+=numbytes;
		}

        }
	*buffer = RT_INFO->buf_current;
	RT_INFO->buf_current += len;
	RT_INFO->buf_filled -= len;
        return len;
}
#endif


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
			TRACEMQ_INFO->dummy_pcap = trace_create_dead("pcapfile:-");
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

/* Reads the body of a TraceMQ packet from the network */
static int tracemq_read_data_packet(libtrace_t *libtrace,
				    libtrace_packet_t *packet) {
	zframe_t *frame = NULL;
	size_t framing_len = 0;
	size_t payload_len = 0;

	uint32_t prep_flags = 0;
	prep_flags |= TRACE_PREP_DO_NOT_OWN_BUFFER;

	/* if this is called, we already have read the message, we just
	   need to pop the next frame */
	if((frame = zmsg_pop(TRACEMQ_INFO->msg)) == NULL) {
		return -1;
	}

	framing_len = zframe_size(frame);

#if DEBUG
	fprintf(stderr, "Unpacking packet with %d bytes of framing\n",
	       framing_len);
#endif

	/* ensure the buffer is big enough */
	if(packet->buffer != NULL) {
		packet->buffer = realloc(packet->buffer, framing_len);
	} else {
		packet->buffer = malloc(framing_len);
	}
	if(packet->buffer == NULL) {
		return -1;
	}

	/* for now, do a memcpy */
	/** TODO - figure out to this more efficiently */
	memcpy(packet->buffer, zframe_data(frame), framing_len);

	/* free the frame */
	zframe_destroy(&frame);

	/* wdcap would have sent one frame with framing, one with payload, check
	   if we have another frame */
	if((frame = zmsg_pop(TRACEMQ_INFO->msg)) != NULL) {
		payload_len = zframe_size(frame);

#if DEBUG
		fprintf(stderr, "\t... and %d bytes of payload\n",
			payload_len);
#endif

		/* ensure the buffer is big enough */
		if(packet->buffer != NULL) {
			packet->buffer = realloc(packet->buffer,
						 framing_len+payload_len);
		} else {
			packet->buffer = malloc(framing_len+payload_len);
		}
		if(packet->buffer == NULL) {
			return -1;
		}

		/* for now, do a memcpy */
		/** TODO - figure out to this more efficiently */
		memcpy(packet->buffer+framing_len,
		       zframe_data(frame), payload_len);


		zframe_destroy(&frame);

#if DEBUG
		int i;
		for (i = 0; i < (framing_len+payload_len); i++) {
			fprintf(stderr, "%02X ",((uint8_t*)(packet->buffer))[i]);
			if((i+1) % 8 == 0)
				fprintf(stderr, "\n");
			if(i == (framing_len-1))
				fprintf(stderr, "\n");
		}
		fprintf(stderr, "\n");
#endif
	}

#if DEBUG
	fprintf(stderr, "sending ack\n");
#endif

	/* Always send an ACK */
	if (tracemq_send_ack(libtrace,
			     TRACEMQ_INFO->tracemq_hdr.sequence) == -1) {
		return -1;
	}

	/* Convert to the original capture format */
	if (tracemq_set_format(libtrace, packet) < 0) {
		fprintf(stderr, "could not set format\n");
		return -1;
        }

	/* Update payload pointers and packet type to match the original
	 * format */
	if (trace_prepare_packet(packet->trace, packet, packet->buffer,
				 packet->type, 0)) {
		fprintf(stderr, "could not prepare packet\n");
		return -1;
	}

#if DEBUG
	fprintf(stderr, "done (%"PRIu16")\n", trace_get_source_port(packet));
#endif

	return framing_len + payload_len;
}

/* Reads a TraceMQ packet from the network.
 * It reads a new message from ZMQ, decodes the tracemq_header, and then
 * calls the appropriate handler function for the message type
 */
static int tracemq_read_packet_versatile(libtrace_t *libtrace,
					 libtrace_packet_t *packet) {
	size_t br = 0;
	zframe_t *frame = NULL;
	tracemq_header_t *hdr = NULL;

	libtrace_rt_types_t switch_type;

	/* not sure what this does */
	if (packet->buf_control == TRACE_CTRL_PACKET) {
		packet->buf_control = TRACE_CTRL_EXTERNAL;
		free(packet->buffer);
		packet->buffer = NULL;
	}

	/* free the last message if any */
	if(TRACEMQ_INFO->msg != NULL) {
		zmsg_destroy(&TRACEMQ_INFO->msg);
	}

	/* read the next message from ZMQ */
	if((TRACEMQ_INFO->msg = zmsg_recv (TRACEMQ_INFO->socket)) == NULL) {
		/* interrupted */
		return 0;
	}

	/* a message from the server will always begin with:
	 *  tracemq_header_t
	 *
	 * Then, based on the type, there may be much much more
	 */
	if((frame = zmsg_pop(TRACEMQ_INFO->msg)) == NULL) {
		return -1;
	}

	hdr = (tracemq_header_t*)zframe_data(frame);
	TRACEMQ_INFO->tracemq_hdr.type = hdr->type;
	TRACEMQ_INFO->tracemq_hdr.sequence = hdr->sequence;

	packet->type = hdr->type;

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
			break;
		case TRACE_RT_PAUSE_ACK:
			/* XXX: Add support for this */
			break;
		case TRACE_RT_OPTION:
			/* XXX: Add support for this */
			break;
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

#if 0
static int rt_get_fd(const libtrace_t *trace) {
        return ((struct rt_format_data_t *)trace->format_data)->input_fd;
}
#endif

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
	tracemq_prepare_packet,		/* prepare_packet */
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
