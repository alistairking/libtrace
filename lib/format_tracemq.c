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
	/* Buffer to store received packets into */
	char *pkt_buffer;
	/* Pointer to the next packet to be read from the buffer */
	char *buf_current;
	/* Amount of buffer space used */
	size_t buf_filled;

	/* Header frame for the packet currently being received */
	tracemq_header_t tracemq_hdr;

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
	tx_hdr.type = TRACE_TRACEMQ_START;
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
		case TRACE_TRACEMQ_DENY_CONN:
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

		case TRACE_TRACEMQ_HELLO:
			/* no hello header atm */

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

	TRACEMQ_INFO->pkt_buffer = NULL;
	TRACEMQ_INFO->buf_current = NULL;
	TRACEMQ_INFO->buf_filled = 0;

	TRACEMQ_INFO->uri = NULL;
	TRACEMQ_INFO->context = NULL;
	TRACEMQ_INFO->socket = NULL;
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
	TRACEMQ_INFO->tracemq_hdr.type = TRACE_TRACEMQ_LAST;

	return 0;
}

static int tracemq_pause_input(libtrace_t *libtrace) {
	zframe_t *frame;
        tracemq_header_t close_msg;

	close_msg.type = TRACE_TRACEMQ_CLOSE;

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


/* Sets the trace format for the packet to match the format it was originally
 * captured in, rather than the RT format */
static int rt_set_format(libtrace_t *libtrace, libtrace_packet_t *packet) 
{

	/* We need to assign the packet to a "dead" trace */

	/* Try to minimize the number of corrupt packets that slip through
	 * while making it easy to identify new pcap DLTs */
	if (packet->type > TRACE_RT_DATA_DLT && 
			packet->type < TRACE_RT_DATA_DLT_END) {
		if (!RT_INFO->dummy_pcap) {
			RT_INFO->dummy_pcap = trace_create_dead("pcap:-");
		}
		packet->trace = RT_INFO->dummy_pcap;
		return 0;	
	}

	if (packet->type > TRACE_RT_DATA_BPF &&
			packet->type < TRACE_RT_DATA_BPF_END) {

		if (!RT_INFO->dummy_bpf) {
			RT_INFO->dummy_bpf = trace_create_dead("bpf:-");
			/* This may fail on a non-BSD machine */
			if (trace_is_err(RT_INFO->dummy_bpf)) {
				trace_perror(RT_INFO->dummy_bpf, "Creating dead bpf trace");
				return -1;
			}
		}
		packet->trace = RT_INFO->dummy_bpf;
		return 0;
	}

	switch (packet->type) {
		case TRACE_RT_DUCK_2_4:
		case TRACE_RT_DUCK_2_5:
			if (!RT_INFO->dummy_duck) {
				RT_INFO->dummy_duck = trace_create_dead("duck:dummy");
			}
			packet->trace = RT_INFO->dummy_duck;
			break;
		case TRACE_RT_DATA_ERF:
			if (!RT_INFO->dummy_erf) {
				RT_INFO->dummy_erf = trace_create_dead("erf:-");
			}
			packet->trace = RT_INFO->dummy_erf;
			break;
		case TRACE_RT_DATA_LINUX_NATIVE:
			if (!RT_INFO->dummy_linux) {
				RT_INFO->dummy_linux = trace_create_dead("int:");
				/* This may fail on a non-Linux machine */
				if (trace_is_err(RT_INFO->dummy_linux)) {
					trace_perror(RT_INFO->dummy_linux, "Creating dead int trace");
					return -1;
				}
			}
			packet->trace = RT_INFO->dummy_linux;
			break;
		case TRACE_RT_DATA_LINUX_RING:
			if (!RT_INFO->dummy_ring) {
				RT_INFO->dummy_ring = trace_create_dead("ring:");
				/* This may fail on a non-Linux machine */
				if (trace_is_err(RT_INFO->dummy_ring)) {
					trace_perror(RT_INFO->dummy_ring, "Creating dead int trace");
					return -1;
				}
			}
			packet->trace = RT_INFO->dummy_ring;
			break;
		case TRACE_RT_STATUS:
		case TRACE_RT_METADATA:
			/* Just use the RT trace! */
			packet->trace = libtrace;
			break;
		case TRACE_RT_DATA_LEGACY_ETH:
		case TRACE_RT_DATA_LEGACY_ATM:
		case TRACE_RT_DATA_LEGACY_POS:
			printf("Sending legacy over RT is currently not supported\n");
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Legacy packet cannot be sent over rt");
			return -1;
		default:
			printf("Unrecognised format: %u\n", packet->type);
			trace_set_err(libtrace, TRACE_ERR_BAD_PACKET, "Unrecognised packet format");
			return -1;
	}
	return 0; /* success */
}		

/* Sends an RT ACK to the server to acknowledge receipt of packets */
static int rt_send_ack(libtrace_t *libtrace, 
		uint32_t seqno)  {
	
	static char *ack_buffer = 0;
	char *buf_ptr;
	int numbytes = 0;
	size_t to_write = 0;
	rt_header_t *hdr;
	rt_ack_t *ack_hdr;
	
	if (!ack_buffer) {
		ack_buffer = (char*)malloc(sizeof(rt_header_t) 
							+ sizeof(rt_ack_t));
	}
	
	hdr = (rt_header_t *) ack_buffer;
	ack_hdr = (rt_ack_t *) (ack_buffer + sizeof(rt_header_t));
	
	hdr->type = TRACE_RT_ACK;
	hdr->length = sizeof(rt_ack_t);

	ack_hdr->sequence = seqno;
	
	to_write = hdr->length + sizeof(rt_header_t);
	buf_ptr = ack_buffer;

	/* Keep trying until we write the entire ACK */
	while (to_write > 0) {
		numbytes = send(RT_INFO->input_fd, buf_ptr, to_write, 0); 
		if (numbytes == -1) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
			else {
				printf("Error sending ack\n");
				perror("send");
				trace_set_err(libtrace, TRACE_ERR_RT_FAILURE, 
						"Error sending ack");
				return -1;
			}
		}
		to_write = to_write - numbytes;
		buf_ptr = buf_ptr + to_write;
		
	}

	return 1;
}

/* Shouldn't need to call this too often */
static int rt_prepare_packet(libtrace_t *libtrace, libtrace_packet_t *packet,
		void *buffer, libtrace_rt_types_t rt_type, uint32_t flags) {

	if (packet->buffer != buffer &&
                        packet->buf_control == TRACE_CTRL_PACKET) {
                free(packet->buffer);
        }

        if ((flags & TRACE_PREP_OWN_BUFFER) == TRACE_PREP_OWN_BUFFER) {
                packet->buf_control = TRACE_CTRL_PACKET;
        } else
                packet->buf_control = TRACE_CTRL_EXTERNAL;


        packet->buffer = buffer;
        packet->header = NULL;
        packet->type = rt_type;
	packet->payload = buffer;

	if (libtrace->format_data == NULL) {
		rt_init_format_data(libtrace);
	}

	return 0;
}	

/* Reads the body of an RT packet from the network */
static int rt_read_data_packet(libtrace_t *libtrace,
		libtrace_packet_t *packet, int blocking) {
	uint32_t prep_flags = 0;

	prep_flags |= TRACE_PREP_DO_NOT_OWN_BUFFER;

	/* The stored RT header will tell us how much data we need to read */
	if (rt_read(libtrace, &packet->buffer, (size_t)RT_INFO->rt_hdr.length, 
				blocking) != RT_INFO->rt_hdr.length) {
		return -1;
	}

	/* Send an ACK if required */
        if (RT_INFO->reliable > 0 && packet->type >= TRACE_RT_DATA_SIMPLE) {
		if (rt_send_ack(libtrace, RT_INFO->rt_hdr.sequence) == -1)
                               	return -1;
	}
	
	/* Convert to the original capture format */
	if (rt_set_format(libtrace, packet) < 0) {
		return -1;
        }
               	
	/* Update payload pointers and packet type to match the original
	 * format */
	if (trace_prepare_packet(packet->trace, packet, packet->buffer,
				packet->type, prep_flags)) {
		return -1;
	}

	return 0;
}

/* Reads an RT packet from the network. Will block if the "blocking" flag is
 * set to 1, otherwise will return if insufficient data is available */
static int rt_read_packet_versatile(libtrace_t *libtrace,
		libtrace_packet_t *packet,int blocking) {
	rt_header_t *pkt_hdr = NULL;
	void *void_hdr;
	libtrace_rt_types_t switch_type;
	
	if (packet->buf_control == TRACE_CTRL_PACKET) {
		packet->buf_control = TRACE_CTRL_EXTERNAL;
		free(packet->buffer);
		packet->buffer = NULL;
	}

	/* RT_LAST indicates that we need to read the RT header for the next
	 * packet. This is a touch hax, I admit */
	if (RT_INFO->rt_hdr.type == TRACE_RT_LAST) {
		void_hdr = (void *)pkt_hdr;
		/* FIXME: Better error handling required */
		if (rt_read(libtrace, &void_hdr, 
				sizeof(rt_header_t),blocking) !=
				sizeof(rt_header_t)) {
			return -1;
		}
		pkt_hdr = (rt_header_t *)void_hdr;
		
		/* Need to store these in case the next rt_read overwrites 
		 * the buffer they came from! */
		RT_INFO->rt_hdr.type = pkt_hdr->type;
		RT_INFO->rt_hdr.length = pkt_hdr->length;
		RT_INFO->rt_hdr.sequence = pkt_hdr->sequence;
	}
	packet->type = RT_INFO->rt_hdr.type;
	
	/* All data-bearing packets (as opposed to RT internal messages) 
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
			if (rt_read_data_packet(libtrace, packet, blocking))
				return -1;
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
	RT_INFO->rt_hdr.type = TRACE_RT_LAST;
	return RT_INFO->rt_hdr.length + sizeof(rt_header_t);
}

/* Reads the next available packet in a blocking fashion */
static int rt_read_packet(libtrace_t *libtrace,
		libtrace_packet_t *packet) {
	return rt_read_packet_versatile(libtrace,packet,1);
}


/* This should only get called for RT messages - RT-encapsulated data records
 * should be converted to the appropriate capture format */
static int rt_get_capture_length(const libtrace_packet_t *packet) {
	rt_metadata_t *rt_md_hdr;
	switch (packet->type) {
		case TRACE_RT_STATUS:
			return sizeof(rt_status_t);
		case TRACE_RT_HELLO:
			return sizeof(rt_hello_t);
		case TRACE_RT_START:
			return 0;
		case TRACE_RT_ACK:
			return sizeof(rt_ack_t);
		case TRACE_RT_END_DATA:
			return 0;
		case TRACE_RT_CLOSE:
			return 0;
		case TRACE_RT_DENY_CONN:
			return sizeof(rt_deny_conn_t);
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
			/* This is a little trickier to work out */
			rt_md_hdr = (rt_metadata_t *)packet->buffer;
			return rt_md_hdr->label_len + rt_md_hdr->value_len + 
				sizeof(rt_metadata_t);
		default:
			printf("Unknown type: %d\n", packet->type);
			
	}
	return 0;
}

/* RT messages do not have a wire length because they were not captured from
 * the wire - they were generated by the capture process */
static int rt_get_wire_length(UNUSED const libtrace_packet_t *packet) {
	return 0;
}

/* Although RT messages do contain "framing", this framing is considered to be
 * stripped as soon as the packet is read by the RT client */			
static int rt_get_framing_length(UNUSED const libtrace_packet_t *packet) {
	return 0;
}


static libtrace_linktype_t rt_get_link_type(UNUSED const libtrace_packet_t *packet)
{
	/* RT messages don't have a link type */
	return TRACE_TYPE_NONDATA;
}

static int rt_get_fd(const libtrace_t *trace) {
        return ((struct rt_format_data_t *)trace->format_data)->input_fd;
}

static libtrace_eventobj_t trace_event_rt(libtrace_t *trace,
					libtrace_packet_t *packet) 
{
	libtrace_eventobj_t event = {0,0,0.0,0};
	libtrace_err_t read_err;

	assert(trace);
	assert(packet);
	
	if (trace->format->get_fd) {
		event.fd = trace->format->get_fd(trace);
	} else {
		event.fd = 0;
	}

	do {

		event.size = rt_read_packet_versatile(trace, packet, 0);
		if (event.size == -1) {
			read_err = trace_get_err(trace);
			if (read_err.err_num == EAGAIN) {
				/* No data available - do an IOWAIT */
				event.type = TRACE_EVENT_IOWAIT;
			}
			else {
				trace_perror(trace, "Error doing a non-blocking read from rt");
				event.type = TRACE_EVENT_PACKET;
				break;
			}
		} else if (event.size == 0) {
			/* RT gives us a specific indicator that there will be 
			 * no more packets. */
			if (packet->type == TRACE_RT_END_DATA)
				event.type = TRACE_EVENT_TERMINATE;
			else
				/* Since several RT messages can have zero-byte
				 * length (once the framing is removed), an 
				 * event size of zero can still indicate a 
				 * PACKET event */
				event.type = TRACE_EVENT_PACKET;

		}	
		else {
			event.type = TRACE_EVENT_PACKET;
		}

		if (trace->filter && event.type == TRACE_EVENT_PACKET) {
			if (!trace_apply_filter(trace->filter, packet)) {
				trace_clear_cache(packet);
				continue;
			}
		}

		break;	
	} while (1);

	return event;
}

static void rt_help(void) {
        printf("rt format module\n");
        printf("Supported input URIs:\n");
        printf("\trt:hostname:port\n");
        printf("\trt:hostname (connects on default port)\n");
        printf("\n");
        printf("\te.g.: rt:localhost\n");
        printf("\te.g.: rt:localhost:32500\n");
        printf("\n");

}

#endif

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
        tracemq_get_fd,                	/* get_fd */
        trace_event_tracemq,            /* trace_event */
        tracemq_help,			/* help */
	NULL				/* next pointer */
};

void tracemq_constructor(void) {
	register_format(&tracemq);
}
