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

#ifndef _TRACEMQ_PROTOCOL_H
#define _TRACEMQ_PROTOCOL_H

#include "libtrace.h"
#include <time.h>

/** @file
 *
 * @brief Header file containing definitions specific to the TraceMQ protocol that
 * can be used to transport captured packets over a network connection.
 *
 */

/** Default port for the TraceMQ server */
#define TRACEMQ_DEFAULT_URI "tcp://localhost:7600"

/** Maximum size for the RT header */
/*#define TRACEMQ_MAX_HDR_SIZE 256*/
/** Maximum sequence number for the RT protocol */
/*#define TRACEMQ_MAX_SEQUENCE 2147483647*/

/* Procedure for adding new RT control types
 * -------------------------------------------
 *
 * Add type to the enum list
 * Add a struct below (even if it is empty - wrap it in an #if 0)
 * Update rt_get_capture_length
 * If type is intended to be sent TO clients, update rt_read_packet
 * 	Otherwise, update server implementations e.g. WDCAP
 *
 * Procedure for adding new RT data types
 * ----------------------------------------
 * 
 * If you are adding a new format:
 * 	RT_DATA_(new format) must be equal to RT_DATA_SIMPLE + 
 * 		TRACE_FORMAT_(new_format)
 * 	Add a new dummy trace type to the rt_format_t structure
 * 	Set the dummy trace to NULL in rt_init_input
 * 	Update rt_set_format
 *
 * If you are adding a new PCAP DLT type:
 * 	RT_DATA_PCAP_(new DLT) must be equal to RT_DATA_PCAP + (DLT value)
 * 	
 */

/** TraceMQ packet header (frame prepended to all TraceMQ messages) */
typedef struct tracemq_header {
	/** The type of TRACEMQ packet */
	libtrace_tracemq_types_t type;
	/** The sequence number of the packet */
	uint32_t sequence;
} tracemq_header_t;

/* TODO: Reorganise this struct once more hello info is added */

/** TraceMQ Hello packet sub-header */
typedef struct tracemq_hello {
	/** Indicates whether the sender is acting in a reliable fashion, 
	 *  i.e. expecting acknowledgements */
	/*uint8_t reliable;*/
} tracemq_hello_t;

/** TraceMQ Status sub-header */
typedef struct tracemq_status {
	/** TODO - add stats here, like dropped packets etc */
} tracemq_status_t;

/** Reasons that a TraceMQ connection may be denied */
enum tracemq_conn_denied_t {
	/** The server has reached the maximum number of client connections */
 	TRACEMQ_DENY_FULL	=1,
	/** Client failed to correctly authenticate */
 	TRACEMQ_DENY_AUTH	=3
};

/** TraceMQ Denied Connection sub-header */
typedef struct tracemq_deny_conn {
	/** The reason that the connection was denied */
	enum tracemq_conn_denied_t reason;
} tracemq_deny_conn_t;

#if 0
/** TraceMQ meta-data sub-header */
typedef struct tracemq_metadata {
	/** Length of the label string that follows the header */
	uint32_t label_len;
	/** Length of the value string that follows the header */
	uint32_t value_len;
} tracemq_metadata_t;
#endif

#endif
