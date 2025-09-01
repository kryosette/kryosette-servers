#pragma once
#ifndef LLC_SAP_H
#define LLC_SAP_H

#include <stdint.h>

/* Standardized and Well-Known SAP Values */
#define LLC_NULL_SAP 0x00 /**< Addresses the LLC itself for management. */
#define LLC_SNAP_SAP 0xAA /**< Indicates a SNAP header follows the LLC header. */
#define LLC_STP_SAP 0x42 /**< Reserved for Spanning Tree Protocol (STP) BPDUs. */
#define LLC_IPX_SAP 0xE0 /**< Reserved for Novell IPX/SPX. */
#define LLC_GLOBAL_SAP 0xFF /**< Broadcast address for all SAPs on a node. */

/* Common SAP for IP, often used with SNAP. Rarely used raw. */
#define LLC_IP_SAP 0x06 /**< Historically assigned for IP, but SNAP is preferred. */

typedef enum {

}

#endif
