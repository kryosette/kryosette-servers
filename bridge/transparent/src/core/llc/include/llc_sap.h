#ifndef LLC_SAP_H
#define LLC_SAP_H

#include <stdint.h> // For uint8_t

/**
 * @file llc_sap.h
 * @brief LLC Service Access Point (SAP) definitions and management structures.
 * 
 * A SAP is a port number at the Data Link Layer, used to multiplex different
 * protocols over a single MAC address.
 */

/* Standardized and Well-Known SAP Values */
#define LLC_NULL_SAP 0x00 /**< Addresses the LLC itself for management. */
#define LLC_SNAP_SAP 0xAA /**< Indicates a SNAP header follows the LLC header. */
#define LLC_STP_SAP 0x42 /**< Reserved for Spanning Tree Protocol (STP) BPDUs. */
#define LLC_IPX_SAP 0xE0 /**< Reserved for Novell IPX/SPX. */
#define LLC_GLOBAL_SAP 0xFF /**< Broadcast address for all SAPs on a node. */

/* Common SAP for IP, often used with SNAP. Rarely used raw. */
#define LLC_IP_SAP 0x06 /**< Historically assigned for IP, but SNAP is preferred. */

/**
 * @brief LLC SAP Type.
 * 
 * Distinguishes between individual and group SAP addresses.
 * The Least Significant Bit (LSB) of the DSAP field indicates the type.
 */
typedef enum {
    LLC_SAP_TYPE_INDIVIDUAL = 0, /**< Unicast address for a specific service. */
    LLC_SAP_TYPE_GROUP = 1 /**< Multicast address for a group of services. */
} llc_sap_type_t;

/**
 * @brief LLC SAP State.
 * 
 * Tracks the operational state of a registered SAP.
 */
typedef enum {
    LLC_SAP_STATE_INACTIVE, /**< SAP is registered but not active. */
    LLC_SAP_STATE_ACTIVE /**< SAP is active and can receive frames. */
} llc_sap_state_t;

#endif


