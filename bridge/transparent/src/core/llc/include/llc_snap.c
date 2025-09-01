#pragma once 
#ifndef LLC_SNAP_H
#define LLC_SNAP_H

#include <stdint.h> // For uint8_t, uint16_t, uint32_t

/**
 * @file llc_snap.h
 * @brief Definitions for the SubNetwork Access Protocol (SNAP) header.
 * 
 * SNAP is used to transmit protocols (like IP) over IEEE 802 networks
 * using the same EtherType values as Ethernet II.
 */

/**
 * @brief Standard SNAP LLC header values.
 * These values in the LLC header indicate that a SNAP header follows.
 */
#define LLC_SNAP_DSAP 0xAA /**< Destination SAP for SNAP. */
#define LLC_SNAP_SSAP 0xAA /**< Source SAP for SNAP. */
#define LLC_SNAP_CTRL 0x03 /**< Control field for Unnumbered Information (UI). */

/**
 * @brief Well-known OUI (Organizational Unique Identifier) values.
 */
#define SNAP_OUI_IEEE_8021 0x0080C2 /**< OUI for IEEE 802.1 standards (e.g., STP). */
#define SNAP_OUI_ETHERNET 0x000000  /**< OUI for standard Ethernet EtherTypes. THIS IS THE ONE. */

/**
 * @brief The SNAP header structure.
 * 
 * This 5-byte header follows the LLC header when DSAP/SSAP are 0xAA.
 * It specifies the protocol of the payload.
 */
#pragma pack(push, 1) // Ensure no padding between fields
typedef struct {
    uint8_t oui[3];   /**< Organizational Unique Identifier. */
    uint16_t ethertype; /**< Protocol type (EtherType). */
} llc_snap_header_t;
#pragma pack(pop)

/**
 * @brief Function to check if an LLC header indicates a SNAP frame.
 * 
 * @param dsap The DSAP value from the LLC header.
 * @param ssap The SSAP value from the LLC header.
 * @param control The Control value from the LLC header.
 * @return int 1 if it's a SNAP frame, 0 otherwise.
 */
static inline int llc_is_snap_frame(uint8_t dsap, uint8_t ssap, uint8_t control) {
    return (dsap == LLC_SNAP_DSAP && ssap == LLC_SNAP_SSAP && control == LLC_SNAP_CTRL);
}

/**
 * @brief Function to extract the EtherType from a SNAP header.
 * 
 * @param snap_hdr A pointer to the llc_snap_header_t.
 * @return uint16_t The EtherType in host byte order.
 */
static inline uint16_t llc_snap_get_ethertype(const llc_snap_header_t *snap_hdr) {
    // OUI is stored in network byte order (big-endian), so we need to convert it.
    return ntohs(snap_hdr->ethertype);
}

/**
 * @brief Function to write a SNAP header for a given EtherType.
 * 
 * @param snap_hdr A pointer to the structure to fill.
 * @param ethertype The EtherType to use (e.g., 0x0800 for IP), in host byte order.
 */
static inline void llc_snap_set_ethertype(llc_snap_header_t *snap_hdr, uint16_t ethertype) {
    // Set the OUI to the standard for Ethernet EtherTypes
    snap_hdr->oui[0] = 0x00;
    snap_hdr->oui[1] = 0x00;
    snap_hdr->oui[2] = 0x00;
    // Convert the EtherType to network byte order and store it
    snap_hdr->ethertype = htons(ethertype);
}

#endif /* LLC_SNAP_H */
