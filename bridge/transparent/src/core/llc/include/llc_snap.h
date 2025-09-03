#pragma once
#ifndef LLC_SNAP_H
#define LLC_SNAP_H

#include <stdint.h> // For uint8_t, uint16_t
#include <arpa/inet.h> // For ntohs, htons (for Linux)

/**
 * @file llc_snap.h
 * @brief Definitions for the SubNetwork Access Protocol (SNAP) header.
 * 
 * SNAP is used to transmit protocols (like IP) over IEEE 802 networks
 * using the same EtherType values as Ethernet II.
 * Defined in RFC 1042.
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
#define SNAP_OUI_ETHERNET 0x000000  /**< OUI for standard Ethernet EtherTypes. THIS IS THE ONE. */
#define SNAP_OUI_IEEE_8021 0x0080C2 /**< OUI for IEEE 802.1 standards. */

/**
 * @brief The full SNAP Protocol Identifier (PID).
 * 
 * This is the 5-byte value that uniquely identifies the protocol.
 * In practice, it's split into a 3-byte OUI and a 2-byte EtherType.
 * This union allows you to access it as a whole or by its parts.
 */
#pragma pack(push, 1) // Ensure no padding between fields
typedef union {
    struct {
        uint8_t oui[3];     /**< Organizational Unique Identifier. */
        uint16_t ethertype; /**< Protocol type (EtherType). */
    } parts;
    uint8_t pid[5]; /**< Full 5-byte Protocol Identifier. */
} llc_snap_pid_t;

/**
 * @brief The SNAP header structure.
 * 
 * This 5-byte header follows the LLC header when DSAP/SSAP are 0xAA.
 * It specifies the protocol of the payload.
 */
typedef llc_snap_pid_t llc_snap_header_t; // The header IS the PID.
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
    // EtherType is stored in network byte order (big-endian), convert it to host order.
    return ntohs(snap_hdr->parts.ethertype);
}

/**
 * @brief Function to write a SNAP header for a given EtherType using the standard Ethernet OUI.
 * 
 * @param snap_hdr A pointer to the structure to fill.
 * @param ethertype The EtherType to use (e.g., 0x0800 for IP), in host byte order.
 */
static inline void llc_snap_set_ethertype(llc_snap_header_t *snap_hdr, uint16_t ethertype) {
    // Set the OUI to the standard for Ethernet EtherTypes (00-00-00)
    snap_hdr->parts.oui[0] = 0x00;
    snap_hdr->parts.oui[1] = 0x00;
    snap_hdr->parts.oui[2] = 0x00;
    // Convert the EtherType to network byte order and store it
    snap_hdr->parts.ethertype = htons(ethertype);
}

/**
 * @brief Checks if the SNAP header uses the standard Ethernet OUI.
 * 
 * @param snap_hdr A pointer to the llc_snap_header_t.
 * @return int 1 if OUI is 00-00-00, 0 otherwise.
 */
static inline int llc_snap_is_ethertype(const llc_snap_header_t *snap_hdr) {
    return (snap_hdr->parts.oui[0] == 0x00 &&
            snap_hdr->parts.oui[1] == 0x00 &&
            snap_hdr->parts.oui[2] == 0x00);
}

#endif /* LLC_SNAP_H */
