/**
 * @file llc_service_primitives.h
 * @brief LLC Service Primitives Interface (Based on IEEE Std 802.2-1985)
 * @description This header defines the abstract service interface between 
 *              the Network Layer and the Logical Link Control (LLC) Sublayer,
 *              and between the LLC and MAC sublayers.
 * @author Network Wizard 🧙‍♂️
 * @date 1985 (Standard), 2025 (Implementation)
 * @license IEEE
 * @note This is an abstract interface definition. Implementation details are OS-specific.
 */
#pragma once
#ifndef LLC_SERVICE_PRIMITIVES_H
#define LLC_SERVICE_PRIMITIVES_H

#include <stdint.h> 
#include <stddef.h> 

/*===========================================================================*\
 * Common Type Definitions
\*===========================================================================*/

/** LSAP Address (Address of the access point to the data link services) */
typedef uint16_t lsap_address_t;

/** MAC Address (Hardware/MAC address) */
typedef struct {
    uint8_t octet[6]; /**< 48-bit MAC address in network byte order */
} mac_address_t;

/** Reason Code (Reason code - for indications) */
typedef uint8_t llc_reason_t;
#define LLC_REASON_REMOTE_REQUEST   0x01 /**< Remote entity requested */
#define LLC_REASON_INTERNAL_ERROR   0x02 /**< Internal LLC error */
#define LLC_REASON_RESET_REQUESTED  0x03 /**< Reset requested by remote */

/** Status Code (Status code - for confirmations) */
typedef uint8_t llc_status_t;
#define LLC_STATUS_SUCCESS          0x00 /**< Operation successful */
#define LLC_STATUS_FAILURE          0x01 /**< Operation failed */
#define LLC_STATUS_TIMEOUT          0x02 /**< Operation timed out */

/** Service Class (Service Class/priority) */
typedef uint8_t service_class_t;
#define SERVICE_CLASS_BEST_EFFORT   0x00 /**< Default, no priority */
#define SERVICE_CLASS_PRIORITY      0x01 /**< Priority service */
#define SERVICE_CLASS_EXPRESS       0x02 /**< Express service */

/** MSDU Type (MAC Service Data Block type) */
typedef struct {
    size_t length;      /**< Length of the MSDU in bytes */
    uint8_t *data;      /**< Pointer to the MSDU data */
} msdu_t;

/** LSDU Type (LLC service data block type) */
typedef struct {
    size_t length;      /**< Length of the LSDU in bytes */
    uint8_t *data;      /**< Pointer to the LSDU data */
} lsdu_t;

/*===========================================================================*\
 * Network Layer <-> LLC Interface Primitives
* (Network Layer interface Primitives <-> LLC)
\*===========================================================================*/

/**
 * @brief L_DISCONNECT.indication primitive
 * @description Notification of connection disconnection (from LLC to Network layer)
* @usage Is transmitted from bottom to top to inform about connection disconnection.
 */
typedef struct {
    lsap_address_t local_address; /**< Local LSAP */
    lsap_address_t remote_address; /**< Remote LSAP */
    llc_reason_t reason; /**< Reason for disconnection */
} l_disconnect_indication_t;

/**
 * @brief L_DISCONNECT.confirm primitive
 * @description Confirms disconnection of the connection (from LLC to Network Layer)
* @usage Confirms that the disconnection request has been processed.
 */
typedef struct {
    lsap_address_t local_address; /**< Local LSAP */
    lsap_address_t remote_address; /**< Remote LSAP */
    llc_status_t status; /**< Disconnection operation status */
} l_disconnect_confirm_t;

/**
 * @brief L_RESET.request primitive
 * @description Connection reset request (from Network layer to LLC) * @usage Connection reset request.

 */
typedef struct {
    lsap_address_t local_address; /**< Local LSAP */
    lsap_address_t remote_address; /**< Remote LSAP */
} l_reset_request_t;

/**
 * @brief L_RESET.indication primitive
 * @description Notification of connection reset (from LLC to Network layer)
* @usage Informs that the connection has been reset (initiator is a remote party or an internal error).
 */
typedef struct {
    lsap_address_t local_address; /**< Local LSAP */
    lsap_address_t remote_address; /**< Remote LSAP */
    llc_reason_t reason; /**< Reason for reset */
} l_reset_indication_t;

/**
 * @brief L_RESET.confirm primitive
 * @description Confirms connection reset (from LLC to Network layer)
* @usage Confirms completion of connection reset operation.
 */
typedef struct {
    lsap_address_t local_address; /**< Local LSAP */
    lsap_address_t remote_address; /**< Remote LSAP */
    llc_status_t status; /**< Reset operation status */
} l_reset_confirm_t;

/**
 * @brief L_CONNECTION_FLOWCONTROL.request primitive
 * @description Flow control request (from the Network layer to the LLC)
* @usage Is used to control the flow of data coming FROM the LLC to the Network layer.
 */
typedef struct {
    lsap_address_t local_address; /**< Local LSAP */
     remote_address; /**< Remote LSAP */
    uint32_t amount; /**< Amount of data that can be transferred (in bytes or "credits") */
} l_connection_flowcontrol_request_t;

/**
 * @brief L_CONNECTION_FLOWCONTROL.indication primitive
 * @description Specifies flow control (from LLC to Network Layer)
* @usage is used to control the flow of data coming FROM Network layer to LLC.
 */
typedef struct {
    lsap_address_t local_address; /**< Local LSAP */
    lsap_address_t remote_address; /**< Remote LSAP */
    uint32_t amount; /**< Amount of data that can be transferred losslessly */
} l_connection_flowcontrol_indication_t;

/*===========================================================================*\
 * LLC <-> MAC Interface Primitives (MA_UNITDATA)
 * (LLC <-> MAC interface primitives)
 * 
 * Important! In the 802.2-1985 standard, the primitives are called MA_DATA.*,
* but in later versions and implementations, the name MA_UNITDATA is often used.*
* to avoid confusion with the Data service.
\*===========================================================================*/

/** Transmission Status */
typedef uint8_t mac_transmission_status_t;
#define MAC_STATUS_SUCCESS 0x00 /**< Frame transmitted successfully */
#define MAC_STATUS_TOO_MANY_COLLISIONS 0x01 /**< Too many collisions (CSMA/CD) */
#define MAC_STATUS_CHANNEL_BUSY 0x02 /**< The channel is busy (Token Ring) */
#define MAC_STATUS_NO_ACK 0x03 /**< No confirmation (for optional ACKs) */

/** Reception Status */
typedef uint8_t mac_reception_status_t;
#define MAC_RX_SUCCESS 0x00 /**< Frame received without errors */
#define MAC_RX_CRC_ERROR 0x01 /**< CRC error */
#define MAC_RX_ALIGNMENT_ERROR 0x02 /**< Alignment error */
#define MAC_RX_FRAME_TOO_SHORT 0x03 /**< Frame is too short */
#define MAC_RX_FRAME_TOO_LONG 0x04 /**< Frame is too long */

/**
 * @brief MA_UNITDATA.request primitive
 * @description Request to transfer an MSDU data block (from LLC to MAC)
* @usage is the main primitive for sending a frame to the network.
 */
typedef struct {
    mac_address_t destination_address; /**< Individual or group destination MAC address */
    msdu_t m_sdu; /**< Transmitted MAC Service Data Block (MSDU) */
    service_class_t requested_service_class;/**< Requested service class (priority) */
} ma_unitdata_request_t;

/**
 * @brief MA_UNITDATA.indication primitive
 * @description Notification of the receipt of an MSDU data block (from MAC to LLC)
* @usage is the main primitive for receiving a frame from the network.
 */
typedef struct {
    mac_address_t destination_address; /**< Destination address from the received frame */
    mac_address_t source_address; /**< Source address from the received frame */
    msdu_t m_sdu; /**< Received MAC Service Data block (MSDU) */
    mac_reception_status_t reception_status;/**< Frame reception status (success/error) */
    service_class_t service_class; /**< Service class of the received frame */
} ma_unitdata_indication_t;

/**
 * @brief MA_UNITDATA.confirm primitive
 * @description Confirmation of transfer (from MAC to LLC)
* @usage Confirms the result of the previous request MA_UNITDATA.request.
 * Has a local meaning.
 */
typedef struct {
    mac_transmission_status_t transmission_status; /**< Transmission status (success/reason for failure) */
    service_class_t provided_service_class; /**< Actually provided service class */
} ma_unitdata_confirm_t;

/*===========================================================================*\
 * Service Access Point (SAP) Management (optional)
* (Service Access Point management is optional)
\*===========================================================================*/

/** LLC SAP Structure (LLC Service Access Point Structure) */
typedef struct {
    lsap_address_t address; /**< SAP address */
    uint8_t in_use; /**< Busy flag (1 = busy, 0 = free) */
// ... other status management fields
} llc_sap_entry_t;

/** Function prototype for primitive handler */
typedef void (*llc_primitive_handler_t)(void *primitive);

#endif /* LLC_SERVICE_PRIMITIVES_H */