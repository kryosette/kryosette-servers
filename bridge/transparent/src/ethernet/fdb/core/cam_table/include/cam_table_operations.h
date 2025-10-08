#pragma once
#ifndef CAM_TABLE_OPERATIONS_H
#define CAM_TABLE_OPERATIONS_H

#include "cam_table.h"
#include <pthread.h>

/* ===== CAM Table Operations ===== */

/**
 * @brief Add L2 MAC entry to CAM table
 */
int cam_table_add_l2_entry(cam_table_manager_t *manager,
                           const uint8_t *mac_bytes,
                           uint16_t vlan_id,
                           uint32_t port,
                           packet_action_t action);

/**
 * @brief Find L2 MAC entry in CAM table
 */
int cam_table_find_l2_entry(cam_table_manager_t *manager,
                            const uint8_t *mac_bytes,
                            uint16_t vlan_id,
                            cam_l2_entry_t *result);

/**
 * @brief Delete L2 MAC entry from CAM table
 */
int cam_table_delete_l2_entry(cam_table_manager_t *manager,
                              const uint8_t *mac_bytes,
                              uint16_t vlan_id);

/**
 * @brief Update L2 MAC entry in CAM table
 */
int cam_table_update_l2_entry(cam_table_manager_t *manager,
                              const uint8_t *mac_bytes,
                              uint16_t vlan_id,
                              uint32_t new_port,
                              packet_action_t new_action);

/**
 * @brief Get all L2 entries from CAM table
 */
int cam_table_get_all_l2_entries(cam_table_manager_t *manager,
                                 cam_l2_entry_t *entries,
                                 uint32_t *count);

/**
 * @brief Clear all L2 entries from CAM table
 */
int cam_table_clear_all_l2_entries(cam_table_manager_t *manager);

/**
 * @brief Set MAC address to pending state (for security)
 */
int cam_table_set_mac_pending(cam_table_manager_t *manager,
                              const uint8_t *mac_bytes,
                              uint16_t vlan_id,
                              const char *reason);

/**
 * @brief Remove MAC address from pending state
 */
int cam_table_clear_mac_pending(cam_table_manager_t *manager,
                                const uint8_t *mac_bytes,
                                uint16_t vlan_id);

/**
 * @brief Block MAC address (security action)
 */
int cam_table_block_mac(cam_table_manager_t *manager,
                        const uint8_t *mac_bytes,
                        uint16_t vlan_id,
                        const char *reason);

/**
 * @brief Unblock MAC address
 */
int cam_table_unblock_mac(cam_table_manager_t *manager,
                          const uint8_t *mac_bytes,
                          uint16_t vlan_id);

#endif /* CAM_TABLE_OPERATIONS_H */