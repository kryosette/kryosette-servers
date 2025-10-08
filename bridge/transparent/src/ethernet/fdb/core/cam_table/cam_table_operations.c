#include "cam_table_operations.h"
#include <string.h>

/* ===== Internal Helper Functions ===== */

static bool mac_bytes_equal(const uint8_t *mac1, const uint8_t *mac2)
{
    return memcmp(mac1, mac2, MAC_ADDRESS_LENGTH) == 0;
}

static void bytes_to_mac_address(const uint8_t *bytes, mac_address_t *mac)
{
    memcpy(mac->bytes, bytes, MAC_ADDRESS_LENGTH);
}

static int find_entry_index(cam_table_manager_t *manager,
                            const uint8_t *mac_bytes,
                            uint16_t vlan_id)
{
    if (!manager || !manager->cam_table || !mac_bytes)
        return -1;

    cam_table_t *table = manager->cam_table;

    pthread_mutex_lock(&table->lock);

    for (uint32_t i = 0; i < table->count; i++)
    {
        cam_table_entry_t *entry = &table->entries[i];

        if (entry->header.type == ENTRY_TYPE_L2_MAC &&
            entry->header.status != ENTRY_STATUS_INVALID &&
            entry->header.vlan_id == vlan_id &&
            mac_bytes_equal(mac_bytes, entry->data.l2_entry.mac_address.bytes))
        {
            pthread_mutex_unlock(&table->lock);
            return i;
        }
    }

    pthread_mutex_unlock(&table->lock);
    return -1;
}

/* ===== Public CAM Table Operations ===== */

int cam_table_add_l2_entry(cam_table_manager_t *manager,
                           const uint8_t *mac_bytes,
                           uint16_t vlan_id,
                           uint32_t port,
                           packet_action_t action)
{
    if (!manager || !manager->cam_table || !mac_bytes)
    {
        return -1;
    }

    cam_table_t *table = manager->cam_table;

    // Check if entry already exists
    int existing_index = find_entry_index(manager, mac_bytes, vlan_id);
    if (existing_index >= 0)
    {
        // Update existing entry
        return cam_table_update_l2_entry(manager, mac_bytes, vlan_id, port, action);
    }

    pthread_mutex_lock(&table->lock);

    // Check capacity
    if (table->count >= table->capacity)
    {
        pthread_mutex_unlock(&table->lock);

        if (manager->log_callback != NULL)
        {
            char log_msg[256];
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                     mac_bytes[0], mac_bytes[1], mac_bytes[2],
                     mac_bytes[3], mac_bytes[4], mac_bytes[5]);
            snprintf(log_msg, sizeof(log_msg),
                     "CAM table full: cannot add MAC %s VLAN %d", mac_str, vlan_id);
            manager->log_callback(log_msg, 2); // ERROR level
        }
        return -2; // Table full
    }

    // Create new entry
    cam_table_entry_t *new_entry = &table->entries[table->count];

    // Initialize header
    new_entry->header.index = table->count;
    new_entry->header.type = ENTRY_TYPE_L2_MAC;
    new_entry->header.status = ENTRY_STATUS_ACTIVE;
    new_entry->header.created_timestamp = time(NULL);
    new_entry->header.last_updated = time(NULL);
    new_entry->header.last_accessed = time(NULL);
    new_entry->header.vlan_id = vlan_id;
    new_entry->header.logical_port = port & 0xFF;
    new_entry->header.priority = 1;
    new_entry->header.reference_count = 1;
    new_entry->header.hit_flag = true;

    // Initialize L2 data
    bytes_to_mac_address(mac_bytes, &new_entry->data.l2_entry.mac_address);
    new_entry->data.l2_entry.header = new_entry->header;
    new_entry->data.l2_entry.flags = 0;

    // Update indexes
    if (table->l2_count < table->capacity)
    {
        table->l2_index[table->l2_count] = table->count;
        table->l2_count++;
    }

    table->count++;

    // Update statistics
    manager->stats.entries_learned++;
    manager->utilization.used_entries++;
    manager->utilization.free_entries--;
    manager->utilization.allocated_l2++;

    pthread_mutex_unlock(&table->lock);

    // Log the addition
    if (manager->log_callback != NULL)
    {
        char log_msg[256];
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 mac_bytes[0], mac_bytes[1], mac_bytes[2],
                 mac_bytes[3], mac_bytes[4], mac_bytes[5]);
        snprintf(log_msg, sizeof(log_msg),
                 "Added L2 entry: MAC %s VLAN %d Port %u Action %d",
                 mac_str, vlan_id, port, action);
        manager->log_callback(log_msg, 0); // INFO level
    }

    // Call learn callback if set
    if (manager->learn_callback != NULL)
    {
        manager->learn_callback(&new_entry->header, manager);
    }

    return 0;
}

int cam_table_find_l2_entry(cam_table_manager_t *manager,
                            const uint8_t *mac_bytes,
                            uint16_t vlan_id,
                            cam_l2_entry_t *result)
{
    if (!manager || !manager->cam_table || !mac_bytes || !result)
    {
        return -1;
    }

    int index = find_entry_index(manager, mac_bytes, vlan_id);
    if (index < 0)
    {
        return -1; // Not found
    }

    cam_table_t *table = manager->cam_table;

    pthread_mutex_lock(&table->lock);

    // Copy the entry data
    memcpy(result, &table->entries[index].data.l2_entry, sizeof(cam_l2_entry_t));

    // Update access time and hit flag
    table->entries[index].header.last_accessed = time(NULL);
    table->entries[index].header.hit_flag = true;

    // Update statistics
    manager->stats.lookup_requests++;
    manager->stats.lookup_hits++;

    pthread_mutex_unlock(&table->lock);

    return 0;
}

int cam_table_delete_l2_entry(cam_table_manager_t *manager,
                              const uint8_t *mac_bytes,
                              uint16_t vlan_id)
{
    if (!manager || !manager->cam_table || !mac_bytes)
    {
        return -1;
    }

    cam_table_t *table = manager->cam_table;
    int index = find_entry_index(manager, mac_bytes, vlan_id);

    if (index < 0)
    {
        return -1; // Not found
    }

    pthread_mutex_lock(&table->lock);

    // Call delete callback if set
    if (manager->delete_callback != NULL)
    {
        manager->delete_callback(&table->entries[index].header, manager);
    }

    // Mark entry as invalid
    table->entries[index].header.status = ENTRY_STATUS_INVALID;
    table->entries[index].header.type = ENTRY_TYPE_INVALID;

    // Update statistics
    manager->stats.entries_deleted++;
    manager->utilization.used_entries--;
    manager->utilization.free_entries++;
    manager->utilization.allocated_l2--;

    pthread_mutex_unlock(&table->lock);

    // Log the deletion
    if (manager->log_callback != NULL)
    {
        char log_msg[256];
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 mac_bytes[0], mac_bytes[1], mac_bytes[2],
                 mac_bytes[3], mac_bytes[4], mac_bytes[5]);
        snprintf(log_msg, sizeof(log_msg),
                 "Deleted L2 entry: MAC %s VLAN %d", mac_str, vlan_id);
        manager->log_callback(log_msg, 0); // INFO level
    }

    return 0;
}

int cam_table_update_l2_entry(cam_table_manager_t *manager,
                              const uint8_t *mac_bytes,
                              uint16_t vlan_id,
                              uint32_t new_port,
                              packet_action_t new_action)
{
    if (!manager || !manager->cam_table || !mac_bytes)
    {
        return -1;
    }

    cam_table_t *table = manager->cam_table;
    int index = find_entry_index(manager, mac_bytes, vlan_id);

    if (index < 0)
    {
        return -1; // Not found
    }

    pthread_mutex_lock(&table->lock);

    cam_table_entry_t *entry = &table->entries[index];

    // Store old port for logging
    uint32_t old_port = entry->header.logical_port;

    // Update entry
    entry->header.logical_port = new_port & 0xFF;
    entry->header.last_updated = time(NULL);

    // Update statistics
    manager->stats.entries_moved++;

    pthread_mutex_unlock(&table->lock);

    // Log the update
    if (manager->log_callback != NULL)
    {
        char log_msg[256];
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 mac_bytes[0], mac_bytes[1], mac_bytes[2],
                 mac_bytes[3], mac_bytes[4], mac_bytes[5]);
        snprintf(log_msg, sizeof(log_msg),
                 "Updated L2 entry: MAC %s VLAN %d Port %u->%u",
                 mac_str, vlan_id, old_port, new_port);
        manager->log_callback(log_msg, 0); // INFO level
    }

    return 0;
}

int cam_table_get_all_l2_entries(cam_table_manager_t *manager,
                                 cam_l2_entry_t *entries,
                                 uint32_t *count)
{
    if (!manager || !manager->cam_table || !entries || !count)
    {
        return -1;
    }

    cam_table_t *table = manager->cam_table;
    uint32_t found_count = 0;

    pthread_mutex_lock(&table->lock);

    for (uint32_t i = 0; i < table->count && found_count < *count; i++)
    {
        cam_table_entry_t *entry = &table->entries[i];

        if (entry->header.type == ENTRY_TYPE_L2_MAC &&
            entry->header.status != ENTRY_STATUS_INVALID)
        {
            memcpy(&entries[found_count], &entry->data.l2_entry, sizeof(cam_l2_entry_t));
            found_count++;
        }
    }

    pthread_mutex_unlock(&table->lock);

    *count = found_count;
    return 0;
}

int cam_table_clear_all_l2_entries(cam_table_manager_t *manager)
{
    if (!manager || !manager->cam_table)
    {
        return -1;
    }

    cam_table_t *table = manager->cam_table;
    uint32_t deleted_count = 0;

    pthread_mutex_lock(&table->lock);

    for (uint32_t i = 0; i < table->count; i++)
    {
        cam_table_entry_t *entry = &table->entries[i];

        if (entry->header.type == ENTRY_TYPE_L2_MAC &&
            entry->header.status != ENTRY_STATUS_INVALID)
        {
            // Call delete callback if set
            if (manager->delete_callback != NULL)
            {
                manager->delete_callback(&entry->header, manager);
            }

            entry->header.status = ENTRY_STATUS_INVALID;
            entry->header.type = ENTRY_TYPE_INVALID;
            deleted_count++;
        }
    }

    // Reset L2 index
    table->l2_count = 0;

    // Update statistics and utilization
    manager->stats.entries_deleted += deleted_count;
    manager->utilization.used_entries -= deleted_count;
    manager->utilization.free_entries += deleted_count;
    manager->utilization.allocated_l2 = 0;

    pthread_mutex_unlock(&table->lock);

    // Log the clearance
    if (manager->log_callback != NULL)
    {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg),
                 "Cleared all L2 entries: %u entries removed", deleted_count);
        manager->log_callback(log_msg, 0); // INFO level
    }

    return 0;
}

int cam_table_set_mac_pending(cam_table_manager_t *manager,
                              const uint8_t *mac_bytes,
                              uint16_t vlan_id,
                              const char *reason)
{
    if (!manager || !manager->cam_table || !mac_bytes)
    {
        return -1;
    }

    cam_table_t *table = manager->cam_table;
    int index = find_entry_index(manager, mac_bytes, vlan_id);

    if (index < 0)
    {
        return -1; // Not found
    }

    pthread_mutex_lock(&table->lock);

    cam_table_entry_t *entry = &table->entries[index];
    entry->header.status = ENTRY_STATUS_PENDING_ADD;

    pthread_mutex_unlock(&table->lock);

    // Log the pending state
    if (manager->log_callback != NULL)
    {
        char log_msg[256];
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 mac_bytes[0], mac_bytes[1], mac_bytes[2],
                 mac_bytes[3], mac_bytes[4], mac_bytes[5]);
        snprintf(log_msg, sizeof(log_msg),
                 "MAC %s VLAN %d set to PENDING: %s", mac_str, vlan_id, reason);
        manager->log_callback(log_msg, 1); // WARNING level
    }

    return 0;
}

int cam_table_block_mac(cam_table_manager_t *manager,
                        const uint8_t *mac_bytes,
                        uint16_t vlan_id,
                        const char *reason)
{
    if (!manager || !manager->cam_table || !mac_bytes)
    {
        return -1;
    }

    // First, ensure the MAC exists in the table
    int index = find_entry_index(manager, mac_bytes, vlan_id);
    if (index < 0)
    {
        // If not found, add it with DROP action
        return cam_table_add_l2_entry(manager, mac_bytes, vlan_id, 0, PKT_ACTION_DROP);
    }

    cam_table_t *table = manager->cam_table;

    pthread_mutex_lock(&table->lock);

    cam_table_entry_t *entry = &table->entries[index];
    entry->header.logical_port = 0; // No port
    // Note: In a real implementation, you'd set the action to DROP

    pthread_mutex_unlock(&table->lock);

    // Log the blocking
    if (manager->log_callback != NULL)
    {
        char log_msg[256];
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 mac_bytes[0], mac_bytes[1], mac_bytes[2],
                 mac_bytes[3], mac_bytes[4], mac_bytes[5]);
        snprintf(log_msg, sizeof(log_msg),
                 "MAC %s VLAN %d BLOCKED: %s", mac_str, vlan_id, reason);
        manager->log_callback(log_msg, 2); // ERROR level
    }

    return 0;
}