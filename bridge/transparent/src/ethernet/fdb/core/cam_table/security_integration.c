// security_integration.c
#include "cam_table_operations.h"

/**
 * @brief Security integration function - called when attack is detected
 */
void security_handle_attack_detection(cam_table_manager_t *cam_manager,
                                      anomaly_detector_t *detector,
                                      const char *attacker_mac_str,
                                      uint16_t vlan_id,
                                      int threat_level)
{
    if (!cam_manager || !attacker_mac_str)
        return;

    // Convert MAC string to bytes
    uint8_t mac_bytes[6];
    if (sscanf(attacker_mac_str, "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
               &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
               &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]) != 6)
    {
        return; // Invalid MAC format
    }

    char reason[100];

    if (threat_level >= 70) // CRITICAL threat - BLOCK immediately
    {
        snprintf(reason, sizeof(reason), "Critical attack detected (level %d)", threat_level);
        cam_table_block_mac(cam_manager, mac_bytes, vlan_id, reason);

        // Also add to IP block list if we have IP information
        if (detector && strlen(detector->current.attacker_ip) > 0)
        {
            add_to_block_list(detector, detector->current.attacker_ip, reason);
        }
    }
    else if (threat_level >= 40) // MEDIUM threat - set to PENDING
    {
        snprintf(reason, sizeof(reason), "Suspicious activity detected (level %d)", threat_level);
        cam_table_set_mac_pending(cam_manager, mac_bytes, vlan_id, reason);
    }
    // LOW threat - just log, no action
}

/**
 * @brief Example usage in your main monitoring function
 */
void enhanced_monitoring_with_cam(const char *interface, cam_table_manager_t *cam_manager)
{
    anomaly_detector_t detector;
    init_detector(&detector);

    // Initialize CAM table if not already done
    if (!cam_manager->initialized)
    {
        cam_table_init(cam_manager, UFT_MODE_L2_BRIDGING);
    }

    // ... (rest of my monitoring setup)

    while (!stop_monitoring)
    {
        // ... (packet capture and analysis code)

        // After anomaly detection
        int threat_score = detect_anomalies(&detector);

        if (threat_score >= 40) // Medium or higher threat
        {
            // Extract MAC from packet and handle security
            // You need to extract MAC from your packet buffer
            uint8_t src_mac[6];
            memcpy(src_mac, packet + 6, 6); // Source MAC is at offset 6 in Ethernet header

            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                     src_mac[0], src_mac[1], src_mac[2],
                     src_mac[3], src_mac[4], src_mac[5]);

            security_handle_attack_detection(cam_manager, &detector,
                                             mac_str, 1, threat_score); // VLAN 1 for example
        }

        // ... (rest of monitoring loop)
    }
}