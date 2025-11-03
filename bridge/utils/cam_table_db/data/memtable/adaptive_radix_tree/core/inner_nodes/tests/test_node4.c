#include "/mnt/c/Users/dmako/kryosette/kryosette-servers/bridge/utils/cam_table_db/data/memtable/adaptive_radix_tree/core/inner_nodes/include/node4.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Mock leaf node for testing
typedef struct leaf_node
{
    struct node_header header;
    char value[32];
} leaf_node;

leaf_node *create_leaf(const char *value)
{
    leaf_node *leaf = malloc(sizeof(leaf_node));
    leaf->header.type = 255; // Use 255 for leaf type
    leaf->header.count = 0;
    leaf->header.prefix_len = 0;
    strncpy(leaf->value, value, sizeof(leaf->value) - 1);
    leaf->value[sizeof(leaf->value) - 1] = '\0';
    return leaf;
}

void leaf_free(leaf_node *leaf)
{
    free(leaf);
}

// Simple mock implementation
void art_node_free_iterative(art_node *node)
{
    free(node);
}

void test_node4_creation()
{
    printf("=== Testing Node4 Creation ===\n");

    inner_node node = node4_create();
    assert(node != NULL);

    node4 *n = (node4 *)node;
    assert(n->header.type == NODE4);
    assert(n->header.count == 0);
    assert(n->header.prefix_len == 0);

    // Verify all keys and children are zeroed
    for (int i = 0; i < 4; i++)
    {
        assert(n->keys[i] == 0);
        assert(n->children[i] == NULL);
    }

    node4_free(n);
    printf("✅ Node4 creation test passed\n");
}

void test_node4_add_child()
{
    printf("\n=== Testing Node4 Add Child ===\n");

    node4 *node = (node4 *)node4_create();
    assert(node != NULL);

    // Create test leaves
    art_node *leaf1 = (art_node *)create_leaf("value1");
    art_node *leaf2 = (art_node *)create_leaf("value2");
    art_node *leaf3 = (art_node *)create_leaf("value3");
    art_node *leaf4 = (art_node *)create_leaf("value4");
    art_node *leaf5 = (art_node *)create_leaf("value5");

    // Test 1: Add first child
    int result = node4_add_child(node, 'C', leaf1);
    assert(result == 0);
    assert(node->header.count == 1);
    assert(node->keys[0] == 'C');
    assert(node->children[0] == leaf1);
    printf("✅ Added first child 'C'\n");

    // Test 2: Add child that should be sorted before existing
    result = node4_add_child(node, 'A', leaf2);
    assert(result == 0);
    assert(node->header.count == 2);
    assert(node->keys[0] == 'A');
    assert(node->keys[1] == 'C');
    assert(node->children[0] == leaf2);
    assert(node->children[1] == leaf1);
    printf("✅ Added child 'A' (maintained sorted order)\n");

    // Test 3: Add child in the middle
    result = node4_add_child(node, 'B', leaf3);
    assert(result == 0);
    assert(node->header.count == 3);
    assert(node->keys[0] == 'A');
    assert(node->keys[1] == 'B');
    assert(node->keys[2] == 'C');
    printf("✅ Added child 'B' (inserted in middle)\n");

    // Test 4: Add child at the end
    result = node4_add_child(node, 'D', leaf4);
    assert(result == 0);
    assert(node->header.count == 4);
    assert(node->keys[0] == 'A');
    assert(node->keys[1] == 'B');
    assert(node->keys[2] == 'C');
    assert(node->keys[3] == 'D');
    printf("✅ Added child 'D' (inserted at end)\n");

    // Test 5: Try to add duplicate key
    result = node4_add_child(node, 'B', leaf5);
    assert(result == -3);
    assert(node->header.count == 4);
    printf("✅ Rejected duplicate key 'B'\n");

    // Test 6: Try to add to full node
    result = node4_add_child(node, 'E', leaf5);
    assert(result == -2);
    assert(node->header.count == 4);
    printf("✅ Rejected addition to full node\n");

    // Cleanup
    node4_free(node);
    leaf_free((leaf_node *)leaf5);
    printf("✅ All add child tests passed\n");
}

void test_node4_find_child()
{
    printf("\n=== Testing Node4 Find Child ===\n");

    node4 *node = (node4 *)node4_create();
    assert(node != NULL);

    // Add test children
    art_node *leaf1 = (art_node *)create_leaf("value1");
    art_node *leaf2 = (art_node *)create_leaf("value2");
    art_node *leaf3 = (art_node *)create_leaf("value3");

    node4_add_child(node, 'C', leaf1);
    node4_add_child(node, 'A', leaf2);
    node4_add_child(node, 'B', leaf3);

    // Test finding existing children
    art_node *found = node4_find_child(node, 'A');
    assert(found == leaf2);
    printf("✅ Found child 'A'\n");

    found = node4_find_child(node, 'B');
    assert(found == leaf3);
    printf("✅ Found child 'B'\n");

    found = node4_find_child(node, 'C');
    assert(found == leaf1);
    printf("✅ Found child 'C'\n");

    // Test finding non-existent child
    found = node4_find_child(node, 'X');
    assert(found == NULL);
    printf("✅ Correctly did not find child 'X'\n");

    // Test with NULL node
    found = node4_find_child(NULL, 'A');
    assert(found == NULL);
    printf("✅ Handled NULL node correctly\n");

    node4_free(node);
    printf("✅ All find child tests passed\n");
}

void test_node4_remove_child()
{
    printf("\n=== Testing Node4 Remove Child ===\n");

    node4 *node = (node4 *)node4_create();
    assert(node != NULL);

    // Add test children
    art_node *leaf1 = (art_node *)create_leaf("value1");
    art_node *leaf2 = (art_node *)create_leaf("value2");
    art_node *leaf3 = (art_node *)create_leaf("value3");
    art_node *leaf4 = (art_node *)create_leaf("value4");

    node4_add_child(node, 'A', leaf1);
    node4_add_child(node, 'B', leaf2);
    node4_add_child(node, 'C', leaf3);
    node4_add_child(node, 'D', leaf4);

    assert(node->header.count == 4);

    // Test 1: Remove from middle
    int result = node4_remove_child(node, 'B');
    assert(result == 0);
    assert(node->header.count == 3);
    assert(node->keys[0] == 'A');
    assert(node->keys[1] == 'C');
    assert(node->keys[2] == 'D');
    printf("✅ Removed middle child 'B'\n");

    // Test 2: Remove from beginning
    result = node4_remove_child(node, 'A');
    assert(result == 0);
    assert(node->header.count == 2);
    assert(node->keys[0] == 'C');
    assert(node->keys[1] == 'D');
    printf("✅ Removed first child 'A'\n");

    // Test 3: Remove from end
    result = node4_remove_child(node, 'D');
    assert(result == 0);
    assert(node->header.count == 1);
    assert(node->keys[0] == 'C');
    printf("✅ Removed last child 'D'\n");

    // Test 4: Remove non-existent key
    result = node4_remove_child(node, 'X');
    assert(result == -3);
    assert(node->header.count == 1);
    printf("✅ Rejected removal of non-existent key\n");

    // Test 5: Remove from empty node
    node4 *empty_node = (node4 *)node4_create();
    result = node4_remove_child(empty_node, 'A');
    assert(result == -2);
    printf("✅ Handled removal from empty node\n");

    // Test 6: Remove with NULL node
    result = node4_remove_child(NULL, 'A');
    assert(result == -1);
    printf("✅ Handled NULL node in removal\n");

    // Remove last child
    result = node4_remove_child(node, 'C');
    assert(result == 0);
    assert(node->header.count == 0);
    printf("✅ Removed last remaining child\n");

    node4_free(node);
    node4_free(empty_node);
    printf("✅ All remove child tests passed\n");
}

void test_edge_cases()
{
    printf("\n=== Testing Edge Cases ===\n");

    // Test with maximum capacity
    node4 *node = (node4 *)node4_create();
    art_node *leaves[4];

    for (int i = 0; i < 4; i++)
    {
        char value[32];
        snprintf(value, sizeof(value), "value%d", i);
        leaves[i] = (art_node *)create_leaf(value);

        int result = node4_add_child(node, 'A' + i, leaves[i]);
        assert(result == 0);
    }

    assert(node->header.count == 4);
    printf("✅ Filled node to maximum capacity\n");

    // Verify sorted order
    for (int i = 0; i < 4; i++)
    {
        assert(node->keys[i] == 'A' + i);
    }
    printf("✅ Maintained sorted order at full capacity\n");

    node4_free(node);
    printf("✅ All edge case tests passed\n");
}

int main()
{
    printf("Starting Node4 Comprehensive Tests\n\n");

    test_node4_creation();
    test_node4_add_child();
    test_node4_find_child();
    test_node4_remove_child();
    test_edge_cases();

    printf("\nAll Node4 tests passed successfully!\n");
    printf("Summary: Creation, Addition, Search, Removal all working correctly.\n");

    return 0;
}