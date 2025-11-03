#include "/mnt/c/Users/dmako/kryosette/kryosette-servers/bridge/utils/cam_table_db/data/memtable/adaptive_radix_tree/core/inner_nodes/include/node4.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

// ==================== TESTING ====================
// Simple leaf node for testing

void node4_free(node4 *node)
{
    free(node);
}

leaf_node *create_leaf(const char *value)
{
    leaf_node *leaf = malloc(sizeof(leaf_node));
    leaf->header.type = LEAF_NODE;
    leaf->header.count = 0;
    leaf->header.prefix_len = 0;
    strncpy(leaf->value, value, sizeof(leaf->value) - 1);
    leaf->value[sizeof(leaf->value) - 1] = '\0';
    return leaf;
}

void test_basic_operations()
{
    printf("=== Basic Operations Test ===\n");

    // Test creation
    node4 *node = (node4 *)node4_create();
    assert(node != NULL);
    assert(node->header.count == 0);
    printf("✅ Node4 creation passed\n");

    // Test adding children
    leaf_node *leaf1 = create_leaf("test1");
    int result = node4_add_child(node, 'C', (art_node)leaf1);
    assert(result == 0);
    assert(node->header.count == 1);
    assert(node->keys[0] == 'C');
    printf("✅ Add child 'C' passed\n");

    // Test finding children
    art_node found = node4_find_child(node, 'C');
    assert(found == (art_node)leaf1);
    printf("✅ Find child 'C' passed\n");

    // Test adding more children
    leaf_node *leaf2 = create_leaf("test2");
    result = node4_add_child(node, 'A', (art_node)leaf2);
    assert(result == 0);
    assert(node->header.count == 2);
    assert(node->keys[0] == 'A'); // Should be sorted
    assert(node->keys[1] == 'C');
    printf("✅ Add child 'A' (sorted) passed\n");

    // Test removing children
    result = node4_remove_child(node, 'A');
    assert(result == 0);
    assert(node->header.count == 1);
    printf("✅ Remove child 'A' passed\n");

    node4_print(node);

    node4_free(node);
    free(leaf1);
    free(leaf2);
}

void test_sorted_order()
{
    printf("\n=== Sorted Order Test ===\n");

    node4 *node = (node4 *)node4_create();

    // Add in non-sorted order: C, A, B, D
    leaf_node *leafC = create_leaf("C");
    leaf_node *leafA = create_leaf("A");
    leaf_node *leafB = create_leaf("B");
    leaf_node *leafD = create_leaf("D");

    node4_add_child(node, 'C', (art_node)leafC);
    node4_add_child(node, 'A', (art_node)leafA);
    node4_add_child(node, 'B', (art_node)leafB);
    node4_add_child(node, 'D', (art_node)leafD);

    // Should be sorted: A, B, C, D
    assert(node->keys[0] == 'A');
    assert(node->keys[1] == 'B');
    assert(node->keys[2] == 'C');
    assert(node->keys[3] == 'D');
    printf("✅ Sorted order maintained: A, B, C, D\n");

    node4_print(node);

    node4_free(node);
    free(leafA);
    free(leafB);
    free(leafC);
    free(leafD);
}

void test_error_cases()
{
    printf("\n=== Error Cases Test ===\n");

    node4 *node = (node4 *)node4_create();
    leaf_node *leaf = create_leaf("test");

    // Test NULL parameters
    int result = node4_add_child(NULL, 'A', (art_node)leaf);
    assert(result == -1);
    printf("✅ NULL node check passed\n");

    result = node4_add_child(node, 'A', NULL);
    assert(result == -1);
    printf("✅ NULL child check passed\n");

    // Test duplicate key
    node4_add_child(node, 'A', (art_node)leaf);
    result = node4_add_child(node, 'A', (art_node)leaf);
    assert(result == -3);
    printf("✅ Duplicate key check passed\n");

    // Test capacity exceeded
    leaf_node *leaf2 = create_leaf("test2");
    leaf_node *leaf3 = create_leaf("test3");
    leaf_node *leaf4 = create_leaf("test4");
    leaf_node *leaf5 = create_leaf("test5");

    node4_add_child(node, 'B', (art_node)leaf2);
    node4_add_child(node, 'C', (art_node)leaf3);
    node4_add_child(node, 'D', (art_node)leaf4);

    result = node4_add_child(node, 'E', (art_node)leaf5);
    assert(result == -2);
    printf("✅ Capacity exceeded check passed\n");

    node4_free(node);
    free(leaf);
    free(leaf2);
    free(leaf3);
    free(leaf4);
    free(leaf5);
}

int main()
{
    printf("🚀 Starting Node4 Comprehensive Tests\n\n");

    test_basic_operations();
    test_sorted_order();
    test_error_cases();

    printf("\n🎉 ALL TESTS PASSED! Node4 implementation is working correctly.\n");
    printf("📊 Tested: Creation, Addition, Search, Removal, Sorting, Error handling\n");

    return 0;
}
