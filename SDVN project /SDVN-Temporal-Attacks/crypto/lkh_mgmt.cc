/*
 * lkh_mgmt.cc — LKH Session Key Revocation  (Module 5, Section 7)
 *
 * Implements binary Logical Key Hierarchy tree with O(log n) revocation cost.
 *
 * Equation 3.18:  C_revoke = O(log n)
 *   1,000 vehicles → ~10 KEK updates  (vs. 1,000 under naïve full re-key)
 *
 * Exact C struct layout (Section 7.2):
 *   LKHNode  — kek, left, right, parent, is_leaf, vehicle_id, session_key, revoked
 *   LKHTree  — nodes[LKH_MAX_LEAVES*2], n_leaves, root_index, group_key
 *
 * Key functions (Section 7.3):
 *   lkh_revoke_vehicle(LKHTree*, uint8_t vehicle_id[16])
 *   distribute_kek_updates(LKHTree*)
 *   mark_key_revoked(VehicleKeyRecord*, uint8_t vehicle_id[16])
 *
 * Build:
 *   g++ -std=c++17 -O2 lkh_mgmt.cc -lssl -lcrypto -o lkh_mgmt
 *
 * Output: lkh_revocation_log.csv
 */

#include "teta_guard_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>

#ifdef HAVE_OPENSSL
#  include <openssl/rand.h>
#  include <openssl/sha.h>
#endif

/* ─── Fix-3: unified revocation keystore ────────────────────────────────── */
/* lkh_revoke_vehicle atomically calls mark_key_revoked via this pointer so
 * the LKH tree flag and the RSU HMAC keystore flag are always in sync.     */
static VehicleKeyRecord *g_ks      = NULL;
static uint32_t          g_ks_size = 0;

void lkh_set_keystore(VehicleKeyRecord *ks, uint32_t ks_size) {
    g_ks      = ks;
    g_ks_size = ks_size;
}

/* ─── Random key generation ──────────────────────────────────────────────── */

static void gen_random_key(uint8_t key[LKH_KEY_LEN]) {
#ifdef HAVE_OPENSSL
    RAND_bytes(key, LKH_KEY_LEN);
#else
    static uint64_t s = 0xFEDCBA9876543210ULL;
    for (int i = 0; i < (int)LKH_KEY_LEN; i++) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        key[i] = (uint8_t)(s >> 56);
    }
#endif
}

/* ─── Find leaf by vehicle_id ────────────────────────────────────────────── */

static uint32_t find_leaf_by_vehicle_id(const LKHTree *tree,
                                          const uint8_t vehicle_id[16]) {
    for (uint32_t i = 0; i < tree->n_leaves * 2; i++) {
        if (tree->nodes[i].is_leaf &&
            !tree->nodes[i].revoked &&
            memcmp(tree->nodes[i].vehicle_id, vehicle_id, 16) == 0)
            return i;
    }
    return UINT32_MAX;
}

/* ══════════════════════════════════════════════════════════════════════════
 * lkh_init()  — build binary LKH tree for n vehicles
 *
 * Tree layout (0-indexed):
 *   node 0     = root
 *   children of node i: left = 2i+1, right = 2i+2
 *   parent of node i (i>0): (i-1)/2
 *   Leaves: indices [total_nodes - n_leaves .. total_nodes - 1]
 * ══════════════════════════════════════════════════════════════════════════ */

void lkh_init(LKHTree *tree, const uint8_t (*vehicle_ids)[16], uint32_t n) {
    memset(tree, 0, sizeof(*tree));
    tree->n_leaves = n;

    /* Depth = ⌈log₂ n⌉ → total leaves in perfect tree = 2^depth */
    int depth = 0;
    while ((1u << depth) < n) depth++;
    uint32_t total_leaves = 1u << depth;
    uint32_t total_nodes  = 2 * total_leaves;  /* Perfect binary tree */
    if (total_nodes > LKH_MAX_LEAVES * 2) total_nodes = LKH_MAX_LEAVES * 2;

    /* Initialise all nodes */
    for (uint32_t i = 0; i < total_nodes; i++) {
        LKHNode *nd = &tree->nodes[i];
        memset(nd, 0, sizeof(*nd));
        gen_random_key(nd->kek);
        nd->left   = (2 * i + 1 < total_nodes) ? 2 * i + 1 : UINT32_MAX;
        nd->right  = (2 * i + 2 < total_nodes) ? 2 * i + 2 : UINT32_MAX;
        nd->parent = (i == 0) ? UINT32_MAX : (i - 1) / 2;
    }

    /* Assign vehicles to leaves */
    uint32_t leaf_start = total_leaves - 1;
    tree->root_index    = 0;

    for (uint32_t i = 0; i < n; i++) {
        LKHNode *leaf = &tree->nodes[leaf_start + i];
        leaf->is_leaf = true;
        memcpy(leaf->vehicle_id, vehicle_ids[i], 16);
        gen_random_key(leaf->session_key);
        leaf->revoked = false;
    }
    /* Mark unused leaf slots */
    for (uint32_t i = n; i < total_leaves; i++)
        tree->nodes[leaf_start + i].is_leaf = true;  /* empty, not revoked */

    gen_random_key(tree->group_key);

    printf("[LKH] Tree built: n=%u  depth=%d  nodes=%u\n", n, depth, total_nodes);
}

/* ══════════════════════════════════════════════════════════════════════════
 * distribute_kek_updates()  (Section 7.3)
 *
 * After revocation, re-encrypt and broadcast new KEKs to all non-revoked
 * leaves that share each updated internal node.
 * In simulation this prints the distribution plan; in production it would
 * schedule DSRC/CSMA delivery within the next beacon interval T_b.
 * ══════════════════════════════════════════════════════════════════════════ */

void distribute_kek_updates(LKHTree *tree) {
    printf("[LKH] Distributing KEK updates to non-revoked vehicles:\n");
    int update_count = 0;

    /* Compute the actual number of initialized nodes (same formula as lkh_init) */
    int depth = 0;
    while ((1u << depth) < tree->n_leaves) depth++;
    uint32_t total_leaves = 1u << depth;
    uint32_t total_nodes  = 2 * total_leaves;
    if (total_nodes > LKH_MAX_LEAVES * 2) total_nodes = LKH_MAX_LEAVES * 2;

    for (uint32_t i = 0; i < total_nodes; i++) {
        LKHNode *nd = &tree->nodes[i];
        if (nd->is_leaf) continue;
        if (nd->kek[0] == 0 && nd->kek[1] == 0) continue; /* uninitialised */

        /* Collect non-revoked leaves in this subtree */
        char recipients[256]; recipients[0] = '\0';
        int  n_rcpt = 0;
        for (uint32_t j = 0; j < total_nodes; j++) {
            LKHNode *leaf = &tree->nodes[j];
            if (!leaf->is_leaf || leaf->revoked) continue;
            if (leaf->vehicle_id[0] == '\0') continue;
            /* Check if leaf is a descendant of i */
            uint32_t cur = j;
            while (cur != UINT32_MAX && cur != i)
                cur = tree->nodes[cur].parent;
            if (cur == i) {
                if (n_rcpt < 4) {
                    char buf[24];
                    snprintf(buf, sizeof(buf), "%s ", (char *)leaf->vehicle_id);
                    strncat(recipients, buf, sizeof(recipients) - strlen(recipients) - 1);
                }
                n_rcpt++;
            }
        }
        if (n_rcpt > 0) {
            printf("[LKH]   node=%u  kek=%02x%02x...  rcpt=%d (%s%s)\n",
                   i, nd->kek[0], nd->kek[1], n_rcpt,
                   recipients, n_rcpt > 4 ? "..." : "");
            update_count++;
        }
    }
    printf("[LKH] Total KEK distribution messages: %d\n", update_count);
}

/* ══════════════════════════════════════════════════════════════════════════
 * lkh_revoke_vehicle()  (Section 7.3, Eq. 3.18)
 *
 * Revokes vehicle Vk:
 *   1. Mark leaf as revoked
 *   2. Walk path leaf → root, regenerating KEK at each node  (O(log n))
 *   3. Regenerate group key K_G
 *   4. Distribute updated KEKs
 * ══════════════════════════════════════════════════════════════════════════ */

void lkh_revoke_vehicle(LKHTree *tree, const uint8_t vehicle_id[16]) {
    uint32_t leaf_idx = find_leaf_by_vehicle_id(tree, vehicle_id);
    if (leaf_idx == UINT32_MAX) {
        printf("[LKH] Vehicle not found: %s\n", (const char *)vehicle_id);
        return;
    }

    /* 1. Mark leaf as revoked — Fix-3: atomically sync the HMAC keystore too */
    tree->nodes[leaf_idx].revoked = true;
    memset(tree->nodes[leaf_idx].session_key, 0, LKH_KEY_LEN); /* invalidate */
    if (g_ks != NULL)
        mark_key_revoked(g_ks, vehicle_id);   /* keeps VehicleKeyRecord.revoked in sync */
    printf("[LKH] Revoking %s (leaf=%u)\n", (const char *)vehicle_id, leaf_idx);

    /* 2. Walk up from leaf to root, regenerating KEKs on the path */
    int kek_updates = 0;
    uint32_t cur = tree->nodes[leaf_idx].parent;
    while (cur != UINT32_MAX) {
        gen_random_key(tree->nodes[cur].kek);
        kek_updates++;
        cur = tree->nodes[cur].parent;
    }

    /* 3. Regenerate group key K_G */
    gen_random_key(tree->group_key);

    printf("[LKH] KEK updates: %d  (O(log n), n=%u)\n", kek_updates, tree->n_leaves);

    /* 4. Distribute */
    distribute_kek_updates(tree);
}

/* ══════════════════════════════════════════════════════════════════════════
 * mark_key_revoked()  (Section 7.3)
 *
 * After lkh_revoke_vehicle(), mark the vehicle's HMAC session key as
 * revoked in the RSU keystore so lw_mitigate() returns
 * CRYPTO_DROP_REVOKED_KEY immediately on the next message.
 * ══════════════════════════════════════════════════════════════════════════ */

void mark_key_revoked(VehicleKeyRecord *keystore, const uint8_t vehicle_id[16]) {
    uint32_t ks_limit = (g_ks_size > 0) ? g_ks_size : MAX_VEHICLES;
    for (uint32_t i = 0; i < ks_limit; i++) {
        if (keystore[i].vehicle_id[0] == '\0') continue;
        if (memcmp(keystore[i].vehicle_id, vehicle_id, 16) == 0) {
            keystore[i].revoked = true;
            memset(keystore[i].session_key,  0, SESSION_KEY_LEN);
            /* Issue-2 fix: also revoke the CA identity cert so the vehicle
             * cannot produce validly-signed threshold/location-binding reports
             * after its session key has been wiped.  cert_revoke_vehicle adds
             * the id to the CRL in dilithium.cc; dilithium5_verify_cert then
             * rejects this vehicle even if its CA sig is cryptographically valid. */
            cert_revoke_vehicle(vehicle_id);
            printf("[LKH] mark_key_revoked: %s\n", (const char *)vehicle_id);
            return;
        }
    }
    printf("[LKH] mark_key_revoked: vehicle not in keystore: %s\n",
           (const char *)vehicle_id);
}

/* Retrieve session key for a vehicle; returns false if not found or revoked */
bool lkh_get_session_key(const LKHTree *tree,
                          const uint8_t vehicle_id[16],
                          uint8_t out[LKH_KEY_LEN]) {
    uint32_t leaf = find_leaf_by_vehicle_id(tree, vehicle_id);
    if (leaf == UINT32_MAX) return false;
    memcpy(out, tree->nodes[leaf].session_key, LKH_KEY_LEN);
    return true;
}

bool lkh_is_revoked(const LKHTree *tree, const uint8_t vehicle_id[16]) {
    uint32_t leaf = find_leaf_by_vehicle_id(tree, vehicle_id);
    /* find_leaf_by_vehicle_id skips revoked nodes, so UINT32_MAX means either
     * "not in tree" or "in tree but revoked."  Scan the populated portion
     * (tree->n_leaves * 2 nodes, not the full LKH_MAX_LEAVES * 2 capacity)
     * to distinguish the two cases.  This is O(n) over n_leaves; a vehicle_id
     * → leaf_index hash map would give O(1) if needed. */
    if (leaf == UINT32_MAX) {
        for (uint32_t i = 0; i < tree->n_leaves * 2; i++) {
            if (tree->nodes[i].is_leaf &&
                memcmp(tree->nodes[i].vehicle_id, vehicle_id, 16) == 0)
                return tree->nodes[i].revoked;
        }
    }
    return false;
}

/* ── main ─────────────────────────────────────────────────────────────────── */

#ifndef LKH_MGMT_NO_MAIN
int main(void) {
    printf("=== lkh_mgmt.cc — LKH Key Revocation (Eq. 3.18, O(log n)) ===\n");
    printf("[LKH] sizeof(LKHNode)  = %zu bytes\n", sizeof(LKHNode));
    printf("[LKH] sizeof(LKHTree)  = %zu bytes\n", sizeof(LKHTree));

    /* Build tree for 8 vehicles */
    static LKHTree tree;
    uint8_t vids[8][16];
    for (int i = 0; i < 8; i++) snprintf((char*)vids[i], 16, "V%d", i);
    lkh_init(&tree, vids, 8);

    /* Verify session keys accessible */
    printf("\n[LKH] Session keys before revocation:\n");
    for (int i = 0; i < 8; i++) {
        uint8_t k[LKH_KEY_LEN];
        bool ok = lkh_get_session_key(&tree, vids[i], k);
        printf("[LKH]   %s: %s  key=%02x%02x%02x%02x...\n",
               (char*)vids[i], ok ? "active" : "inactive",
               k[0], k[1], k[2], k[3]);
    }

    /* Revoke V3 */
    printf("\n[LKH] --- Revoking V3 (FS-MITIGATE trigger) ---\n");
    lkh_revoke_vehicle(&tree, vids[3]);

    /* V3 should now be inaccessible */
    bool revoked = lkh_is_revoked(&tree, vids[3]);
    printf("[LKH] V3 is_revoked: %s (expected: true)\n", revoked ? "true" : "false");

    uint8_t k[LKH_KEY_LEN] = {0};
    bool ok = lkh_get_session_key(&tree, vids[3], k);
    printf("[LKH] V3 session key accessible: %s (expected: false)\n",
           ok ? "true" : "false");

    /* Scale test: 1000 vehicles */
    printf("\n[LKH] Scaling test: n=1000\n");
    {
        static uint8_t big_vids[1000][16];
        static LKHTree big_tree;
        for (int i = 0; i < 1000; i++) snprintf((char*)big_vids[i], 16, "V%d", i);
        lkh_init(&big_tree, big_vids, 1000);
        /* Count path length for V500 */
        uint32_t leaf = find_leaf_by_vehicle_id(&big_tree, big_vids[500]);
        int depth = 0;
        uint32_t cur = leaf;
        while (cur != UINT32_MAX) { cur = big_tree.nodes[cur].parent; depth++; }
        printf("[LKH] n=1000: depth=%d  max_KEK_updates=%d  (naïve=1000)\n",
               depth, depth);
    }

    /* Write revocation log */
    FILE *f = fopen("lkh_revocation_log.csv", "w");
    fprintf(f, "vehicle_id,revoked,key_active\n");
    for (int i = 0; i < 8; i++) {
        uint8_t kk[LKH_KEY_LEN];
        bool active = lkh_get_session_key(&tree, vids[i], kk);
        fprintf(f, "%s,%s,%s\n",
                (char*)vids[i],
                lkh_is_revoked(&tree, vids[i]) ? "true" : "false",
                active ? "true" : "false");
    }
    fclose(f);
    printf("[LKH] Wrote lkh_revocation_log.csv\n");
    return 0;
}
#endif /* LKH_MGMT_NO_MAIN */
