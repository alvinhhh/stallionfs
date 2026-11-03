#ifndef STALLION_NATIVE_IMPORT_H
#define STALLION_NATIVE_IMPORT_H
#include "image.h"
#include <stdint.h>

/* Private synchronous operation. The caller keeps the source quiescent, owns
 * the GIL, and durably protects output before before_create returns success.
 * Descriptors and core handles never escape. All output/scratch is retained. */
typedef struct {
    const char *source, *destination;
    uint64_t source_identity[2], destination_identity[2], capacity;
    const sfs_verify_budget *verification_budget;
    int (*cancelled)(void *);
    int (*before_create)(void *);
    void *context;
} sfs_import_options;
typedef struct {
    int creation_attempted, created, existing, observed, import_committed;
    int verified, candidate_complete, abort_attempted, close_attempted;
    int reopen_attempted, reopen_close_attempted, local_error, cleanup_error;
    uint64_t observed_identity[2], failed_record, entries, scratch_bytes;
    uint64_t xattr_memory_high_water, xattr_names_scratch_high_water;
    const char *reason;
    char *failure_path;
    size_t failure_path_length;
    int failure_path_error, budget_explicit, budget_saturated;
    uint64_t parent_steps;
    sfs_verify_budget budget;
    sfs_result creation, original, commit, abort, verify, close, reopen, reopen_close;
} sfs_import_report;
/* A finite verification work policy, not a proof of the worst-case work.
 * Saturation retains UINT64_MAX as a finite allowance and never refuses an
 * otherwise representable input. Real completion still requires FULL coverage.
 * This pure helper is also exercised by the existing core test driver. */
static inline uint64_t sfs_import_budget_add(uint64_t a, uint64_t b, int *saturated) {
    if (a > UINT64_MAX - b) { *saturated = 1; return UINT64_MAX; }
    return a + b;
}
static inline uint64_t sfs_import_budget_mul(uint64_t a, uint64_t b, int *saturated) {
    if (b && a > UINT64_MAX / b) { *saturated = 1; return UINT64_MAX; }
    return a * b;
}
static inline sfs_verify_budget sfs_import_default_budget(uint64_t physical_end,
    uint64_t entries, uint64_t parent_steps, int *saturated) {
    uint64_t cells = physical_end / 4096 + !!(physical_end % 4096);
    /* image.c maximum(): at most 48 rows per committed index cell.
     * full_namespace/full_hardlinks/full_xattrs revisit each relation and walk
     * actual parent chains. Budget eight checked lookups per relation and
     * parent step, each allowing both directions of a MAX_HEIGHT=16 cursor.
     * page_read/bounds/metadata check rows and fixed headers; 64 checks/page
     * is a finite allowance. Cached reads can consume less. Memo cache misses
     * can read and evict one 4096-byte auxiliary page per visit. */
    uint64_t relations = sfs_import_budget_add(sfs_import_budget_mul(cells, 48, saturated), entries, saturated);
    relations = sfs_import_budget_add(relations, sfs_import_budget_mul(parent_steps, 3, saturated), saturated);
    relations = sfs_import_budget_add(relations, 1, saturated);
    uint64_t visits = sfs_import_budget_mul(relations, 8 * (2 * 16 + 1), saturated);
    uint64_t bytes = sfs_import_budget_mul(visits, 4096, saturated);
    uint64_t auxiliary = sfs_import_budget_mul(cells ? cells : 1, 128, saturated);
    sfs_verify_budget budget = {
        .raw_cells = sfs_import_budget_mul(relations, 2, saturated),
        .metadata_read_bytes = bytes, .metadata_hash_bytes = bytes,
        .checks = sfs_import_budget_mul(visits, 64, saturated),
        .auxiliary_bytes = auxiliary,
        .auxiliary_io_bytes = sfs_import_budget_mul(bytes, 2, saturated)
    };
    return budget;
}
void sfs_native_import(const sfs_import_options *, sfs_import_report *);
#endif
