#ifndef STALLION_TREE_H
#define STALLION_TREE_H
#include <stddef.h>
#include <stdint.h>

/* Called only on the invoking thread; return nonzero to cancel. */
typedef int (*stallion_cancel_fn)(void *context);

struct stallion_scan_stats {
    uint64_t files, directories, symlinks, other, logical_bytes, skipped_mounts;
};

/* Counts descendants without following their symlinks. Nested mounts are counted
 * as directories but skipped; the root directory is not counted. bulk=0 selects
 * the private POSIX reference traversal. Callbacks run on the invoking thread.
 * Bulk scans use up to workers (1–4) threads; the POSIX reference is sequential.
 * No fixed input-path byte limit is imposed. error_path is a bounded diagnostic
 * buffer and may be truncated. Stats remain zero on failure.
 * Returns 0, or -1 with errno; cancellation reports EINTR.
 */
int stallion_scan(const char *path, int bulk, unsigned workers, struct stallion_scan_stats *stats,
                   stallion_cancel_fn cancel, void *context,
                   char *error_path, size_t error_capacity);

/* Exact destination, which must not exist. Never falls back to byte copying.
 * Workers are joined before return; failures can leave a partial new destination.
 * Directory-clone parents must be owned by the caller or root, non-writable by
 * other users unless sticky, and free of ACL mutation grants to other principals.
 * Callers must keep the source stable during copying; this is not a tree snapshot.
 * Return 0 on success, or -1 with errno and a best-effort recovery/error path.
 */
int stallion_clone(const char *source, const char *destination, unsigned workers,
                   stallion_cancel_fn cancel, void *context,
                   char *error_path, size_t error_capacity);
int stallion_clone_tree(const char *source, const char *destination, unsigned workers,
                        stallion_cancel_fn cancel, void *context,
                        char *error_path, size_t error_capacity);

/* Never follows links or descends into mounted volumes. Directories require
 * recursive; missing_ok accepts only a missing final entry, not other errors.
 */
int stallion_delete(const char *path, int recursive, int missing_ok, unsigned workers,
                    stallion_cancel_fn cancel, void *context,
                    char *error_path, size_t error_capacity);
#endif
