#ifndef STALLION_TREE_H
#define STALLION_TREE_H
#include <stddef.h>
#include <stdint.h>

/* Checked ResourceFork cursor arithmetic; a zero amount marks the end without
 * converting a potentially unrepresentable terminal offset. */
static inline int stallion_fork_chunk(uint64_t length, uint64_t offset, size_t capacity,
                                       uint32_t *position, size_t *amount) {
    if (length > (uint64_t)UINT32_MAX + 1 || offset > length || !capacity) return 0;
    *amount = 0;
    if (offset == length) return 1;
    if (offset > UINT32_MAX) return 0;
    uint64_t remaining = length - offset;
    *amount = remaining < capacity ? (size_t)remaining : capacity;
    *position = (uint32_t)offset;
    return 1;
}

/* Called only on the invoking thread; return nonzero to cancel. */
typedef int (*stallion_cancel_fn)(void *context);

/* Validate an owned, mode-private directory and reject ACL grants to other
 * principals. No permissions are changed. Return 0, or -1 with errno.
 */
int stallion_private_directory(const char *path);
/* Validate a pinned private directory or protected parent, including ACLs. */
int stallion_protected_directory_fd(int fd, int private);

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

/* Ordinary byte copy on macOS 13+, including across volumes that can preserve
 * the required metadata and sparse ranges. Destination must be absent. Parents
 * must meet the directory-clone protection rules below. Leaf-copy parents must
 * not grant inheritable file access to other principals. Failures can leave
 * partial output at the requested destination; workers are joined before return.
 * ResourceFork verification supports lengths through UINT32_MAX+1, a conservative
 * verifier limit, not a filesystem maximum. It runs after the copy engine and
 * does not guarantee early size refusal or an atomic source snapshot.
 */
int stallion_copy(const char *source, const char *destination, unsigned workers,
                  stallion_cancel_fn cancel, void *context,
                  char *error_path, size_t error_capacity);

enum stallion_copy_strategy { STALLION_COPY_MATERIALIZED, STALLION_COPY_AUTO };
/* Same ordinary-copy contract. AUTO may clone eligible regular children within
 * the private destination tree, then verifies ordinary-copy metadata on the clone.
 * Only an admitted GID-only normalization applies metadata to a clone, followed
 * by full verification.
 * Only unsupported/cross-volume clone errors with an absent entry may fall back.
 * Source and destination must remain stable; observed identity checks do not
 * protect against same-user replacement before the first destination lookup.
 */
int stallion_copy_with_strategy(const char *source, const char *destination,
                                enum stallion_copy_strategy strategy, unsigned workers,
                                stallion_cancel_fn cancel, void *context,
                                char *error_path, size_t error_capacity);

/* Exact destination, which must not exist. Never falls back to byte copying.
 * Workers are joined before return; failures can leave a partial new destination.
 * Directory-clone parents must be owned by the caller or root, non-writable by
 * other users unless sticky, and free of ACL mutation grants to other principals.
 * Internal regular-file and symlink hardlinks remain linked within the copy,
 * never to source inodes or aliases outside the copied tree.
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
