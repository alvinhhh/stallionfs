#ifndef STALLION_TREE_H
#define STALLION_TREE_H
#include <stddef.h>

/* Called only on the invoking thread; return nonzero to cancel. */
typedef int (*stallion_cancel_fn)(void *context);

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
