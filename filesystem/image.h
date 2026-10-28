#ifndef SFS_IMAGE_H
#define SFS_IMAGE_H

#include <stddef.h>
#include <stdint.h>

/* Experimental offline core. Callers serialize access to each handle. */
typedef struct sfs_image sfs_image;
typedef uint64_t sfs_inode;
typedef uint32_t sfs_view; /* 0: current namespace; 1..32: immutable snapshots. */

#define SFS_ROOT_INODE UINT64_C(1)
#define SFS_NAME_MAX 255u
#ifndef SFS_IMAGE_MAX
#define SFS_IMAGE_MAX UINT64_C(67108864)
#endif
#ifndef SFS_FILE_MAX
#define SFS_FILE_MAX UINT64_C(4194304)
#endif
#ifndef SFS_METADATA_MAX
#define SFS_METADATA_MAX UINT64_C(1048576)
#endif
#ifndef SFS_ENTRY_MAX
#define SFS_ENTRY_MAX 1024u
#endif
#ifndef SFS_SNAPSHOT_MAX
#define SFS_SNAPSHOT_MAX 32u
#endif

enum sfs_status {
    SFS_OK, SFS_INVALID, SFS_IO, SFS_BUSY, SFS_UNSUPPORTED, SFS_LIMIT,
    SFS_CORRUPT, SFS_RECOVERY_REQUIRED, SFS_OUTCOME_UNKNOWN, SFS_POISONED,
    SFS_NOT_FOUND, SFS_EXISTS, SFS_STATE, SFS_NOMEM
};
enum sfs_phase {
    SFS_PHASE_NONE, SFS_PHASE_PARENT, SFS_PHASE_CREATE, SFS_PHASE_LOCK,
    SFS_PHASE_VALIDATE, SFS_PHASE_READ, SFS_PHASE_ADMISSION,
    SFS_PHASE_RECORDS, SFS_PHASE_RECORD_BARRIER, SFS_PHASE_SLOT0,
    SFS_PHASE_SLOT1, SFS_PHASE_COMMIT_BARRIER, SFS_PHASE_PARENT_BARRIER,
    SFS_PHASE_FINAL_BARRIER, SFS_PHASE_IDENTITY, SFS_PHASE_CLOSE
};
enum sfs_kind { SFS_DIRECTORY = 1, SFS_FILE = 2 };
enum sfs_coverage { SFS_COVERAGE_NONE, SFS_COVERAGE_FULL_REACHABLE };

typedef struct {
    enum sfs_status status;
    enum sfs_phase phase;
    int system_errno;
    uint64_t generation, committed_end, physical_end, device, inode;
    uint8_t uuid[16], root_digest[32];
    enum sfs_coverage coverage;
} sfs_result;
typedef struct {
    sfs_result slots[2]; /* Each OK candidate has passed full reachable verification. */
    int pair_valid, latest_may_be_unknown;
} sfs_recovery;
typedef struct {
    sfs_inode inode, parent;
    enum sfs_kind kind;
    uint64_t size;
    size_t name_length;
    uint8_t name[SFS_NAME_MAX];
} sfs_entry;
typedef struct {
    uint8_t namespace_digest[32];
    uint32_t next;
    int started;
} sfs_cookie; /* Zero-initialize; changing the selected namespace invalidates it. */

/* directory must be owned, private, local writable APFS; name is one component.
 * create never removes a failed image. open never initializes or repairs one.
 * All opens retain a nonblocking exclusive lock until checked close. */
enum sfs_status sfs_image_create(const char *directory, const char *name,
                               sfs_image **out, sfs_result *result);
enum sfs_status sfs_image_open(const char *directory, const char *name,
                             sfs_image **out, sfs_result *result);
/* Inspection is read-only, never selects a candidate implicitly. */
enum sfs_status sfs_image_inspect(const char *directory, const char *name,
                                sfs_image **out, sfs_recovery *recovery,
                                sfs_result *result);
enum sfs_status sfs_image_select(sfs_image *, unsigned slot, sfs_result *);
enum sfs_status sfs_image_close(sfs_image *, sfs_result *);
enum sfs_status sfs_image_verify(sfs_image *, sfs_result *);

enum sfs_status sfs_image_begin(sfs_image *, sfs_result *);
enum sfs_status sfs_image_abort(sfs_image *, sfs_result *);
enum sfs_status sfs_image_add(sfs_image *, sfs_inode parent, const void *name,
                            size_t name_length, enum sfs_kind, sfs_inode *out,
                            sfs_result *);
enum sfs_status sfs_image_remove(sfs_image *, sfs_inode, sfs_result *);
enum sfs_status sfs_image_rename(sfs_image *, sfs_inode, sfs_inode parent,
                               const void *name, size_t name_length, sfs_result *);
/* Bounded ranged input. Gaps are zero-filled; size changes are separate. */
enum sfs_status sfs_image_write(sfs_image *, sfs_inode, uint64_t offset,
                              const void *data, size_t length, sfs_result *);
enum sfs_status sfs_image_resize(sfs_image *, sfs_inode, uint64_t size, sfs_result *);
/* Snapshot retains the last committed current namespace, even inside a tx. */
enum sfs_status sfs_image_snapshot(sfs_image *, const void *name, size_t length,
                                 sfs_view *out, sfs_result *);
enum sfs_status sfs_image_commit(sfs_image *, sfs_result *);

enum sfs_status sfs_image_snapshot_view(sfs_image *, const void *name, size_t length,
                                      sfs_view *out, sfs_result *);
enum sfs_status sfs_image_lookup(sfs_image *, sfs_view, sfs_inode parent,
                               const void *name, size_t length, sfs_entry *, sfs_result *);
enum sfs_status sfs_image_stat(sfs_image *, sfs_view, sfs_inode, sfs_entry *, sfs_result *);
enum sfs_status sfs_image_read(sfs_image *, sfs_view, sfs_inode, uint64_t offset,
                             void *data, size_t capacity, size_t *read_count, sfs_result *);
/* At end, returns OK with *found=0. Returns one entry, never an allocated list. */
enum sfs_status sfs_image_next(sfs_image *, sfs_view, sfs_inode parent,
                             sfs_cookie *, sfs_entry *, int *found, sfs_result *);

#endif
