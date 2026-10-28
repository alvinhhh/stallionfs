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
#define SFS_IMAGE_MAX UINT64_C(9223372036854771712)
#endif
#ifndef SFS_FILE_MAX
#define SFS_FILE_MAX UINT64_C(9223372036854775807)
#endif
#ifndef SFS_METADATA_MAX
#define SFS_METADATA_MAX UINT64_C(4096)
#endif
#ifndef SFS_ENTRY_MAX
#define SFS_ENTRY_MAX (UINT64_MAX - UINT64_C(2))
#endif
#ifndef SFS_SNAPSHOT_MAX
#define SFS_SNAPSHOT_MAX 32u
#endif

enum sfs_status {
    SFS_OK, SFS_INVALID, SFS_IO, SFS_BUSY, SFS_UNSUPPORTED, SFS_LIMIT,
    SFS_CORRUPT, SFS_RECOVERY_REQUIRED, SFS_OUTCOME_UNKNOWN, SFS_POISONED,
    SFS_NOT_FOUND, SFS_EXISTS, SFS_STATE, SFS_NOMEM, SFS_INCOMPLETE
};
enum sfs_phase {
    SFS_PHASE_NONE, SFS_PHASE_PARENT, SFS_PHASE_CREATE, SFS_PHASE_LOCK,
    SFS_PHASE_VALIDATE, SFS_PHASE_READ, SFS_PHASE_ADMISSION,
    SFS_PHASE_RECORDS, SFS_PHASE_RECORD_BARRIER, SFS_PHASE_SLOT0,
    SFS_PHASE_SLOT1, SFS_PHASE_COMMIT_BARRIER, SFS_PHASE_PARENT_BARRIER,
    SFS_PHASE_FINAL_BARRIER, SFS_PHASE_IDENTITY, SFS_PHASE_CLOSE,
    SFS_PHASE_VERIFY_AUX
};
enum sfs_kind { SFS_DIRECTORY = 1, SFS_FILE = 2 };
enum sfs_coverage {
    SFS_COVERAGE_NONE, SFS_COVERAGE_FULL_REACHABLE,
    SFS_COVERAGE_ROOT_ONLY, SFS_COVERAGE_TOUCHED
};
enum sfs_incomplete_reason {
    SFS_INCOMPLETE_NONE, SFS_INCOMPLETE_RAW, SFS_INCOMPLETE_METADATA_READ,
    SFS_INCOMPLETE_METADATA_HASH, SFS_INCOMPLETE_CHECKS,
    SFS_INCOMPLETE_AUX_LENGTH, SFS_INCOMPLETE_AUX_IO, SFS_INCOMPLETE_CANCELLED
};
/* All limits are positive; inspect shares them across both candidate passes. */
typedef struct {
    uint64_t raw_cells, metadata_read_bytes, metadata_hash_bytes, checks;
    uint64_t auxiliary_bytes, auxiliary_io_bytes;
    int (*cancelled)(void *context);
    void *context;
} sfs_verify_budget;

typedef struct {
    enum sfs_status status;
    enum sfs_phase phase;
    int system_errno;
    uint64_t generation, committed_end, physical_end, device, inode;
    uint8_t uuid[16], root_digest[32];
    enum sfs_coverage coverage;
    enum sfs_incomplete_reason incomplete_reason;
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
typedef struct { uint8_t bytes[1088]; } sfs_cookie;
/* Zero-initialize; cookies bind a committed namespace and parent, never pointers. */

/* directory must be owned, private, local writable APFS; name is one component.
 * create never removes a failed image. open never initializes or repairs one.
 * All opens retain a nonblocking exclusive lock until checked close. */
enum sfs_status sfs_image_create(const char *directory, const char *name,
                               uint64_t capacity, sfs_image **out, sfs_result *result);
enum sfs_status sfs_image_open(const char *directory, const char *name,
                             sfs_image **out, sfs_result *result);
/* Normal admission with O_RDONLY: selected ROOT_ONLY, no recovery fallback.
 * Mutations return STATE; fatal reads poison this ordinary handle. */
enum sfs_status sfs_image_open_readonly(const char *directory, const char *name,
                                      sfs_image **out, sfs_result *result);
/* Inspection is read-only, never selects a candidate implicitly. */
enum sfs_status sfs_image_inspect(const char *directory, const char *name,
                                sfs_image **out, sfs_recovery *recovery,
                                const sfs_verify_budget *budget, sfs_result *result);
enum sfs_status sfs_image_select(sfs_image *, unsigned slot,
                                 const sfs_verify_budget *, sfs_result *);
enum sfs_status sfs_image_close(sfs_image *, sfs_result *);
enum sfs_status sfs_image_verify(sfs_image *, const sfs_verify_budget *, sfs_result *);

enum sfs_status sfs_image_begin(sfs_image *, sfs_result *);
enum sfs_status sfs_image_abort(sfs_image *, sfs_result *);
enum sfs_status sfs_image_add(sfs_image *, sfs_inode parent, const void *name,
                            size_t name_length, enum sfs_kind, sfs_inode *out,
                            sfs_result *);
enum sfs_status sfs_image_remove(sfs_image *, sfs_inode, sfs_result *);
enum sfs_status sfs_image_rename(sfs_image *, sfs_inode, sfs_inode parent,
                               const void *name, size_t name_length, sfs_result *);
/* At most 65536 bytes per call; stream calls in one transaction. Holes read zero. */
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
/* Reconstruct a next cookie after a canonical child in the explicit view.
 * Bind to the successful open/select generation and commit-root digest.
 * Callers retain image/view identity. Failure leaves nonnull out unchanged;
 * success reports TOUCHED, including after the directory's last child. */
enum sfs_status sfs_image_resume_after(sfs_image *image, sfs_view view,
                                     uint64_t expected_generation,
                                     const uint8_t expected_root_digest[32],
                                     sfs_inode parent, sfs_inode previous,
                                     sfs_cookie *out, sfs_result *result);

#endif
