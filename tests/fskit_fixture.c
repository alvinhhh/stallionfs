#define _DARWIN_C_SOURCE 1
#include "../filesystem/image.h"
#include <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static sfs_image *image;
static sfs_result result;
static sfs_result anchor;
static void need(int ok, const char *where) {
    if (!ok) {
        fprintf(stderr, "%s: status=%d errno=%d\n", where, result.status, errno);
        if (image) { sfs_image *owned = image; image = NULL; (void)sfs_image_close(owned, &result); }
        exit(1);
    }
}
#define OK(call) need((call) == SFS_OK, #call)
static void hex(FILE *f, const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; ++i) fprintf(f, "%02x", p[i]);
}
static sfs_metadata_initial metadata(uint32_t mode) {
    sfs_metadata_initial m = {0};
    m.mode = mode; m.uid = geteuid(); m.gid = getegid();
    m.restore = SFS_RESTORE_BIRTH | SFS_RESTORE_ACCESS | SFS_RESTORE_MODIFICATION;
    m.birth.seconds = m.access.seconds = m.modification.seconds = 1700000000;
    m.birth.nanoseconds = 123; m.access.nanoseconds = 456; m.modification.nanoseconds = 789;
    return m;
}
static const char *names[] = {"empty", "resource", "sparse-resource", "data",
    "data-resource", "opaque", "link", "dir", "child"};
typedef struct { sfs_inode parent, inode; const char *name; enum sfs_kind kind; } name_row;
static const name_row namespace_rows[] = {
    {1, 2, "empty", SFS_FILE}, {1, 3, "resource", SFS_FILE},
    {1, 4, "sparse-resource", SFS_FILE}, {1, 5, "data", SFS_FILE},
    {1, 6, "data-resource", SFS_FILE}, {1, 7, "opaque", SFS_FILE},
    {1, 8, "link", SFS_SYMLINK}, {1, 9, "dir", SFS_DIRECTORY},
    {9, 10, "child", SFS_FILE}, {1, 6, "data-resource-alias", SFS_FILE},
    {9, 6, "data-resource-alias", SFS_FILE}
};
static const char fork_name[] = "com.apple.ResourceFork";
static const char opaque_name[] = "org.alvin.sfs-allocation";
static uint8_t payload[8193];
static sfs_inode ids[10] = {1};
static sfs_metadata_entry entries[10];
static void check_content(sfs_inode id, size_t size, int holes) {
    uint8_t bytes[16385]; size_t n = 0;
    memset(bytes, 0xa5, sizeof(bytes));
    OK(sfs_image_read(image, 0, id, 0, bytes, sizeof(bytes), &n, &result));
    need(n == size, "primary length");
    for (size_t j = 0; j < n; ++j) need(bytes[j] == (holes ? 0 : payload[j]), "primary bytes");
}
static void check_xattrs(sfs_inode id, const char *expected) {
    sfs_xattr_entry e = {0}; int found = 0; uint64_t size = 0;
    OK(sfs_image_next_xattr(image, 0, anchor.generation, anchor.root_digest,
                            id, NULL, 0, &e, &found, &result));
    need(found == (expected != NULL), "xattr count");
    if (!expected) return;
    need(e.name_length == strlen(expected) && !memcmp(e.name, expected, e.name_length) && e.size == sizeof(payload), "xattr identity");
    OK(sfs_image_xattr_size(image, 0, id, expected, strlen(expected), &size, &result));
    need(size == sizeof(payload), "xattr size");
    uint8_t bytes[8193]; size_t n = 0;
    OK(sfs_image_read_xattr(image, 0, id, expected, strlen(expected), 0, bytes, sizeof(bytes), &n, &result));
    need(n == sizeof(bytes) && !memcmp(bytes, payload, n), "xattr bytes");
    OK(sfs_image_next_xattr(image, 0, anchor.generation, anchor.root_digest,
                            id, expected, strlen(expected), &e, &found, &result));
    need(!found, "xattr end");
}
int main(int argc, char **argv) {
    need(argc == 2 && argv[1][0] == '/', "one absolute fresh parent");
    umask(077);
    need(mkdir(argv[1], 0700) == 0, "exclusive private parent");
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (uint8_t)((i * 37 + 11) & 255);
    sfs_metadata_initial root = metadata(S_IFDIR | 0777);
    OK(sfs_image_create_metadata_version(argv[1], "image.sfs", 8 * 1024 * 1024, 6, &root, &image, &result));
    OK(sfs_image_begin(image, &result));
    for (size_t i = 0; i < 9; ++i) {
        enum sfs_kind kind = i == 6 ? SFS_SYMLINK : i == 7 ? SFS_DIRECTORY : SFS_FILE;
        sfs_metadata_initial m = metadata(kind == SFS_DIRECTORY ? S_IFDIR | 0777 : kind == SFS_SYMLINK ? S_IFLNK | 0777 : S_IFREG | 0666);
        sfs_inode parent = i == 8 ? ids[8] : 1;
        if (kind == SFS_SYMLINK) OK(sfs_image_symlink_metadata(image, parent, names[i], strlen(names[i]), "data", 4, &m, &ids[i + 1], &result));
        else OK(sfs_image_add_metadata(image, parent, names[i], strlen(names[i]), kind, &m, &ids[i + 1], &result));
        need(ids[i + 1] == i + 2, "fixed inode sequence");
        if (i == 2) OK(sfs_image_resize(image, ids[i + 1], 16385, &result));
        if (i == 3 || i == 4 || i == 8) OK(sfs_image_write(image, ids[i + 1], 0, payload, i == 8 ? 64 : sizeof(payload), &result));
        const char *x = (i == 1 || i == 2 || i == 4) ? fork_name : i == 5 ? opaque_name : NULL;
        if (x) OK(sfs_image_set_xattr(image, ids[i + 1], x, strlen(x), payload, sizeof(payload), &result));
    }
    OK(sfs_image_link(image, 6, 1, "data-resource-alias", 19, &result));
    OK(sfs_image_link(image, 6, 9, "data-resource-alias", 19, &result));
    OK(sfs_image_commit(image, &result));
    anchor = result;
    for (size_t i = 0; i < 10; ++i) {
        OK(sfs_image_stat_metadata(image, 0, ids[i], &entries[i], &result));
        sfs_metadata_entry *m = &entries[i];
        enum sfs_kind kind = i == 0 || i == 8 ? SFS_DIRECTORY : i == 7 ? SFS_SYMLINK : SFS_FILE;
        need(m->entry.inode == ids[i] && m->entry.kind == kind && m->link_count == (ids[i] == 6 ? 3u : 1u) &&
             m->uid == geteuid() && m->gid == getegid() && m->flags == 0 &&
             m->mode == (uint32_t)(kind == SFS_DIRECTORY ? S_IFDIR | 0777 : kind == SFS_SYMLINK ? S_IFLNK | 0777 : S_IFREG | 0666), "metadata");
        uint64_t expected_size = i == 3 ? 16385 : i == 4 || i == 5 ? 8193 : i == 7 ? 4 : i == 9 ? 64 : 0;
        uint64_t expected_allocation = i == 4 || i == 5 ? 12288 : (i == 7 || i == 9) ? 4096 : 0;
        need(m->entry.size == expected_size && m->referenced_data_bytes == expected_allocation &&
             m->birth.seconds == 1700000000 && m->birth.nanoseconds == 123 &&
             m->access.seconds == 1700000000 && m->access.nanoseconds == 456,
             "metadata sizes and preserved times");
        if (i) {
            sfs_entry e;
            OK(sfs_image_lookup(image, 0, i == 9 ? ids[8] : 1, names[i - 1], strlen(names[i - 1]), &e, &result));
            need(e.inode == ids[i] && e.name_length == strlen(names[i - 1]) && !memcmp(e.name, names[i - 1], e.name_length), "lookup identity");
        }
        if (kind == SFS_FILE) check_content(ids[i], i == 3 ? 16385 : i == 4 || i == 5 ? 8193 : i == 9 ? 64 : 0, i == 3);
        if (kind == SFS_SYMLINK) {
            uint8_t b[4096]; size_t n = 0;
            OK(sfs_image_readlink(image, 0, ids[i], b, sizeof(b), &n, &result));
            need(n == 4 && !memcmp(b, "data", 4), "symlink bytes");
        }
        check_xattrs(ids[i], i == 2 || i == 3 || i == 5 ? fork_name : i == 6 ? opaque_name : NULL);
    }
    for (size_t i = 0; i < 11; ++i) {
        const name_row *row = &namespace_rows[i]; sfs_entry e;
        OK(sfs_image_lookup(image, 0, row->parent, row->name, strlen(row->name), &e, &result));
        need(e.inode == row->inode && e.parent == row->parent && e.kind == row->kind &&
             e.name_length == strlen(row->name) && !memcmp(e.name, row->name, e.name_length), "exact namespace lookup");
        if (row->inode == 6) { check_content(e.inode, sizeof(payload), 0); check_xattrs(e.inode, fork_name); }
    }
    for (size_t d = 0; d < 2; ++d) {
        sfs_cookie cookie = {0}; sfs_entry e; int found = 0; unsigned seen = 0; size_t count = 0;
        sfs_inode parent = d ? 9 : 1;
        do {
            uint64_t position = 0;
            OK(sfs_image_next_position(image, 0, parent, &cookie, &e, &position, &found, &result));
            if (!found) break;
            size_t i = 0;
            while (i < 11 && !(namespace_rows[i].parent == parent && e.name_length == strlen(namespace_rows[i].name) &&
                               !memcmp(e.name, namespace_rows[i].name, e.name_length))) ++i;
            need(i < 11 && e.parent == parent && e.inode == namespace_rows[i].inode && e.kind == namespace_rows[i].kind &&
                 !(seen & (1u << i)) && position >= 17, "exact namespace row");
            seen |= 1u << i; ++count;
        } while (count <= 11);
        need(!found && count == (d ? 2u : 9u), "namespace count");
    }
    need(result.generation == anchor.generation && !memcmp(result.uuid, anchor.uuid, 16) && !memcmp(result.root_digest, anchor.root_digest, 32), "stable anchor");
    sfs_verify_budget budget = {8192, 32 * 1024 * 1024, 32 * 1024 * 1024, 100000,
                               16 * 1024 * 1024, 32 * 1024 * 1024, NULL, NULL};
    OK(sfs_image_verify(image, &budget, &result));
    need(result.coverage == SFS_COVERAGE_FULL_REACHABLE, "full verification");
    anchor = result;
    sfs_image *owned = image; image = NULL;
    OK(sfs_image_close(owned, &result));
    /* Identity inputs are published only after full verification and consumed close. */
    char path[4096];
    need(snprintf(path, sizeof(path), "%s/manifest.json", argv[1]) < (int)sizeof(path), "manifest path");
    FILE *manifest = fopen(path, "wx"); need(manifest != NULL, "exclusive manifest");
    fprintf(manifest, "{\"format\":\"0.6\",\"full_verified\":true,\"consumed_close\":true,\"payload_bytes\":49226,\"uuid\":\"");
    hex(manifest, anchor.uuid, 16); fprintf(manifest, "\",\"generation\":%" PRIu64 ",\"root_digest\":\"", anchor.generation);
    hex(manifest, anchor.root_digest, 32); fprintf(manifest, "\",\"entries\":[");
    for (size_t i = 0; i < 10; ++i) {
        sfs_metadata_entry *m = &entries[i];
        fprintf(manifest, "%s{\"name\":\"%s\",\"inode\":%" PRIu64 ",\"parent\":%" PRIu64 ",\"kind\":%d,\"size\":%" PRIu64 ",\"referenced_data_bytes\":%" PRIu64 ",\"link_count\":%" PRIu64 ",\"mode\":%u,\"uid\":%u,\"gid\":%u,\"flags\":%u,\"times\":[", i ? "," : "", i ? names[i-1] : "/", m->entry.inode, m->entry.parent, m->entry.kind, m->entry.size, m->referenced_data_bytes, m->link_count, m->mode, m->uid, m->gid, m->flags);
        sfs_timestamp ts[] = {m->birth, m->access, m->modification, m->change};
        for (size_t j = 0; j < 4; ++j) fprintf(manifest, "%s[%" PRId64 ",%u]", j ? "," : "", ts[j].seconds, ts[j].nanoseconds);
        const char *x = i == 2 || i == 3 || i == 5 ? fork_name : i == 6 ? opaque_name : "";
        fprintf(manifest, "],\"xattr_name\":\"%s\",\"xattr_size\":%u", x, *x ? 8193u : 0u);
        if (m->entry.kind == SFS_FILE) {
            uint8_t content[16385] = {0}, primary_digest[32];
            if (i != 3 && m->entry.size) memcpy(content, payload, (size_t)m->entry.size);
            CC_SHA256(content, (CC_LONG)m->entry.size, primary_digest);
            fprintf(manifest, ",\"primary_sha256\":\""); hex(manifest, primary_digest, 32); fprintf(manifest, "\"");
        }
        if (i == 7) fprintf(manifest, ",\"target_hex\":\"64617461\"");
        fprintf(manifest, "}");
    }
    uint8_t digest[32]; CC_SHA256(payload, sizeof(payload), digest);
    fprintf(manifest, "],\"names\":[");
    for (size_t i = 0; i < 11; ++i) {
        const name_row *row = &namespace_rows[i];
        fprintf(manifest, "%s{\"parent\":%" PRIu64 ",\"inode\":%" PRIu64 ",\"name\":\"%s\",\"kind\":%d}",
                i ? "," : "", row->parent, row->inode, row->name, row->kind);
    }
    fprintf(manifest, "],\"payload8193_sha256\":\""); hex(manifest, digest, 32); fprintf(manifest, "\"}\n");
    need(!ferror(manifest) && fclose(manifest) == 0, "manifest close");
    need(snprintf(path, sizeof(path), "%s/FixtureIdentity.swift", argv[1]) < (int)sizeof(path), "identity path");
    FILE *swift = fopen(path, "wx"); need(swift != NULL, "exclusive identity");
    fprintf(swift, "import Foundation\nenum FixtureIdentity {\n static let uuid: [UInt8] = [");
    for (size_t i = 0; i < 16; ++i) fprintf(swift, "%s%u", i ? "," : "", anchor.uuid[i]);
    fprintf(swift, "]\n static let generation: UInt64 = %" PRIu64 "\n static let digest: [UInt8] = [", anchor.generation);
    for (size_t i = 0; i < 32; ++i) fprintf(swift, "%s%u", i ? "," : "", anchor.root_digest[i]);
    fprintf(swift, "]\n static let entries: [(inode: UInt64, parent: UInt64, name: String, kind: UInt32, links: UInt64)] = [\n");
    for (size_t i = 0; i < 10; ++i) {
        sfs_metadata_entry *m = &entries[i];
        fprintf(swift, "  (%" PRIu64 ",%" PRIu64 ",\"%s\",%u,%" PRIu64 "),\n",
                m->entry.inode, m->entry.parent, i ? names[i-1] : "/", (unsigned)m->entry.kind, m->link_count);
    }
    fprintf(swift, "]\n static let names: [(parent: UInt64, inode: UInt64, name: String, kind: UInt32)] = [\n");
    for (size_t i = 0; i < 11; ++i) {
        const name_row *row = &namespace_rows[i];
        fprintf(swift, "  (%" PRIu64 ",%" PRIu64 ",\"%s\",%u),\n", row->parent, row->inode, row->name, (unsigned)row->kind);
    }
    fprintf(swift, "]\n}\n"); need(!ferror(swift) && fclose(swift) == 0, "identity close");
    return 0;
}
