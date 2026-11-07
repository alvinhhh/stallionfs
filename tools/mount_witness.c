/* Read-only mount witness; compile against the pinned Darwin SDK before use. */
#include <sys/param.h>
#include <sys/mount.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
_Static_assert(MNT_EXT_FSKIT == 0x00000002, "Unexpected SDK FSKit flag");
static void json_string(const char *s, size_t limit) {
    putchar('"');
    for (size_t i = 0; i < limit && s[i]; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') { putchar('\\'); putchar(c); }
        else if (c < 0x20 || c >= 0x7f) printf("\\u%04x", c);
        else putchar(c);
    }
    putchar('"');
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    struct statfs *mounts = NULL;
    int count = getmntinfo_r_np(&mounts, MNT_NOWAIT);
    if (count <= 0 || mounts == NULL) { free(mounts); return 3; }
    const struct statfs *found = NULL;
    int matches = 0;
    for (int i = 0; i < count; ++i) {
        if (strnlen(mounts[i].f_mntonname, sizeof mounts[i].f_mntonname) == sizeof mounts[i].f_mntonname ||
            strnlen(mounts[i].f_mntfromname, sizeof mounts[i].f_mntfromname) == sizeof mounts[i].f_mntfromname ||
            strnlen(mounts[i].f_fstypename, sizeof mounts[i].f_fstypename) == sizeof mounts[i].f_fstypename) {
            free(mounts); return 4;
        }
        if (!strcmp(mounts[i].f_mntonname, argv[2])) { found = &mounts[i]; ++matches; }
    }
    int ok = matches == 1 && !strcmp(found->f_mntfromname, argv[1]) && (found->f_flags_ext & MNT_EXT_FSKIT);
    printf("{\"ok\":%s,\"mountpoint_matches\":%d,\"sdk_mnt_ext_fskit\":%u", ok ? "true" : "false", matches, MNT_EXT_FSKIT);
    if (matches == 1) {
        printf(",\"f_flags_ext\":%u,\"f_type\":%u,\"f_fstypename\":", found->f_flags_ext, found->f_type);
        json_string(found->f_fstypename, sizeof found->f_fstypename);
        printf(",\"f_mntonname\":"); json_string(found->f_mntonname, sizeof found->f_mntonname);
        printf(",\"f_mntfromname\":"); json_string(found->f_mntfromname, sizeof found->f_mntfromname);
    }
    puts("}"); free(mounts); return ok ? 0 : 5;
}
