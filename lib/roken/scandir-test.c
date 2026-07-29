#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <roken.h>

#ifdef WIN32
#define test_rmdir _rmdir
#else
#define test_rmdir rmdir
#endif

static int ROKEN_LIB_CALL
select_entry(const struct dirent *entry)
{
    return strncmp(entry->d_name, "keep-", 5) == 0;
}

static int
make_file(const char *dirname, const char *name)
{
    char path[MAXPATHLEN];
    FILE *f;

    if (snprintf(path, sizeof(path), "%s/%s", dirname, name) < 0 ||
        (f = fopen(path, "w")) == NULL)
        return -1;
    return fclose(f);
}

static void
remove_file(const char *dirname, const char *name)
{
    char path[MAXPATHLEN];

    if (snprintf(path, sizeof(path), "%s/%s", dirname, name) >= 0)
        (void) remove(path);
}

int
main(void)
{
    const char *const names[] = {
        "keep-zeta", "skip", "keep-alpha", "keep-gamma",
        "keep-beta", "keep-eta", "keep-delta"
    };
    const char *const expected[] = {
        "keep-alpha", "keep-beta", "keep-delta",
        "keep-eta", "keep-gamma", "keep-zeta"
    };
    char dirname[] = "scandir-test.XXXXXX";
    struct dirent **entries = NULL;
    size_t i;
    int nentries = 0;
    int ret = 1;

    if (mkdtemp(dirname) == NULL) {
        fprintf(stderr, "mkdtemp: %s\n", strerror(errno));
        return 1;
    }
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (make_file(dirname, names[i]) != 0) {
            fprintf(stderr, "failed to create %s\n", names[i]);
            goto out;
        }
    }

    nentries = scandir(dirname, &entries, select_entry, alphasort);
    if (nentries != (int)(sizeof(expected) / sizeof(expected[0]))) {
        fprintf(stderr, "scandir did not filter and sort entries\n");
        goto out;
    }
    for (i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
        if (strcmp(entries[i]->d_name, expected[i]) != 0) {
            fprintf(stderr, "scandir did not filter and sort entries\n");
            goto out;
        }
    }
    ret = 0;

out:
    for (i = 0; i < (size_t)(nentries > 0 ? nentries : 0); i++)
        free(entries[i]);
    free(entries);
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        remove_file(dirname, names[i]);
    if (test_rmdir(dirname) != 0)
        ret = 1;
    return ret;
}
