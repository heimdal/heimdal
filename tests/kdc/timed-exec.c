#include <config.h>

#include <roken.h>

int
main(int argc, char **argv)
{
    struct timeval start, stop;
    char *end;
    long elapsed, limit;
    int ret;

    if (argc < 3)
	errx(1, "usage: timed-exec milliseconds command [argument ...]");

    limit = strtol(argv[1], &end, 10);
    if (*argv[1] == '\0' || *end != '\0' || limit < 1)
	errx(1, "invalid time limit: %s", argv[1]);

    gettimeofday(&start, NULL);
    ret = simple_execvp(argv[2], &argv[2]);
    gettimeofday(&stop, NULL);
    if (ret)
	return ret;

    timevalsub(&stop, &start);
    elapsed = stop.tv_sec * 1000 + stop.tv_usec / 1000;
    if (elapsed >= limit)
	errx(1, "command took %ldms; expected less than %ldms",
	     elapsed, limit);

    return 0;
}
