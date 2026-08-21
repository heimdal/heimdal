#include <config.h>

#include <roken.h>

int
main(int argc, char **argv)
{
    struct sockaddr_in addr;
    char packet[1];
    char *end;
    long port;
    rk_socket_t s;

    if (argc != 2)
	errx(1, "usage: udp-sink port");

    port = strtol(argv[1], &end, 10);
    if (*argv[1] == '\0' || *end != '\0' || port < 1 || port > 65535)
	errx(1, "invalid port: %s", argv[1]);

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (rk_IS_BAD_SOCKET(s))
	err(1, "socket");

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == -1)
	err(1, "bind");

    if (recv(s, packet, sizeof(packet), 0) == -1)
	err(1, "recv");

    return 0;
}
