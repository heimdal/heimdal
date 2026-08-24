#include "krb5_locl.h"
#include <err.h>

static const unsigned char request[] = {
    0x30, 0x1a,
      0xa0, 0x07, 0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xa2, 0x03, 0x1b, 0x01, 0x58,
      0xa7, 0x03, 0x02, 0x01, 0xff,
      0xa8, 0x05, 0x30, 0x03, 0x02, 0x01, 0x12
};

int
main(void)
{
    unsigned char *encoded = NULL;
    KDC_REQ_BODY body;
    size_t encoded_len, size;
    int ret;

    memset(&body, 0, sizeof(body));
    ret = decode_KDC_REQ_BODY(request, sizeof(request), &body, &size);
    if (ret)
        errx(1, "decode_KDC_REQ_BODY: %d", ret);
    if (size != sizeof(request) ||
        (uint32_t)body.nonce != UINT32_MAX)
        errx(1, "decoded nonce mismatch");

    ASN1_MALLOC_ENCODE(KDC_REQ_BODY, encoded, encoded_len,
                       &body, &size, ret);
    if (ret)
        errx(1, "encode_KDC_REQ_BODY: %d", ret);
    if (size != encoded_len || encoded_len != sizeof(request) ||
        memcmp(encoded, request, sizeof(request)) != 0)
        errx(1, "request did not round trip");

    free(encoded);
    free_KDC_REQ_BODY(&body);
    return 0;
}
