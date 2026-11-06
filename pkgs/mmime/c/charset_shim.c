/* charset_shim.c: charset conversion to UTF-8 through iconv, for the CeeSafe `mmime` package. Conversions are
 * made at ingest (header decoding), never on a hot path, so each call opens and closes its converter.
 *
 * mmc_to_utf8 converts `in` from the charset named `name` into `out`. It returns the number of bytes written, or
 * -1 for an unknown charset, -2 when `out` is too small. Invalid input sequences become U+FFFD and conversion goes on.
 */
#include <errno.h>
#include <iconv.h>
#include <stdint.h>
#include <string.h>

int64_t mmc_to_utf8(const uint8_t *name, size_t name_len, const uint8_t *in, size_t in_len, uint8_t *out,
                    size_t cap);

int64_t mmc_to_utf8(const uint8_t *name, size_t name_len, const uint8_t *in, size_t in_len, uint8_t *out,
                    size_t cap) {
    char charset[64];
    if (name_len == 0 || name_len >= sizeof charset) return -1;
    for (size_t i = 0; i < name_len; i++) {
        if (name[i] == 0) return -1;
        charset[i] = (char)name[i];
    }
    charset[name_len] = 0;
    iconv_t cd = iconv_open("UTF-8", charset);
    if (cd == (iconv_t)-1) return -1;
    char *src = (char *)(uintptr_t)in; /* iconv takes char **, but does not write the input */
    size_t src_left = in_len;
    char *dst = (char *)out;
    size_t dst_left = cap;
    int64_t result = 0;
    while (src_left > 0) {
        size_t r = iconv(cd, &src, &src_left, &dst, &dst_left);
        if (r != (size_t)-1) break;
        if (errno == E2BIG) {
            result = -2;
            break;
        }
        /* EILSEQ or EINVAL: replace one byte with U+FFFD and go on. */
        if (dst_left < 3) {
            result = -2;
            break;
        }
        memcpy(dst, "\xef\xbf\xbd", 3);
        dst += 3;
        dst_left -= 3;
        src++;
        src_left--;
    }
    if (result == 0) {
        /* Flush a stateful encoding's shift sequence (ISO-2022-JP). */
        if (iconv(cd, NULL, NULL, &dst, &dst_left) == (size_t)-1 && errno == E2BIG) result = -2;
    }
    iconv_close(cd);
    if (result < 0) return result;
    return (int64_t)(cap - dst_left);
}
