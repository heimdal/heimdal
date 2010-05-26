/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is public domain and free for all purposes.
 * 
 * Love Hornquist Astrand <lha@h5l.org>
 */
#include <tfm.h>
#include <stdarg.h>

void fp_init_multi(fp_int *a, ...)
{
  va_list ap;
  fp_int *b;

  fp_init(a);
  va_start(ap, a);
  while((b = va_arg(ap, fp_int *)) != NULL) {
    fp_init(b);
  }
  va_end(ap);
}
