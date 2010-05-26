/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is public domain and free for all purposes.
 * 
 * Love Hornquist Astrand <lha@h5l.org>
 */
#include <tfm.h>


int fp_find_prime(fp_int *a)
{
  fp_int b;
  int res;

  if (fp_iseven(a))
    fp_add_d(a, 1, a);

  do {

    if ((res = fp_isprime(a)) == FP_NO) {
      fp_add_d(a, 2, a);
      continue;
    }
#if 0 /* we can't do this with linear search */
    /* see if (a-1)/2 is prime */
    fp_init(&b);
    fp_sub_d(a, 1, &b);
    fp_div_2(&b, &b);
 
    /* is it prime? */
    if ((res = fp_isprime(&b)) == FP_YES)
      fp_add_d(a, 2, a);
#endif

  } while (res != FP_YES);

  fp_zero(&b);

  return res;
}
