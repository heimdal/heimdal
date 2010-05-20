#makefile for TomsFastMath
#
#
VERSION=0.12

CFLAGS += -Wall -W -Wshadow -Isrc/headers

ifndef MAKE
   MAKE=make
endif

ifndef IGNORE_SPEED

CFLAGS += -O3 -funroll-loops

#profiling
#PROF=-pg -g
#CFLAGS += $(PROF)

#speed
CFLAGS += -fomit-frame-pointer

endif

#START_INS
OBJECTS=src/addsub/fp_add.o src/addsub/fp_add_d.o src/addsub/fp_addmod.o src/addsub/fp_cmp.o \
src/addsub/fp_cmp_d.o src/addsub/fp_cmp_mag.o src/addsub/fp_sub.o src/addsub/fp_sub_d.o \
src/addsub/fp_submod.o src/addsub/s_fp_add.o src/addsub/s_fp_sub.o src/bin/fp_radix_size.o \
src/bin/fp_read_radix.o src/bin/fp_read_signed_bin.o src/bin/fp_read_unsigned_bin.o \
src/bin/fp_reverse.o src/bin/fp_s_rmap.o src/bin/fp_signed_bin_size.o src/bin/fp_to_signed_bin.o \
src/bin/fp_to_unsigned_bin.o src/bin/fp_toradix.o src/bin/fp_unsigned_bin_size.o src/bit/fp_cnt_lsb.o \
src/bit/fp_count_bits.o src/bit/fp_div_2.o src/bit/fp_div_2d.o src/bit/fp_lshd.o src/bit/fp_mod_2d.o \
src/bit/fp_rshd.o src/divide/fp_div.o src/divide/fp_div_d.o src/divide/fp_mod.o src/divide/fp_mod_d.o \
src/exptmod/fp_2expt.o src/exptmod/fp_exptmod.o src/misc/fp_ident.o src/misc/fp_set.o \
src/mont/fp_montgomery_calc_normalization.o src/mont/fp_montgomery_reduce.o \
src/mont/fp_montgomery_setup.o src/mul/fp_mul.o src/mul/fp_mul_2.o src/mul/fp_mul_2d.o \
src/mul/fp_mul_comba.o src/mul/fp_mul_comba_12.o src/mul/fp_mul_comba_17.o src/mul/fp_mul_comba_20.o \
src/mul/fp_mul_comba_24.o src/mul/fp_mul_comba_28.o src/mul/fp_mul_comba_3.o src/mul/fp_mul_comba_32.o \
src/mul/fp_mul_comba_4.o src/mul/fp_mul_comba_48.o src/mul/fp_mul_comba_6.o src/mul/fp_mul_comba_64.o \
src/mul/fp_mul_comba_7.o src/mul/fp_mul_comba_8.o src/mul/fp_mul_comba_9.o \
src/mul/fp_mul_comba_small_set.o src/mul/fp_mul_d.o src/mul/fp_mulmod.o src/numtheory/fp_gcd.o \
src/numtheory/fp_invmod.o src/numtheory/fp_isprime.o src/numtheory/fp_lcm.o \
src/numtheory/fp_prime_miller_rabin.o src/numtheory/fp_prime_random_ex.o src/sqr/fp_sqr.o \
src/sqr/fp_sqr_comba.o src/sqr/fp_sqr_comba_12.o src/sqr/fp_sqr_comba_17.o src/sqr/fp_sqr_comba_20.o \
src/sqr/fp_sqr_comba_24.o src/sqr/fp_sqr_comba_28.o src/sqr/fp_sqr_comba_3.o src/sqr/fp_sqr_comba_32.o \
src/sqr/fp_sqr_comba_4.o src/sqr/fp_sqr_comba_48.o src/sqr/fp_sqr_comba_6.o src/sqr/fp_sqr_comba_64.o \
src/sqr/fp_sqr_comba_7.o src/sqr/fp_sqr_comba_8.o src/sqr/fp_sqr_comba_9.o \
src/sqr/fp_sqr_comba_generic.o src/sqr/fp_sqr_comba_small_set.o src/sqr/fp_sqrmod.o 

HEADERS=src/headers/tfm.h 

#END_INS

ifndef LIBPATH
   LIBPATH=~/local/lib
endif

ifndef INCPATH
   INCPATH=~/local/include
endif

ifndef INSTALL_GROUP
   GROUP=jherzog
else
   GROUP=$(INSTALL_GROUP)
endif

ifndef INSTALL_USER
   USER=jherzog
else
   USER=$(INSTALL_USER)
endif

ifndef LIBNAME
	LIBNAME=libtfm.a
endif

default: $(LIBNAME)

$(LIBNAME): $(OBJECTS)
	$(AR) $(ARFLAGS) $@ $(OBJECTS)
	ranlib $@

install: $(LIBNAME)
	install -d -g $(GROUP) -o $(USER) $(DESTDIR)$(LIBPATH)
	install -d -g $(GROUP) -o $(USER) $(DESTDIR)$(INCPATH)
	install -g $(GROUP) -o $(USER) $(LIBNAME) $(DESTDIR)$(LIBPATH)
	install -g $(GROUP) -o $(USER) $(HEADERS) $(DESTDIR)$(INCPATH)

mtest/mtest: mtest/mtest.o
	cd mtest ; CFLAGS="$(CFLAGS) -I../" MAKE=${MAKE} ${MAKE} mtest

test: $(LIBNAME) demo/test.o mtest/mtest
	$(CC) $(CFLAGS) demo/test.o $(LIBNAME) $(PROF) -o test

timing: $(LIBNAME) demo/test.o
	$(CC) $(CFLAGS) demo/test.o $(LIBNAME) $(PROF) -o test

profiled:
	CFLAGS="${CFLAGS} -fprofile-generate" MAKE=${MAKE} ${MAKE} timing
	./test
	rm -f `find . -type f | grep "[.]o" | xargs`
	rm -f `find . -type f | grep "[.]a" | xargs`
	rm -f test
	CFLAGS="${CFLAGS} -fprofile-use" MAKE=${MAKE} ${MAKE} timing
	
stest: $(LIBNAME) demo/stest.o 
	$(CC) $(CFLAGS) demo/stest.o $(LIBNAME) -o stest

rsatest: $(LIBNAME) demo/rsa.o
	$(CC) $(CFLAGS) demo/rsa.o $(LIBNAME) -o rsatest

docdvi: tfm.tex
	touch tfm.ind
	latex tfm >/dev/null
	latex tfm >/dev/null
	makeindex tfm
	latex tfm >/dev/null

docs: docdvi
	latex tfm >/dev/null
	dvipdf tfm
	mv -f tfm.pdf doc

#This rule cleans the source tree of all compiled code, not including the pdf
#documentation.
clean:
	rm -f `find . -type f | grep "[.]o" | xargs`
	rm -f `find . -type f | grep "[.]lo"  | xargs`
	rm -f `find . -type f | grep "[.]a" | xargs`
	rm -f `find . -type f | grep "[.]la"  | xargs`
	rm -f `find . -type f | grep "[.]obj" | xargs`
	rm -f `find . -type f | grep "[.]lib" | xargs`
	rm -f `find . -type f | grep "[.]exe" | xargs`
	rm -f `find . -type f | grep "[.]gcda" | xargs`
	rm -f `find . -type f | grep "[.]gcno" | xargs`
	rm -f `find . -type f | grep "[.]il" | xargs`
	rm -f `find . -type f | grep "[.]dyn" | xargs`
	rm -f `find . -type f | grep "[.]dpi" | xargs`
	rm -rf `find . -type d | grep "[.]libs" | xargs`
	rm -f tfm.aux  tfm.dvi  tfm.idx  tfm.ilg  tfm.ind  tfm.lof  tfm.log  tfm.toc test mtest/mtest
	cd mtest ; MAKE=${MAKE} ${MAKE} clean

no_oops: clean
	cd .. ; cvs commit
	echo Scanning for scratch/dirty files
	find . -type f | grep -v CVS | xargs -n 1 bash mess.sh

zipup: no_oops docs clean
	perl gen.pl ; mv mpi.c pre_gen/ ; \
	cd .. ; rm -rf tfm* tomsfastmath-$(VERSION) ; mkdir tomsfastmath-$(VERSION) ; \
	cp -R ./tomsfastmath/* ./tomsfastmath-$(VERSION)/ ; \
	tar -c tomsfastmath-$(VERSION)/* | bzip2 -9vvc > tfm-$(VERSION).tar.bz2 ; \
	zip -9r tfm-$(VERSION).zip tomsfastmath-$(VERSION)/* ; \
	mv -f tfm* ~ ; rm -rf tomsfastmath-$(VERSION)

# $Source: /cvs/libtom/tomsfastmath/makefile,v $ 
# $Revision: 1.38 $ 
# $Date: 2007/03/13 01:23:03 $ 
