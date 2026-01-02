#!/usr/bin/env perl
#
# Generate config.h for Windows from config.h.w32 template
# Used when cross-compiling for Windows on Unix
#

use strict;
use warnings;
use Getopt::Long;

my %vars = (
    'PACKAGE' => 'heimdal',
    'PACKAGE_NAME' => 'Heimdal',
    'PACKAGE_BUGREPORT' => 'heimdal-bugs@h5l.org',
    'PACKAGE_VERSION' => '7.99.1',
    'PACKAGE_COPYRIGHT' => 'Copyright (c) 1995-2025 Kungliga Tekniska Högskolan',
    'PACKAGE_COMPANY' => 'Heimdal Project',
    'MAJOR' => '7',
    'MINOR' => '99',
    'AUX' => '1',
    'PATCH' => '0',
);

my %features = (
    'KRB5' => 1,
    'PKINIT' => 1,
    'NO_AFS' => 1,
);

my $target = '';  # 'win32' or 'win64'

GetOptions(
    'package=s' => \$vars{'PACKAGE'},
    'package-name=s' => \$vars{'PACKAGE_NAME'},
    'package-version=s' => \$vars{'PACKAGE_VERSION'},
    'package-bugreport=s' => \$vars{'PACKAGE_BUGREPORT'},
    'package-copyright=s' => \$vars{'PACKAGE_COPYRIGHT'},
    'package-company=s' => \$vars{'PACKAGE_COMPANY'},
    'krb5!' => \$features{'KRB5'},
    'pkinit!' => \$features{'PKINIT'},
    'weak-crypto!' => \$features{'WEAK_CRYPTO'},
    'afs!' => sub { $features{'NO_AFS'} = !$_[1]; },
    'win32' => sub { $target = 'win32'; },
    'win64' => sub { $target = 'win64'; },
) or die "Usage: $0 [--win32|--win64] [options] < config.h.w32 > config.h\n";

die "Must specify --win32 or --win64\n" unless $target;

# Parse version into components
if ($vars{'PACKAGE_VERSION'} =~ /^(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?/) {
    $vars{'MAJOR'} = $1;
    $vars{'MINOR'} = $2;
    $vars{'AUX'} = $3 // 0;
    $vars{'PATCH'} = $4 // 0;
}

while (<STDIN>) {
    if (/\@FEATURE_DEFS\@/) {
        print "#define KRB5 1\n" if $features{'KRB5'};
        print "#define PKINIT 1\n" if $features{'PKINIT'};
        print "#define HEIM_WEAK_CRYPTO 1\n" if $features{'WEAK_CRYPTO'};
        print "#define NO_AFS 1\n" if $features{'NO_AFS'};
        # Target architecture for bits.c
        print "#define TARGET_WINDOWS 1\n";
        print "#define TARGET_WIN64 1\n" if $target eq 'win64';
        # Add HAVE_STDINT_H since modern Windows has it
        print "#define HAVE_STDINT_H 1\n";
        print "#define HAVE_INT8_T 1\n";
        print "#define HAVE_INT16_T 1\n";
        print "#define HAVE_INT32_T 1\n";
        print "#define HAVE_INT64_T 1\n";
        print "#define HAVE_UINT8_T 1\n";
        print "#define HAVE_UINT16_T 1\n";
        print "#define HAVE_UINT32_T 1\n";
        print "#define HAVE_UINT64_T 1\n";
    } elsif (/\@VERSION_OPTDEFS\@/) {
        # Leave empty for cross-compile builds
    } else {
        # Substitute @VAR@ patterns
        s/\@([A-Z_]+)\@/$vars{$1} \/\/ $1/eg;
        print;
    }
}
