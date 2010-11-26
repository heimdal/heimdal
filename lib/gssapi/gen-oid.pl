#!/usr/bin/perl

require 'getopts.pl';

my $output;
my $CFILE, $HFILE;
my $onlybase;
my $header = 0;

Getopts('b:h') || die "foo";

if($opt_b) {
    $onlybase = $opt_b;
}

$header = 1 if ($opt_h);

if ($header) {
    printf "#ifndef GSSAPI_GSSAPI_OID\n";
    printf "#define GSSAPI_GSSAPI_OID 1\n\n";
} else {
    printf "#include \"gssapi.h\"\n\n";
}

while(<>) {

    if (/^\w*#(.*)/) {
	my $comment = $1;

	if ($header) {
	    printf("$comment\n");
	}

    } elsif (/^oid\s+([\w\.]+)\s+(\w+)\s+([\w\.]+)/) {
	my ($base, $name, $oid) = ($1, $2, $3);

	next if (defined $onlybase and $onlybase ne $base);

	my $store = "__" . lc($name) . "_oid_desc";

	# encode oid

	my @array = split(/\./, $oid);
	my $length = 0;
	my $data = "";

	my $num = $array[0] * 40 + $array[1];
	$data .= sprintf("\\x%x", $num);
	$length += 1;

	foreach $num (@array[2 .. $#array]) {
	    my $num2 = $num;
	    while ($num2) {
		my $p = int($num2 % 128);
		$num2 = int($num2 / 128);
		$p |= 0x80 if ($num2);
		$data .= sprintf("\\x%02x", $p);
		$length += 1;
	    }
	}
	if ($header) {
	    printf "extern gss_OID_desc $store;\n";
	    printf "#define $name (&$store)\n\n";
	} else {
	    printf "/* $name - $oid */\n";
	    printf "gss_OID_desc $store = { $length, \"$data\" };\n\n";
	}
    }

}

if ($header) {
    printf "#endif /* GSSAPI_GSSAPI_OID */\n";
}
