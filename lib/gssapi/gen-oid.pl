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
    printf "#include \"gssapi_mech.h\"\n\n";
}

my %tables;
my %types;

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

	my $num;

	$n = $#array;
	while ($n > 1) {
	    $num = $array[$n];

	    my $p = int($num % 128);
	    $data = sprintf("\\x%02x", $p) . $data;

	    $num = int($num / 128);

	    $length += 1;

	    while ($num > 0) {
		$p = int($num % 128) + 128;
		$num = int($num / 128);
		$data = sprintf("\\x%02x", $p) . $data;
		$length += 1;
	    }
	    $n--;
	}
	$num = int($array[0] * 40 + $array[1]);

	$data = sprintf("\\x%x", $num) . $data;
	$length += 1;

	if ($header) {
	    printf "extern GSSAPI_LIB_VARIABLE gss_OID_desc $store;\n";
	    printf "#define $name (&$store)\n\n";
	} else {
	    printf "/* $name - $oid */\n";
	    printf "gss_OID_desc GSSAPI_LIB_VARIABLE $store = { $length, \"$data\" };\n\n";
	}
    } elsif (/^desc\s+([\w]+)\s+(\w+)\s+(\"[^\"]*\")\s+(\"[^\"]*\")/) {
        my ($type, $oid, $short, $long) = ($1, $2, $3, $4);
	my $object = { type=> $type, oid => $oid, short => $short, long => $long };
	
	$tables{$oid} = \$object;
	$types{$type} = 1;
    }

}

foreach my $k (keys %types) {
    if (!$header) {
	print "struct _gss_oid_name_table _gss_ont_" . $k . "[] = {\n";
	foreach my $m (values %tables) {
	    if ($$m->{type} eq $k) {
		printf "  { %s, \"%s\", %s, %s },\n", $$m->{oid}, $$m->{oid}, $$m->{short}, $$m->{long};
	    }
	}
	printf "  { NULL }\n";
	printf "};\n\n";
	
    }
}

if ($header) {
    printf "#endif /* GSSAPI_GSSAPI_OID */\n";
}
