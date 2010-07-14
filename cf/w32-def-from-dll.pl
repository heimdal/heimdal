my $show_module_name = 1;
my $use_indent = 1;
my $strip_leading_underscore = 0;
my $module_name = "";
my %target_exports = ();
my %local_exports = ();

sub build_target_exports_list($)
{
    $fn = shift;

    print STDERR "Processing defs from file [$fn]\n";

    open(SP, '-|', "dumpbin /exports \"".$fn."\"") or die "Can't open pipe for $fn";

  LINE:
    while (<SP>) {
#        112   6F 00071CDC krb5_encrypt_size

	/^ +([[:digit:]]+)\s+[[:xdigit:]]+\s[[:xdigit:]]{8,}\s+(\S+)(?:| = (\S*))$/ && do {
	    my ($ordinal, $symbol, $in) = ($1, $2, $3);

	    if ($in eq "") { $in = $symbol };
	    $target_exports{$symbol} = $in;
	};
    }

    close SP;
}

# Dump all symbols for the given dll file that are defined and have
# external scope.

sub build_glue_exports_list($)
{
    $fn = shift;

    print STDERR "Opening dump of DLL [$fn]\n";

    open(SP, '-|', "dumpbin /exports \"".$fn."\"") or die "Can't open pipe for $fn";

  LINE:
    while (<SP>) {
#        112   6F 00071CDC krb5_encrypt_size

	/^ +([[:digit:]]+)\s+[[:xdigit:]]+\s[[:xdigit:]]{8,}\s+(\S+)(?:| = (\S*))$/ && do {
	    my ($ordinal, $symbol, $in) = ($1, $2, $3);

	    if ($strip_leading_underscore && $symbol =~ /_(.*)/) {
		$symbol = $1;
	    }
	    if (exists $local_exports{$symbol}) {
		print "\t".$symbol;
		print " = ".$local_exports{$symbol};
		if ($in ne $local_exports{$symbol} and $in ne "") {
		    print STDERR "Incorrect calling convention for local $symbol\n";
		    print STDERR "  ".$in." != ".$local_exports{$symbol}."\n";
		}
		print "\t@".$ordinal."\n";
	    } elsif (exists $local_exports{"SHIM_".$symbol}) {
		print "\t".$symbol;
		print " = ".$local_exports{"SHIM_".$symbol};
		print "\t@".$ordinal."\n";
	    } elsif (exists $target_exports{$symbol}) {
		print "\t".$symbol;
		print " = ".$module_name;
		if ($in ne $target_exports{$symbol} and $in ne "") {
		    print STDERR "Incorrect calling convention for $symbol\n";
		    print STDERR "  ".$in." != ".$target_exports{$symbol}."\n";
		}
		my $texp = $target_exports{$symbol};
		if ($texp =~ /^_([^@]+)$/) { $texp = $1; }
		print $texp."\t@".$ordinal."\n";
	    } else {
		print STDERR "Symbol not found: $symbol\n";
	    }
	};
    }

    close SP;
}

sub build_local_exports_list($)
{
    $fn = shift;

    print STDERR "Opening dump of object [$fn]\n";

    open(SP, '-|', "dumpbin /symbols \"".$fn."\"") or die "Can't open pipe for $fn";

  LINE:
    while (<SP>) {
	# 009 00000010 SECT3  notype ()    External     | _remove_error_table@4
	m/^[[:xdigit:]]{3,}\s[[:xdigit:]]{8,}\s(\w+)\s+\w*\s+(?:\(\)|  )\s+(\w+)\s+\|\s+(\S+)$/ && do {
	    my ($section, $visibility, $symbol) = ($1, $2, $3);

	    if ($section ne "UNDEF" && $visibility eq "External") {

		my $exp_name = $symbol;

		if ($symbol =~ m/^_(\w+)(?:@.*|)$/) {
		    $exp_name = $1;
		}

		if ($symbol =~ m/^_([^@]+)$/) {
		    $symbol = $1;
		}

		$local_exports{$exp_name} = $symbol;
	    }
	};
    }

    close SP;
}

sub process_file($)
{
    $fn = shift;

    if ($fn =~ m/\.dll$/i) {
	build_glue_exports_list($fn);
    } elsif ($fn =~ m/\.obj$/i) {
	build_local_exports_list($fn);
    } else {
	die "File type not recognized for $fn.";
    }
}

sub use_response_file($)
{
    $fn = shift;

    open (RF, '<', $fn) or die "Can't open response file $fn";

    while (<RF>) {
	/(\S+)/ && do {
	    process_file($1);
	}
    }
    close RF;
}

print "EXPORTS\n";

for (@ARGV) {
    ARG: {
	/-m(.*)/ && do {
	    $module_name = $1.".";
	    last ARG;
	};

	/-e(.*)/ && do {
	    build_target_exports_list($1);
	    last ARG;
	};

	/@(.*)/ && do {
	    use_response_file($1);
	    last ARG;
	};

	process_file($_);
    }
}
