use Getopt::Long;
use Pod::Usage;
use feature "switch";

my $def_name = '';
my $vs_name = '';
my $show_help = 0;

my %syms;

my $def_only = 0;
my $vs_only = 0;

GetOptions ("def=s" => \$def_name,
	    "vs=s" => \$vs_name,
	    "help|?" => \$show_help) or pod2usage( -exitval => 2,
						   -verbose => 3 );
pod2usage( -exitval => 1,
	   -verbose => 3 ) if $show_help or !$def_name or !$vs_name;

open (my $def, '<', $def_name) or die $!;
open (my $vs, '<', $vs_name) or die $!;

# First go through the version-script

my $global = 0;

while(<$vs>)
{
    next unless m/^([^#]+)/;

    @a = split(/\s+|({|})/,$1);

    for $f (@a) {
	given ($f) {
	    when (/global\:/) { $global = 1; }
	    when (/{|}|.*\:/) { $global = 0; }
	    when (/(.*)\;/ and $global == 1) {
		$syms{$1} = 1;
	    }
	}
    }
}

while(<$def>)
{
    next if m/^#/;
    next unless m/^;!([^;]+)/ or m/^([^;]+);?(!?)/;

    @a = split(/\s+/, $1);

    for $f (@a) {
	next if $f =~ /EXPORTS/ or $f =~ /DATA/ or not $f;

	if (not exists $syms{$f} and not $2) {
	    print "$f: Only in DEF\n";
	    ++$def_only;
	}
	delete $syms{$f};
    }
}

#while (($k,$v) = each %syms) {
for $k (sort keys %syms) {
    print "$k: Only in VS\n";
    ++$vs_only;
}

close($def);
close($vs);

if ($def_only or $vs_only) {
    print "\nMismatches found.\n";
    exit(1);
}

__END__

=head1 NAME

w32-sync-exported-symbols.pl - Synchronize Windows .def with version-script

=head1 SYNOPSIS

w32-sync-exported-symbols.pl {options}

  Options:
    --def        Name of .def file
    --vs         Name of version-script file

=head1 DESCRIPTION

Verifies that all the symbols exported by the version-script is also
accounted for in the .def file.  Also checks that no extra symbols are
exported by the .def file unless they are marked as safe.

=cut

