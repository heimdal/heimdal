#!/usr/bin/perl

use strict;
use warnings;

my $lines = 0;

while (<STDIN>) {
    next unless /^\s*puts\("(.*)"\);\s*$/;

    my $line = decode_string($1);
    print "$line\n";
    $lines++;
}

die "no roken header lines found\n" unless $lines;

sub decode_string
{
    my ($string) = @_;
    my $decoded = "";

    while (length $string) {
	my $char = substr($string, 0, 1, "");
	if ($char ne "\\") {
	    $decoded .= $char;
	    next;
	}

	die "trailing backslash in C string\n" unless length $string;
	$char = substr($string, 0, 1, "");
	if ($char eq "n") {
	    $decoded .= "\n";
	} elsif ($char eq "r") {
	    $decoded .= "\r";
	} elsif ($char eq "t") {
	    $decoded .= "\t";
	} elsif ($char eq "f") {
	    $decoded .= "\f";
	} elsif ($char eq "b") {
	    $decoded .= "\b";
	} elsif ($char eq "a") {
	    $decoded .= "\a";
	} elsif ($char eq "v") {
	    $decoded .= "\013";
	} elsif ($char =~ /[0-7]/) {
	    my $octal = $char;
	    $octal .= $1 while length($octal) < 3 &&
		$string =~ s/^([0-7])//;
	    $decoded .= chr oct $octal;
	} elsif ($char eq "x") {
	    $string =~ s/^([0-9a-fA-F]+)//
		or die "empty hexadecimal escape in C string\n";
	    $decoded .= chr hex $1;
	} else {
	    $decoded .= $char;
	}
    }

    return $decoded;
}
