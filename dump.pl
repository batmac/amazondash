#! /usr/bin/env perl
use strict;
use warnings;
use Storable qw(lock_nstore lock_retrieve);

my $file = "macs.dat";
my %seen = (); 
sub p {print @_};

my %cache;

sub load_cache($) {
 
    # parses https://gitlab.com/wireshark/wireshark/raw/master/manuf
    # this function ignores all prefixes longer than 3 bytes (ie 24 bit)
    open my $FH, shift;
    my ($nlines,$nread)=(0,0);
    while (<$FH>) {
        $nlines++;
        next if /^#/;
        next if /^\s*$/;
        chomp;
        my @l = split /\s+/, $_,3;
        $cache{$l[0]} = $l[1];
        if (defined ($l[2])) {
            $cache{$l[0]} = "$l[1] ($l[2])";
        }
        $nread++;
    }

    p "$nlines lines, $nread read\n";
    close($FH);
    return $nread;
}

sub fetch_oui_from_cache($){
    my $mac = shift;
    my $macprefix = uc(substr($mac,0,8));
    if (defined $cache{$macprefix}) {
        return $cache{$macprefix};
    } else {
        return "<UNKNOWN>";
    }
}

%seen = %{ lock_retrieve $file } if -f $file;
p("loaded seen size: ".keys(%seen)."\n") if -f $file;
p"loading OUI cache...\n";
load_cache("manuf");
foreach my $mac (keys %seen) {
	p"$mac => ".fetch_oui_from_cache($mac)."\n";
}
