#! /usr/bin/env perl
use strict;
use warnings;
use Data::Dumper;
$Data::Dumper::Sortkeys = sub {[ sort { $_[0]{$a} <=> $_[0]{$b} } keys %{$_[0]} ]}; # sort keys by value
$Data::Dumper::Indent = 0;
$Data::Dumper::Terse = 1;
use Net::Pcap::Easy;
use Storable qw(lock_nstore lock_retrieve);
$Storable::canonical = 1;
use Proc::PID::File;
exit if Proc::PID::File->running();

my $file = "macs.dat";
my $iface= "enp3s0";
$iface = $ARGV[0] if defined($ARGV[0]);
my $interval = 60;
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

p"listening on $iface...\n";
%seen = %{ lock_retrieve $file } if -f $file;
p("loaded seen size: ".keys(%seen)."\n") if -f $file;
$SIG{'TERM'} = $SIG{'INT'} = sub {
    p"signal\n";
    $Data::Dumper::Indent = 1;
    p Dumper(\%seen);
    lock_nstore(\%seen, $file);
    exit;
};
p"loading OUI cache...\n";
load_cache("manuf");
my $npe = Net::Pcap::Easy->new(
    dev              => $iface,
    filter           => "",
    packets_per_loop => 10,
    bytes_to_capture => 64,
    promiscuous      => 1,

    default_callback => sub {
        my ($npe, $ether, $header ) = @_;
        my $mac = join ":", ($ether->{src_mac} =~ m/(..)/g);
        my $time=time;
        if ( !exists($seen{$mac}) ){
            p"$mac ";
            p("($header->{src_ip} <=> $header->{dest_ip}) ") if defined($header->{src_ip}) and defined($header->{dest_ip});
            # p Dumper($header)."\n";
            p"=> ";
            p Dumper(fetch_oui_from_cache($mac))."\n";
            $seen{$mac} = $time;
        }
    },
);
p"entering loop...\n";
1 while $npe->loop;
