#! /usr/bin/env perl
use strict;
use warnings;
use Data::Dumper;
$Data::Dumper::Sortkeys = sub {[ sort { $_[0]{$a} <=> $_[0]{$b} } keys $_[0] ]}; # sort keys by value@
use Net::Pcap::Easy;
use Storable qw(lock_nstore lock_retrieve);
$Storable::canonical = 1;
use Proc::PID::File;
exit if Proc::PID::File->running();

my $file = "macs.dat";
my $iface= "br0";
my $interval = 60;
my %seen = (); 
sub p {print @_};
%seen = %{ lock_retrieve $file } if -f $file;
p("loaded seen size: ".keys(%seen)."\n") if -f $file;
$SIG{'TERM'} = $SIG{'INT'} = sub { p"signal\n"; p Dumper(\%seen); lock_nstore(\%seen, $file); exit;};
my $npe = Net::Pcap::Easy->new(
	dev              => $iface,
	filter           => "",
	packets_per_loop => 10,
	bytes_to_capture => 64,
	promiscuous      => 1,

	default_callback => sub {
		my ($npe, $ether ) = @_;
		my $mac = join ":", ($ether->{src_mac} =~ m/(..)/g);
		my $time=time;
		if ( !exists($seen{$mac}) ){
			p"$mac seen.\n";	
			$seen{$mac} = $time;
		}
	},
);
p"entering loop...\n";
 1 while $npe->loop;
