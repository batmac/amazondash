#! /usr/bin/env perl
# Launch a specific sub when we see a specific mac address from a 
# list (<%macs>) on the <$iface> interface with a minimum number of
# seconds (<$interval>) between launches.
# Designed for the amazon dash button.
use strict;
use warnings;
use Net::Pcap::Easy;
use Proc::PID::File;
die "Already running!" if Proc::PID::File->running();

my $iface= "br0";
my $interval = 60;
my %macs = (
	 "a0:02:dc:c5:d8:69" => \&kraftdinner,
	 "74:da:38:2e:0a:26" => \&rpi,
 	 "00:9c:02:a0:3e:8b" => \&mc,
);

sub p {print @_};
my %timeout;
my @macs = map{ "ether src ". $_ } keys %macs;
my $filter = "( ".join(" or ", @macs)." )";
p"filter: $filter\n";
my $npe = Net::Pcap::Easy->new(
	dev              => $iface,
	filter           => $filter,
	packets_per_loop => 10,
	bytes_to_capture => 64,
	promiscuous      => 1,

	default_callback => sub {
		my ($npe, $ether ) = @_;
		my $mac = join ":", ($ether->{src_mac} =~ m/(..)/g);
		p"$mac sent something\n";
		my $time=time;
		if ( !exists($timeout{$mac}) or ($time - $timeout{$mac})>$interval ){
			#p"yes\n";
			$timeout{$mac} = $time;
			($macs{$mac} || sub {p"$mac error!!!\n"})->($mac);
		}
	},
);
p"entering loop...\n";
1 while $npe->loop;

sub rpi {
	my $mac = shift;
	p"$mac\n";
}
sub kraftdinner {
	p"hi button!\n";
}
sub mc {
	p"hi button!\n";
}
