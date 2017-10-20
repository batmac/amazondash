#! /usr/bin/env perl
use strict;
use warnings;
use Data::Dumper;
$Data::Dumper::Sortkeys = sub {[ sort { $_[0]{$a} <=> $_[0]{$b} } keys %{$_[0]} ]}; # sort keys by value
$Data::Dumper::Indent = 0;
$Data::Dumper::Terse = 1;
use Net::Pcap::Easy;
use Net::MAC::Vendor;
use Storable qw(lock_nstore lock_retrieve);
$Storable::canonical = 1;
use Proc::PID::File;
exit if Proc::PID::File->running();

my $file = "macs.dat";
my $iface= "en0";
$iface = $ARGV[0] if defined($ARGV[0]);
my $interval = 60;
my %seen = (); 
sub p {print @_};
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
Net::MAC::Vendor::load_cache("oui.txt");
#Net::MAC::Vendor::load_cache(undef,"oui-fresh.txt");
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
			p Dumper(Net::MAC::Vendor::fetch_oui_from_cache($mac))."\n";
			$seen{$mac} = $time;
		}
	},
);
p"entering loop...\n";
 1 while $npe->loop;
