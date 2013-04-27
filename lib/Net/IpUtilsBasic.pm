package Net::IPUtilsBasic;

use strict;
use warnings;
use Carp qw/croak/;

require Exporter;
our @ISA       = qw/Exporter/;
our $VERSION   = '0.01';

our @EXPORT    = qw/isClassAddrA
                    isClassAddrB
                    isClassAddrC
                    isClassAddrD
                    isClassAddrE
                    dec2binIpAddr
                    bin2decIpAddr/;

our @EXPORT_OK = qw/getAddrMaskDefault
                    getAddrClass
                    isValidMask
                    extendMaskByBits
                    calcSubnetsNHosts
                    getBroadcastAddr/;

our %EXPORT_TAGS = ('class'   => [qw/isClassAddrA isClassAddrB isClassAddrC
                                  isClassAddrD isClassAddrE getAddrClass/],
                    'convert' => [qw/dec2binIpAddr bin2decIpAddr/]);

use constant { 'A' => qr'^0',
               'B' => qr'^10',
               'C' => qr'^110',
               'D' => qr'^1110',
               'E' => qr'^11110',
               'MASKA' => '255.0.0.0',
               'MASKB' => '255.255.0.0',
               'MASKC' => '255.255.255.0',
               'IPREGEXP' => qr'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$',
             };

sub isClassAddrA {
  my ($addr, $dec) = @_;

  !$dec && _validateIp(&bin2decIpAddr($addr));
  $dec && ($addr = &dec2binIpAddr($addr));

  return 1 if($addr =~ A);
}

sub isClassAddrB {
  my ($addr, $dec) = @_;

  !$dec && _validateIp(&bin2decIpAddr($addr));
  $dec && ($addr = &dec2binIpAddr($addr));

  return 1 if($addr =~ B);
}

sub isClassAddrC {
  my ($addr, $dec) = @_;

  !$dec && _validateIp(&bin2decIpAddr($addr));
  $dec && ($addr = &dec2binIpAddr($addr));

  return 1 if($addr =~ C);
}

sub isClassAddrD {
  my ($addr, $dec) = @_;

  !$dec && _validateIp(&bin2decIpAddr($addr));
  $dec && ($addr = &dec2binIpAddr($addr));

  return 1 if($addr =~ D);
}

sub isClassAddrE {
  my ($addr, $dec) = @_;

  !$dec && _validateIp(&bin2decIpAddr($addr));
  $dec && ($addr = &dec2binIpAddr($addr));

  return 1 if($addr =~ E);
}

sub getAddrMaskDefault {
  my ($addr, $dec) = @_;

  $dec && ($addr = &dec2binIpAddr($addr));

  my ($class) = getAddrClass($addr);

  my $mask = eval 'MASK'.$class;

  return $mask;
}

sub getAddrClass {
  my ($addr, $dec) = @_;

  !$dec && _validateIp($addr);

  $dec && ($addr = &dec2binIpAddr($addr));

  my $class = (($addr =~ A)?'A'
                :($addr =~ B)?'B'
                   :($addr =~ C)?'C'
                      :($addr =~ D)?'D'
                         :($addr =~ E)?'E'
                            :undef);

  return $class;
}

sub dec2binIpAddr {
  my ($addr) = @_;

  _validateIp($addr);

  my @octets = split /\./,$addr;

  map {$_ = sprintf '%08b', $_} @octets;

  return join '.',@octets;
}

sub bin2decIpAddr {
  my ($addr) = @_;
  my @octets = split /\./, $addr;

  map {$_ = oct "0b$_"} @octets;

  my $decAddr = join '.',@octets;

  _validateIp($decAddr);

  return $decAddr;
}

sub _validateIp {
  my ($addr) = @_;

  ($addr =~ /^[01.]*$/) && ($addr = &bin2decIpAddr($addr));
  my $validate = sub { map { return 0 if ( $_ > 255);}@_; return 1;};

  if(($addr =~ IPREGEXP) && $validate->($1,$2,$3,$4)) {
      return 1;
  }
  else {
      croak "$addr is not a valid IP address";
  }
}

sub isValidMask {
  my ($addr, $dec) = @_;

  $dec && ($addr = &dec2binIpAddr($addr));

  my ($prefix) = ($addr =~ /(.*1)/);

  ($prefix =~ /0/)?return 0:return 1;
}

sub extendMaskByBits {
  my ($mask,$noBits,$dec) = @_;

  $dec && ($mask = &dec2binIpAddr($mask));

  return $mask if(!$noBits);

  croak "Bits $noBits is invalid!!" if ($noBits !~ /^\d+$/ || $noBits > 24);
  croak "Mask $mask invalid!!" if (! isValidMask($mask));

  for (1..$noBits) {
      $mask =~ s/0/1/;
  }

  return $mask;
}

sub calcSubnetsNHosts {
  my ($addr,$borrow,$dec) = @_;

  !$dec && _validateIp($addr);
  $dec && ($addr = &dec2binIpAddr($addr));

  my $defaultMask = getAddrMaskDefault($addr);

  my $extendedMask = extendMaskByBits($defaultMask,$borrow,1);

  $borrow = 0 if(!defined $borrow);

  my $numSubnets = 2 ** $borrow;

  my $numZeros = ($extendedMask =~ s/0//g) || 0;
  my $numHosts = 2 ** $numZeros - 2;

  return ($numSubnets, $numHosts);
}

sub getBroadcastAddr {
  my ($addr, $defaultMask, $subnetMask, $dec) = @_;

  $defaultMask && isValidMask($defaultMask,$dec);
  !$defaultMask && ($defaultMask = getAddrMaskDefault($addr,$dec));

  $subnetMask && isValidMask($subnetMask,$dec);
  $dec && ($addr = &dec2binIpAddr($addr)) 
       && ($defaultMask = &dec2binIpAddr($defaultMask))
       && ($subnetMask = &dec2binIpAddr($subnetMask));

  my $subnetMaskOnBits = ($subnetMask =~ s/1/1/g);
  my $defaultMaskOnBits = ($defaultMask =~ s/1/1/g);
  my $numSubnetBits = ($subnetMaskOnBits - $defaultMaskOnBits);

  croak "Default mask : $defaultMask and/or Subnet mask : $subnetMask incorrect!!" if($numSubnetBits !~/^\d+$/);

  my $numHostBits = 32 - $subnetMaskOnBits;
  my $numHostAddrs = 2 ** $numHostBits;

  my $numSubnets = 2 ** $numSubnetBits;

  my @broadcastAddrs;

  for (0..($numSubnets-1)) {
      push @broadcastAddrs, bin2decIpAddr ($addr);
      $addr = _incrIpAddr($addr, $numHostAddrs);
  }
  return (@broadcastAddrs);
}

sub _incrIpAddr {
  my ($addr, $incr) = @_;
  $addr = bin2decIpAddr($addr);

  my ($o4,$o3,$o2,$o1) = split /\./,$addr;

  $o1 += $incr;
  if($o1 <= 255) {
      return dec2binIpAddr("$o4.$o3.$o2.$o1");
  }
  else {
      $incr = $o1 - 255;
      $o1 = 255;

      $o2 += $incr;
      if ($o2 <= 255) {
          return dec2binIpAddr("$o4.$o3.$o2.$o1");
      }
      else {
          $incr = $o2 - 255;
          $o2 = 255;

          $o3 += $incr;
          if($o3 <= 255) {
              return dec2binIpAddr("$o4.$o3.$o2.$o1");
          }
          else {
              $incr = $o3 - 255;
              $o3 = 255;

              $o4 += $incr;
              return dec2binIpAddr("$o4.$o3.$o2.$o1");
          }
      }
   }
}

1;

=head1 NAME

Net::IPUtilsBasic - Common useful routines like converting decimal address to binary and vice versa, determining address class,
                    determining default mask, subnets and hosts and broadcast addresses for hosts in subnet.

=head1 SYNOPSIS

  use Net::IPUtilsBasic;                       ## subroutines isClassAddrA-E, bin2decIpAddr, dec2binIpAddr
  use Net::IPUtilsBasic qw/:class/;            ## subroutines isClassAddrA-E, getAddrClass
  use Net::IPUtilsBasic qw/:convert/;          ## subroutines bin2decIpAddr, dec2binIpAddr 
  use Net::IPUtilsBasic qw/getAddrMaskDefault 
                           getAddrClass
                           isValidMask
                           extendMaskByBits
                           calcSubnetsNHosts
                           getBroadcastAddr    ## Explicit inclusions

  isClassAddrA('127.0.32.45',1);
  isClassAddrA('00001111.11110010.00100100.10000001');

  dec2binIpAddr('128.0.0.56');
  bin2decIpAddr('10001000.10100001.00010101.00000001');

  getAddrMaskDefault('124.45.0.0',1);
  getAddrMaskDefault('10000000.00000001.01010101.10000001');

  getAddrClass('124.45.0.0',1);
  getAddrClass('00001111.11110010.00100100.10000001');

  isValidMask('255.255.252.0',1);
  isValidMask('11111111.00000000.00000000.00000000');

  extendMaskByBits('255.255.0.0',2,1);
  extendMaskByBits('11111111.00000000.00000000.00000000',2);

  calcSubnetsNHosts('128.0.0.1',4,1);
  calcSubnetsNHosts('10001000.10100001.00010101.00000001',4);
                           
  getBroadcastAddr('198.23.16.0','255.255.255.240','255.255.255.252',1);
  getBroadcastAddr('10000000.00000001.01010101.10000001',
                   '11111111.11111111.11111111.11110000',
                   '11111111.11111111.11111111.11111100',);

=head1 ABSTRACT

  This module tries provide the basic functionalities related to IPv4 addresses.
  Address class, subnet masks, subnet addresses, broadcast addresses can be deduced
  using the given methods. Ip addresses passed are also validated implicitly.

  Provision has been given to specify IP addresses in either dotted decimal notation
  or dotted binary notation, methods have been provided for conversion to-from these
  to notations which are internally used by other methods too.

=head1 METHODS

=head2 isClassAddrA,isClassAddrB,isClassAddrC,isClassAddrD,isClassAddrE

  isClassAddrA(<addr in decimal/binary>,<true if addr is decimal>) : returns 1 if true
  eg.
  isClassAddrA('127.0.32.45',1);
  isClassAddrA('00001111.11110010.00100100.10000001');

=head2 dec2binIpAddr

  dec2binIpAddr(<ip addr in dotted decimal notation>) : returns ip in binary dotted notation
  eg.
  dec2binIpAddr('128.0.0.56');

=head2 bin2decIpAddr

  bin2decIpAddr(<ip addr in dotted binary notation>) : returns ip in decimal dotted notation
  eg.
  bin2decIpAddr('10001000.10100001.00010101.00000001');

=head2 getAddrMaskDefault

  getAddrMaskDefault(<ip addr in decimal/binary notation>,<true if addr is decimal>) : returns default subnet mask in dotted decimal notation
  eg.
  getAddrMaskDefault('124.45.0.0',1); >> 255.0.0.0
  getAddrMaskDefault('10000000.00000001.01010101.10000001'); >> 255.0.0.0

=head2 getAddrClass

  getAddrClass(<ip addr in decimal/binary notation>,<true if addr is decimal>)) : returns class (A/B/C/D/E) of ip address
  eg.  
  getAddrClass('124.45.0.0',1);
  getAddrClass('00001111.11110010.00100100.10000001');

=head2 isValidMask

  isValidMask(<ip addr in decimal/binary notation>,<true if addr is decimal>)) : returns 1 if valid mask
  eg.
  isValidMask('255.255.252.0',1);
  isValidMask('11111111.00000000.00000000.00000000');

=head2 extendMaskByBits

  extendMaskByBits(<ip addr in decimal/binary notation>,<no.of bits to extend>,<true if addr is decimal>))
    : returns mask after extending/turning on given no. of bits after the already on bits of the mask
  eg.
  extendMaskByBits('255.255.0.0',2,1); >> 255.255.192.0
  extendMaskByBits('11111111.00000000.00000000.00000000',2); >> 11111111.11000000.00000000.00000000

=head2 calcSubnetsNHosts
  
  calcSubnetsNHosts(ip addr in decimal/binary notation>,no. of borrowed bits,<true if addr is decimal>))
    : returns (no. of subnets, no. of hosts)
  eg.
  calcSubnetsNHosts('128.0.0.1',4,1);
  calcSubnetsNHosts('10001000.10100001.00010101.00000001',4);

=head2 getBroadcastAddr

  getBroadcastAddr(<ip addr in decimal/binary notation>,
                   <default mask in decimal/binary notation>,
                   <subnet mask in decimal/binary notation>,
                   <true if addr is decimal>) : returns broadcast addresses after subnetting as a list
  eg.
  getBroadcastAddr('198.23.16.0','255.255.255.240','255.255.255.252',1); >> ('198.23.16.0','198.23.16.4','198.23.16.8','198.23.16.12')
  getBroadcastAddr('10000000.00000001.01010101.10000001',
                   '11111111.11111111.11111111.11110000',
                   '11111111.11111111.11111111.11111100',);

=head1 CAVEAT

  IPv4 only

=head1 Similar Modules

  Net::IP, Net::IpAddr etc.

=head1 SUPPORT

  debashish@cpan.org

=head1 ACKNOWLEDGEMENTS

=head1 COPYRIGHT & LICENSE

Copyright 2013 Debashish Parasar, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut
