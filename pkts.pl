#!/usr/bin/env perl
# pkts.pl - skeletal parser for Wireshark text dissections.
#
# This code and its documentation is Copyright 2023 Informatica
# and licensed "public domain" style under Creative Commons "CC0":
#   http://creativecommons.org/publicdomain/zero/1.0/
# To the extent possible under law, the contributors to this project have
# waived all copyright and related or neighboring rights to this work.
# In other words, you can use this code for any purpose without any
# restrictions.  This work is published from: United States.  The project home
# is https://github.com/UltraMessaging/ooo_pkts.pl

use strict;
use warnings;
use Getopt::Std;
use File::Basename;
use Carp;

# globals
my $tool = basename($0);

# process options.
use vars qw($opt_h $opt_o);
getopts('ho:') || mycroak("getopts failure");

if (defined($opt_h)) {
  help();
}

my $out_fd;
if (defined($opt_o)) {
  open($out_fd, ">", $opt_o) or mycroak("Error opening '$opt_o': $!");
} else {
  $out_fd = *STDOUT;
}

my $sect = "";
# These are the values to extract from the text dump of the packet.
my $frame;
my $epoch_usec;
my $dest_port;
my $dest_addr;
my $session_id;
my $transp_sqn;
my $trailing;
my $retrans;
my $topic_index;
my $topic_sqn;

my %pkts;

# Main loop; read each line in each file.
while (<>) {
  chomp;  # remove trailing \n
  s/\r//g;

  #
  # Detect transitions between sections.
  #

  if (/^Frame (\d+):/) {
    # New frame; clear everything.
    undef $epoch_usec;  # total usec since start of 2023
    undef $frame;
    undef $dest_port;
    undef $dest_addr;
    undef $session_id;
    undef $transp_sqn;
    undef $trailing;
    undef $retrans;
    undef $topic_index;
    undef $topic_sqn;

    $frame = $1;
    $sect = "Frame";
    next;
  }
  elsif (/^LBT-RM Protocol:/) {
    $sect = "LBT-RM Protocol";
    next;
  }
  elsif (/^LBMC Protocol/) {
    $sect = "LBMC Protocol";
    next;
  }
  elsif (/^    Data \(/) {
    # Done parsing a dissected frame; process the full packet.
    process_pkt();
    $sect = "";
    next;
  }

  #
  # Not a section header. Do the section-specific processing.
  #

  if ($sect eq "Frame") { process_frame($_); }
  elsif ($sect eq "LBT-RM Protocol") { process_lbt_rm_protocol($_); }
  elsif ($sect eq "LBMC Protocol") { process_lbmc_protocol($_); }
  else { assrt($sect eq ""); }  # between frames.

  ### print $out_fd "??? File: $ARGV, line: $.: '$_'\n";
} continue {  # This continue clause makes "$." give line number within file.
  close ARGV if eof;
}

final();

# All done.
exit(0);


# End of main program, start subroutines.


# Process dissection line in the "frame" section.
sub process_frame {
  my ($iline) = (@_);

  #              '    Epoch Time: 1691675045.732338000 seconds'
  if ($iline =~ /^    Epoch Time: (\d+)\.(\d+) seconds/) {
    my $epoch_sec = $1;
    $epoch_usec = ($2 / 1000) + ($epoch_sec * 1000000);
    return;
  }
  #                 '    Frame Number: 247'
  elsif ($iline =~ /^    Frame Number: (\d+)\b/) {
    $frame = $1;
    return;
  }
  #                 '    Destination Address: 239.192.69.22'
  elsif ($iline =~ /^    Destination Address: (\d+\.\d+\.\d+\.\d+)\b/) {
    $dest_addr = $1;
    return;
  }
  #                 '    Destination Port: 21345'
  elsif ($iline =~ /^    Destination Port: (\d+)\b/) {
    $dest_port = $1;
    return;
  }
}  # process_frame


# Process dissection line in the "lbt-rm" section.
sub process_lbt_rm_protocol {
  my ($iline) = (@_);

  #              '        Session ID: 0xa94eab85'
  if ($iline =~ /^        Session ID: (0x\w+)\b/) {
    $session_id = $1;
    return;
  }
  #                 '        Sequence Number: 0x00663ff2 (6701042)'
  elsif ($iline =~ /^        Sequence Number: 0x\w+ \((\d+)\)/) {
    $transp_sqn = $1;
    return;
  }
  #                 '        Trailing Edge Sequence Number: 0x00a47830 (10778672)'
  elsif ($iline =~ /^        Trailing Edge Sequence Number: 0x\w+ \((\d+)\)/) {
    $trailing = $1;
    return;
  }
  #                 '            ..0. .... = Retransmission: Not set'
  elsif ($iline =~ /^            \.\.(\d)\. \.\.\.\. = Retransmission:/) {
    $retrans = $1;  assrt($retrans == 0);
    return;
  }
}  # process_lbt_rm_protocol


# Process dissection line in the "lbmc" section.
sub process_lbmc_protocol {
  my ($iline) = (@_);

  #              '    Topic Index: 1886811419 (0x7076751b)'
  if ($iline =~ /^    Topic Index: (\d+) /) {
    $topic_index = $1;
    return;
  }
  #                 '    Sequence Number: 5563937'
  elsif ($iline =~ /^    Sequence Number: (\d+)\b/) {
    $topic_sqn = $1;
    return;
  }
}  # process_lbmc_protocol


sub process_pkt {
  print $out_fd "epoch_usec=$epoch_usec, frame=$frame, session_id=$session_id, transp_sqn=$transp_sqn, retrans=$retrans, topic_index=$topic_index, topic_sqn=$topic_sqn\n";
}  # process_pkt


sub final {
  print $out_fd "Final processing:\n";
}  # final


sub mycroak {
  my ($msg) = @_;

  if (defined($ARGV)) {
    # Print input file name and line number.
    croak("Error (use -h for help): input_file:line=$ARGV:$., $msg");
  } else {
    croak("Error (use -h for help): $msg");
  }
}  # mycroak


sub assrt {
  my ($assertion, $msg) = @_;

  if (! ($assertion)) {
    if (defined($msg)) {
      mycroak("Assertion failed, $msg");
    } else {
      mycroak("Assertion failed");
    }
  }
}  # assrt


sub help {
  my($err_str) = @_;

  if (defined $err_str) {
    print "$tool: $err_str\n\n";
  }
  print <<__EOF__;
Usage: $tool [-h] [-o out_file] [file ...]
Where ('R' indicates required option):
    -h - help
    -o out_file - output file (default: STDOUT).
    file ... - zero or more input files.  If omitted, inputs from stdin.

__EOF__

  exit(0);
}  # help
