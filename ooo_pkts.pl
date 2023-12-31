#!/usr/bin/env perl
# ooo_pkts.pl
#
# This code and its documentation is Copyright 2023 Informatica
# and licensed "public domain" style under Creative Commons "CC0":
#   http://creativecommons.org/publicdomain/zero/1.0/
# To the extent possible under law, the contributors to this project have
# waived all copyright and related or neighboring rights to this work.
# In other words, you can use this code for any purpose without any
# restrictions.  This work is published from: United States.  The project home
# is https://github.com/UltraMessaging/pkt_analysis

use strict;
use warnings;
use Getopt::Std;
use File::Basename;
use Carp;

# globals
my $tool = basename($0);

# process options.
use vars qw($opt_h $opt_o $opt_v);
getopts('ho:v') || mycroak("getopts failure");

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

my $prev_epoc_usec;

my %pkts;
my %pkt_times;
my %session_to_index;
my %low_sqns;
my %high_sqns;
my %high_trailing;
my %unrec;
my %dest_addrs;
my %dest_ports;
my %topic_id_low_sqns;  # session_id,topic_index
my %topic_id_high_sqns;  # session_id,topic_index
my %topic_id_pkts;

my $min_win_size = 999999999999;
my $max_win_size = 0;
my $max_trailing_dist = -1;
my $max_trailing_dist_info;

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
  #                 '    Destination Address: 239.192.69.22' (newer text)
  elsif ($iline =~ /^    Destination Address: (\d+\.\d+\.\d+\.\d+)\b/) {
    $dest_addr = $1;
    return;
  }
  #                 '    Destination: 239.192.69.22' (older text)
  elsif ($iline =~ /^    Destination: (\d+\.\d+\.\d+\.\d+)\b/) {
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
  ### print $out_fd "epoch_usec=$epoch_usec, frame=$frame, session_id=$session_id, transp_sqn=$transp_sqn, retrans=$retrans, topic_index=$topic_index, topic_sqn=$topic_sqn\n";

  $dest_ports{$dest_port} = 1;
  $dest_addrs{$dest_addr} = 1;
  if (defined($topic_id_low_sqns{"SID=$session_id,TIDX=$topic_index"})) {
    if ($topic_sqn < $topic_id_low_sqns{"SID=$session_id,TIDX=$topic_index"}) {
      $topic_id_low_sqns{"SID=$session_id,TIDX=$topic_index"} = $topic_sqn;
    }
  } else { $topic_id_low_sqns{"SID=$session_id,TIDX=$topic_index"} = $topic_sqn; }

  if (defined($topic_id_high_sqns{"SID=$session_id,TIDX=$topic_index"})) {
    if ($topic_sqn > $topic_id_high_sqns{"SID=$session_id,TIDX=$topic_index"}) {
      $topic_id_high_sqns{"SID=$session_id,TIDX=$topic_index"} = $topic_sqn;
    }
  } else { $topic_id_high_sqns{"SID=$session_id,TIDX=$topic_index"} = $topic_sqn; }

  if (defined($topic_id_pkts{"SID=$session_id,TIDX=$topic_index,SQN=$topic_sqn"})) {
    print $out_fd "Duplicate topic sqn, frame $frame\n";
  } else {
    $topic_id_pkts{"SID=$session_id,TIDX=$topic_index,SQN=$topic_sqn"} = "F=$frame,TSQN=$transp_sqn";
  }

  if (defined($prev_epoc_usec)) {
    if ($epoch_usec < $prev_epoc_usec) {
      print $out_fd "Time moved backward, frame $frame\n";
    }
    elsif (($epoch_usec - $prev_epoc_usec) > 500) {
      print $out_fd "Delay " . ($epoch_usec - $prev_epoc_usec) . " usec, frame $frame\n";
    }
  }
  $prev_epoc_usec = $epoch_usec;

  if (defined($low_sqns{$session_id})) {
    if ($transp_sqn < $low_sqns{$session_id}) {
      $low_sqns{$session_id} = $transp_sqn;
    }
  }
  else { $low_sqns{$session_id} = $transp_sqn; }

  if (defined($high_sqns{$session_id})) {
    if ($transp_sqn > $high_sqns{$session_id}) {
      $high_sqns{$session_id} = $transp_sqn;
    }
  }
  else { $high_sqns{$session_id} = $transp_sqn; }

  if (defined($high_trailing{$session_id})) {
    if ($trailing > $high_trailing{$session_id}) {
      $high_trailing{$session_id} = $trailing;
    }
  }
  else { $high_trailing{$session_id} = $trailing; }

  if ((($transp_sqn + 1) - $trailing) > $max_win_size) {
    $max_win_size = ($transp_sqn + 1) - $trailing;
  }
  if ((($transp_sqn + 1) - $trailing) < $min_win_size) {
    $min_win_size = ($transp_sqn + 1) - $trailing;
  }

  if (defined($pkts{"SID=$session_id,TSQN=$transp_sqn"})) {
    print $out_fd "Duplicate sqn, frame $frame\n";
  } else {
    $pkts{"SID=$session_id,TSQN=$transp_sqn"} = "F=$frame,TI=$topic_index,SQN=$topic_sqn";
    $pkt_times{"SID=$session_id,TSQN=$transp_sqn"} = $epoch_usec;
  }

  my $gap_low;
  for (my $i = $low_sqns{$session_id}; $i < $high_sqns{$session_id}; $i++) {
    if (! defined($pkts{"SID=$session_id,TSQN=$i"})) {
      if (! defined($gap_low)) {
        $gap_low = $i;
      }
      if ($i < $high_trailing{$session_id}) {
        if (! defined($unrec{"SID=$session_id,TSQN=$i"})) {  # only print once (first time).
          print $out_fd "gap sqn ($i) < high_trailing{$session_id} ($high_trailing{$session_id}), frame=$frame\n";
          $unrec{"SID=$session_id,TSQN=$i"} = -1;
        }
        if (($high_trailing{$session_id} - $i) > $max_trailing_dist) {
          $max_trailing_dist = $high_trailing{$session_id} - $i;
          $max_trailing_dist_info = "F=$frame,TSQN=$i,TRAIL=$high_trailing{$session_id}";
        }
      }
    }
  }
  #if (defined($gap_low)) {
  #  if (($transp_sqn - $gap_low) > 150) {
  #    print $out_fd ($transp_sqn - $gap_low) . " distance between $transp_sqn and $gap_low (F=$frame, SID=$session_id)\n";
  #  }
  #}

  if (defined($unrec{"SID=$session_id,TSQN=$transp_sqn"})) {
    assrt($unrec{"SID=$session_id,TSQN=$transp_sqn"} == -1);
    $unrec{"SID=$session_id,TSQN=$transp_sqn"} = "F=$frame,TI=$topic_index,SQN=$topic_sqn";
  }
}  # process_pkt


sub final {
  my $num_transport_sessions = 0;
  foreach my $sess_id (keys(%low_sqns)) {
    $num_transport_sessions++;
    my $hi_sqn = $high_sqns{$sess_id}; assrt(defined($hi_sqn));
    my $lo_sqn = $low_sqns{$sess_id}; assrt(defined($lo_sqn));
    my $num_msgs = ($hi_sqn - $lo_sqn) + 1;
    if ($num_msgs > 1) {
      my $hi_usec = $pkt_times{"SID=$sess_id,TSQN=$hi_sqn"}; assrt(defined($hi_usec));
      my $lo_usec = $pkt_times{"SID=$sess_id,TSQN=$lo_sqn"}; assrt(defined($lo_usec));
      my $duration_usec = $hi_usec - $lo_usec;
      my $rate = int(($num_msgs * 1000000) / $duration_usec);
      if (($num_msgs > 100) && ($duration_usec > 10000)) {
        print $out_fd "$rate msgs/sec for session $sess_id ($num_msgs over " . ($hi_usec - $lo_usec) . " usec)\n";
      }
    }
  }

  print $out_fd "max_win_size=$max_win_size, min_win_size=$min_win_size, max_trailing_dist=$max_trailing_dist (info=$max_trailing_dist_info)\n";
  print $out_fd "num_transport_sessions=$num_transport_sessions\n";

  my $cnt;

  print $out_fd "Unrecovered: ";
  $cnt = 0;
  foreach my $pkt_id (keys(%unrec)) {
    $cnt++;
    print $out_fd "unrec{$pkt_id}=$unrec{$pkt_id} ";
  }
  print $out_fd "(cnt=$cnt)\n";

  print $out_fd "Dest addrs: ";
  $cnt = 0;
  foreach my $addr (sort(keys(%dest_addrs))) {
    $cnt++;
    print $out_fd "$addr ";
  }
  print $out_fd "(cnt=$cnt)\n";

  print $out_fd "Dest ports: ";
  $cnt = 0;
  foreach my $port (sort(keys(%dest_ports))) {
    $cnt++;
    print $out_fd "$port ";
  }
  print $out_fd "(cnt=$cnt)\n";

  print $out_fd "Topic IDs: ";
  $cnt = 0;
  foreach my $topic (keys(%topic_id_low_sqns)) {
    $cnt++;
    print $out_fd "$topic ";
  }
  print $out_fd "(cnt=$cnt)\n";

  print $out_fd "Remaining gap counts\n";
  foreach my $session_id (keys(%low_sqns)) {
    my $num_gaps = 0;
    for (my $i = $low_sqns{$session_id}; $i < $high_sqns{$session_id}; $i++) {
      if (! defined($pkts{"SID=$session_id,TSQN=$i"})) {
        $num_gaps++;
        if ($opt_v) {
          print $out_fd "Missing pkt: SID=$session_id,TSQN=$i\n";
        }
      }
    }
    if ($num_gaps > 0) {
      print $out_fd "Session $session_id, num_gaps=$num_gaps\n";
    }
  }

  print $out_fd "Find topic-level gaps\n";
  foreach my $topic_id (keys(%topic_id_low_sqns)) {
    my $num_gaps = 0;
    for (my $i = $topic_id_low_sqns{$topic_id}; $i < $topic_id_high_sqns{$topic_id}; $i++) {
      if (! defined($topic_id_pkts{"$topic_id,SQN=$i"})) {
        $num_gaps++;
        if ($opt_v) {
          print $out_fd "Missing topic pkt: $topic_id,SQN=$i\n";
        }
      }
    }
    if ($num_gaps > 0) {
      print $out_fd "Topic $topic_id, num_gaps=$num_gaps\n";
    }
  }
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
    -v - verbose.
    file ... - zero or more input files.  If omitted, inputs from stdin.

__EOF__

  exit(0);
}  # help
