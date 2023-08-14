# pkt_analysis

Misc tools to assist in analysis of UM packet captures.

# Table of contents
<!-- mdtoc-start -->
<!-- TOC created by '../mdtoc/mdtoc.pl README.md' (see https://github.com/fordsfords/mdtoc) -->
<!-- mdtoc-end -->

# Introduction

When I get a packet capture from a customer, I often end up writing a Perl
program to answer whatever questions I have in my mind.
Frequently, I can see some anomoly just by skimming with Wireshark, and I want
to know if that anomoly happens frequently, on which transport sessions,
etc.

THESE TOOLS ARE EXAMPLE CODE, NOT INTENDED TO BE END USER TOOLS!
They might evolve on a day-to-day basis if I am working with a packet capture.
The proper use of these tools is to select one that comes reasonably close
to what you want, then make it a separate tool and evolve it to what you
want.

My general procedure is to first export the packet capture as a text file
with full dissections but without the summary lines.
Then I write perl code to scan the text file.
Note that this frequently means I have to modify Wireshark's set up so that
it recognizes the right packets as UM.
Also, if the packet capture comes from Corvil,
it's not unusual to see packets duplicated.
This is usually due to the presence of a firewall,
and Corvil captures on both sides of the firewall.
It's usually best to get rid of the duplicates by carefully selecting a
MAC address to key off of, then exporting only "displayed" packets.


# pkts.pl

Skeletal parser of Wireshark exported dissection text files.
Does no useful function, but contains the basic parsing for a number of fields.


# ooo_pkts.pl

A customer saw lots of out-of-order packets.
This tool (based on "pkts.pl") looks for transport sessions that saw
unrecoverable loss due to window advance.

