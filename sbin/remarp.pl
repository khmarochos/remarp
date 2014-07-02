#!/usr/bin/perl
#
#   $Id: remarp.pl,v 1.2 2003/04/10 09:26:05 melnik Exp $
#
#   remarp, Collects, stores and compares ARP-tables from remote devices
#   Copyright (C) 2003  V.Melnik <melnik@raccoon.kiev.ua>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

use strict;
use POSIX qw(setsid strftime);
use FindBin qw($Bin);
use Net::SNMP;

use lib "$Bin/../lib";

use remarp::config;
use remarp::configure;

my $timestamp = time;

print(
    "* Remote ARPWatcher v$VERSION started at " .
    strftime("%d-%m-%Y %H:%M:%S", localtime($timestamp)) .
    "\n"
);

my $config = remarp::configure->new();
unless (defined($config)) {
    exit(1);
}
if ($config->{'help'}) {
    exit;
} elsif ($config->{'gnu'}) {
    exit;
} elsif ($config->{'version'}) {
    exit;
}

# check pid-file
if (-e $config->{'pid_file'}) {
    if ((stat($config->{'pid_file'}))[8] >= $timestamp - 3600) {
        die("Found a pid-file '$config->{'pid_file'}', is it my brother?");
    } else {
        warn("Found a stale lock-file '$config->{'pid_file'}', ignoring it");
    }
}

# set pid-file
unless (open(PF, ">$config->{'pid_file'}")) {
    die("Can't open(): $!");
}
print(PF $$);
unless (close(PF)) {
    warn("Can't close(): $!");
}

#
$SIG{'HUP'}     = \&signal_main;
$SIG{'TERM'}    = \&signal_main;
$SIG{'QUIT'}    = \&signal_main;
$SIG{'INT'}     = \&signal_main;
#
my %children_list;
my $shutdown;
foreach my $device (@{$config->{'devices'}}) {
    #
    last if ($shutdown);
    #
    if (scalar(values(%children_list)) >= $config->{'max_children'}) {
        catch_child(\%children_list);
    }
    #
    my $device_comm;
    my $device_addr;
    my $device_port;
    if ($device =~ /^(([0-9a-z\.\_\-]+)@)?([0-9a-z\-][0-9a-z\.\-]+)(:([0-9]+))?$/i) {
        $device_comm = defined($2) ? $2 : 'public';
        $device_addr = $3;
        $device_port = defined($5) ? $5 : 161;
    } else {
        warn("Invalid device '$device'");
        next;
    }
    #
    my $new_pid;
    if (defined($new_pid = fork)) {
        if ($new_pid) {
            $children_list{$new_pid} = $device_addr;
        } else {
            unless (setsid) {
                die("Can't setsid(): $!");
            }
            $SIG{'HUP'}     = \&signal_child;
            $SIG{'TERM'}    = \&signal_child;
            $SIG{'QUIT'}    = \&signal_child;
            $SIG{'INT'}     = \&signal_child;
            getarp($config, $device_comm, $device_addr, $device_port);
            $SIG{'HUP'}     = 'DEFAULT';
            $SIG{'TERM'}    = 'DEFAULT';
            $SIG{'QUIT'}    = 'DEFAULT';
            $SIG{'INT'}     = 'DEFAULT';
            exit;
        }
    } else {
        warn("Can't fork(): $!");
    }
}
#
while (scalar(values(%children_list))) {
    catch_child(\%children_list);
}
#
$SIG{'HUP'}     = 'DEFAULT';
$SIG{'TERM'}    = 'DEFAULT';
$SIG{'QUIT'}    = 'DEFAULT';
$SIG{'INT'}     = 'DEFAULT';

foreach my $file_new (glob("$config->{'spool'}/*.new")) {
    #
    my $file_old = $file_new; $file_old =~ s/\.new$//;
    my $device = $file_old; $device =~ s/^.*\/([0-9a-z\-][0-9a-z\.\-]+)$/$1/i;
    #
    my %arptable_old;
    my %arptable_new;
    #
    unless (open(FILE_NEW, $file_new)) {
        warn("Can't open(): $!");
        next;
    }
    while (<FILE_NEW>) {
        chomp;
        if (/^(([0-9]{1,3}\.){3}[0-9]{1,3})\s+(([0-9A-F]{2}:){5}[0-9A-F]{2})$/) {
            $arptable_new{$1} = $3;
        } else {
            warn("Bad string '$_'");
        }
    }
    unless (close(FILE_NEW)) {
        warn("Can't close(): $!");
    }
    #
    if (-e $file_old) {
        unless (open(FILE_OLD, $file_old)) {
            warn("Can't open(): $!");
            next;
        }
        while (<FILE_OLD>) {
            chomp;
            if (/^(([0-9]{1,3}\.){3}[0-9]{1,3})\s+(([0-9A-F]{2}:){5}[0-9A-F]{2})$/i) {
                $arptable_old{$1} = $3;
            } else {
                warn("Bad string '$_'");
            }
        }
        unless (close(FILE_OLD)) {
            warn("Can't close(): $!");
        }
    }
    #
    my @remarp_out;
    foreach (keys(%arptable_new)) {
        my $ipaddr  = $_;
        my $macaddr = $arptable_new{$_};
        if ($arptable_new{$ipaddr} ne $arptable_old{$ipaddr}) {
            my $remarp_out_string = "$device: $ipaddr (now known as $macaddr";
            if (defined($arptable_old{$ipaddr})) {
                $remarp_out_string = $remarp_out_string .
                    ", but $ipaddr was known as $arptable_old{$_}";
                delete($arptable_old{$ipaddr});
            }
            foreach (keys(%arptable_old)) {
                if ($arptable_new{$ipaddr} eq $arptable_old{$_}) {
                    $remarp_out_string = $remarp_out_string .
                        ", but $_ was known as $arptable_old{$_}";
                    delete($arptable_old{$_});
                }
            }
            $remarp_out_string = $remarp_out_string . ")\n";
            push(@remarp_out, $remarp_out_string);
        }
    }
    foreach (keys(%arptable_old)) {
        if (! defined($arptable_new{$_})) {
            $arptable_new{$_} = $arptable_old{$_};
        }
    }
    #
    unless (open(FILE_OLD, ">$file_old")) {
        warn("Can't open(): $!");
        next;
    }
    foreach (keys(%arptable_new)) {
        print(FILE_OLD "$_ $arptable_new{$_}\n");
    }
    unless (close(FILE_OLD)) {
        warn("Can't close(): $!");
    }
    #
    if (scalar(@remarp_out)) {
        unless (defined(open(SENDMAIL, "|/usr/sbin/sendmail -t"))) {
            warn("Can't open(): $!");
        }
        print(SENDMAIL "From: Remote ARPWatcher <$config->{'email'}>\n");
        print(SENDMAIL "To: rewmarp admin <$config->{'email'}>\n");
        print(SENDMAIL "Subject: $device: remarp flash news\n");
        print(SENDMAIL "X-Powered-By: V.Melnik\n");
        print(SENDMAIL "X-Remarp-Version: $VERSION\n");
        print(SENDMAIL "\n");
        foreach my $remarp_out_string (@remarp_out) {
            chomp($remarp_out_string);
            print(SENDMAIL "$remarp_out_string\n");
        }
        print(SENDMAIL "\n");
        print(SENDMAIL "-- \n");
        print(SENDMAIL "Sincerelly yours,\n");
        print(SENDMAIL "                 Remote ARPWatcher v$VERSION");
        unless (close(SENDMAIL)) {
            warn("Can't close(): $!");
        }
    }
}

# remove pid-file
unless (unlink($config->{'pid_file'})) {
    warn("Can't unlink(): $!");
}

# stop the job
exit;

#
sub signal_main {
    my ($signal) = @_;
    warn("Got signal 'SIG$signal', terminating kids");
    foreach my $child (keys(%children_list)) {
        kill(1, keys(%children_list));
    }
    $shutdown = 1;
}

#
sub signal_child {
    my ($signal) = @_;
    warn("Got signal 'SIG$signal', terminating job");
    $shutdown = 1;
}

#
sub catch_child {
    my ($children_list) = $@;
    if (my $dead_child = wait) {
        delete($children_list{$dead_child});
    }
}

#
sub getarp {
    my ($config, $device_comm, $device_addr, $device_port) = @_;

    my ($snmp_session, $snmp_error) = Net::SNMP->session(
        -hostname       => $device_addr,
        -port           => $device_port,
        -version        => 'v1',
        -community      => $device_comm,
        -retries        => 5
    );
    unless (defined($snmp_session)) {
        die("Can't Net::SNMP->session(): $snmp_error");
    }

    my $snmp_result = $snmp_session->get_table('.1.3.6.1.2.1.4.22.1.2');
    unless (defined($snmp_result)) {
        die("Can't Net::SNMP->get_bulk_request(): " . $snmp_session->error());
    }

    unless (defined(open(ARPTABLE, ">$config->{'spool'}/$device_addr.new"))) {
        warn("Can't open(): $!");
        return(undef);
    }
    foreach (keys(%{$snmp_result})) {
        if ($_ =~ /^\.1\.3\.6\.1\.2\.1\.4\.22\.1\.2\.\d+\.(.+)$/) {
            my $ipaddr  = $1;
            my $macaddr = ${$snmp_result}{$_};
            if ($macaddr =~ s/^0x([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/$1:$2:$3:$4:$5:$6/) {
                $macaddr = uc($macaddr);
                printf(ARPTABLE "$ipaddr $macaddr\n");
            }
        } else {
            warn("Strange SNMP-object '$_'");
        }
    }
    unless (defined(close(ARPTABLE))) {
        warn("Can't close(): $!");
    }

    $snmp_session->close();
}

__END__
