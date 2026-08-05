#!/usr/bin/perl
###############################################################################
# Copyright (C) 2006-2025 Jonathan Michaelson
#
# https://github.com/waytotheweb/scripts
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, see <https://www.gnu.org/licenses>.
###############################################################################
## no critic (ProhibitBarewordFileHandles, ProhibitExplicitReturnUndef, ProhibitMixedBooleanOperators, RequireBriefOpen)
# start main
use strict;
use IPC::Open3;

umask(0177);

our ($return, $fatal, $error, $modulefail);

$fatal = 0;
$error = 0;
$modulefail = 0;

# Each test inserts a probe rule and then always attempts to delete it, even
# when the insert is treated as failed. On some backends (e.g. iptables-nft on
# EL10 without kernel-modules-extra) an insert can succeed while still printing
# a warning, and skipping the delete in that case leaks the probe rule into the
# live ruleset

#my @modules = ("ip_tables","ipt_state","ipt_multiport","iptable_filter","ipt_limit","ipt_LOG","ipt_REJECT","ipt_conntrack","ip_conntrack","ip_conntrack_ftp","iptable_mangle","ip_tables","xt_state","xt_multiport","iptable_filter","xt_limit","ipt_LOG","ipt_REJECT","ip_conntrack_ftp","iptable_mangle","xt_conntrack");
#push @modules,"ipt_owner";
#push @modules,"xt_owner";
#push @modules,"ipt_REDIRECT";
#push @modules,"iptable_nat";
#push @modules,"ipt_recent ip_list_tot=1000 ip_list_hash_size=0";
#foreach my $module (@modules) {&loadmodule($module)}

print "Testing ip_tables/iptable_filter...";
$return = &testiptables("/sbin/iptables -I OUTPUT -p tcp --dport 9999 -j ACCEPT");
&testiptables("/sbin/iptables -D OUTPUT -p tcp --dport 9999 -j ACCEPT");
if ($return ne "") {
	print "FAILED [FATAL Error: $return] - Required for csf to function\n";
	$fatal++;
} else {
	print "OK\n";
}

print "Testing ipt_LOG...";
$return = &testiptables("/sbin/iptables -I OUTPUT -p tcp --dport 9999 -j LOG");
&testiptables("/sbin/iptables -D OUTPUT -p tcp --dport 9999 -j LOG");
if ($return ne "") {
	print "FAILED [FATAL Error: $return] - Required for csf to function\n";
	$fatal++;
} else {
	print "OK\n";
}

print "Testing ipt_multiport/xt_multiport...";
$return = &testiptables("/sbin/iptables -I OUTPUT -p tcp -m multiport --dports 9998,9999 -j LOG");
&testiptables("/sbin/iptables -D OUTPUT -p tcp -m multiport --dports 9998,9999 -j LOG");
if ($return ne "") {
	print "FAILED [FATAL Error: $return] - Required for csf to function\n";
	$fatal++;
} else {
	print "OK\n";
}

print "Testing ipt_REJECT...";
$return = &testiptables("/sbin/iptables -I OUTPUT -p tcp --dport 9999 -j REJECT");
&testiptables("/sbin/iptables -D OUTPUT -p tcp --dport 9999 -j REJECT");
if ($return ne "") {
	print "FAILED [FATAL Error: $return] - Required for csf to function\n";
	$fatal++;
} else {
	print "OK\n";
}

print "Testing ipt_state/xt_state...";
$return = &testiptables("/sbin/iptables -I OUTPUT -p tcp --dport 9999 -m state --state NEW -j LOG");
&testiptables("/sbin/iptables -D OUTPUT -p tcp --dport 9999 -m state --state NEW -j LOG");
if ($return ne "") {
	print "FAILED [FATAL Error: $return] - Required for csf to function\n";
	$fatal++;
} else {
	print "OK\n";
}

print "Testing ipt_limit/xt_limit...";
$return = &testiptables("/sbin/iptables -I OUTPUT -p tcp --dport 9999 -m limit --limit 30/m --limit-burst 5 -j LOG");
&testiptables("/sbin/iptables -D OUTPUT -p tcp --dport 9999 -m limit --limit 30/m --limit-burst 5 -j LOG");
if ($return ne "") {
	print "FAILED [FATAL Error: $return] - Required for csf to function\n";
	$fatal++;
} else {
	print "OK\n";
}

print "Testing ipt_recent...";
$return = &testiptables("/sbin/iptables -I OUTPUT -p tcp --dport 9999 -m recent --set");
&testiptables("/sbin/iptables -D OUTPUT -p tcp --dport 9999 -m recent --set");
if ($return ne "") {
	print "FAILED [Error: $return] - Required for PORTFLOOD and PORTKNOCKING features\n";
	$error++;
} else {
	print "OK\n";
}

print "Testing xt_connlimit...";
$return = &testiptables("/sbin/iptables -I INPUT -p tcp --dport 9999 -m connlimit --connlimit-above 100 -j REJECT --reject-with tcp-reset");
&testiptables("/sbin/iptables -D  INPUT -p tcp --dport 9999 -m connlimit --connlimit-above 100 -j REJECT --reject-with tcp-reset");
if ($return ne "") {
	print "FAILED [Error: $return] - Required for CONNLIMIT feature\n";
	$error++;
} else {
	print "OK\n";
}

print "Testing ipt_owner/xt_owner...";
$return = &testiptables("/sbin/iptables -I OUTPUT -p tcp --dport 9999 -m owner --uid-owner 0 -j LOG");
&testiptables("/sbin/iptables -D OUTPUT -p tcp --dport 9999 -m owner --uid-owner 0 -j LOG");
if ($return ne "") {
	print "FAILED [Error: $return] - Required for SMTP_BLOCK and UID/GID blocking features\n";
	$error++;
} else {
	print "OK\n";
}

print "Testing iptable_nat/ipt_REDIRECT...";
$return = &testiptables("/sbin/iptables -t nat -I OUTPUT -p tcp --dport 9999 -j REDIRECT --to-ports 9900");
&testiptables("/sbin/iptables -t nat -D OUTPUT -p tcp --dport 9999 -j REDIRECT --to-ports 9900");
if ($return ne "") {
	print "FAILED [Error: $return] - Required for MESSENGER feature\n";
	$error++;
} else {
	print "OK\n";
}

print "Testing iptable_nat/ipt_DNAT...";
$return = &testiptables("/sbin/iptables -t nat -I PREROUTING -p tcp --dport 9999 -j DNAT --to-destination 192.168.254.1");
&testiptables("/sbin/iptables -t nat -D PREROUTING -p tcp --dport 9999 -j DNAT --to-destination 192.168.254.1");
if ($return ne "") {
	print "FAILED [Error: $return] - Required for csf.redirect feature\n";
	$error++;
} else {
	print "OK\n";
}

if ($fatal) {print "\nRESULT: csf will not function on this server due to FATAL errors from missing modules [$fatal]\n"}
elsif ($error) {print "\nRESULT: csf will function on this server but some features will not work due to some missing iptables modules [$error]\n"}
else {print "\nRESULT: csf should function on this server\n"}

if (($fatal or $error) and $modulefail) {
	my $el = 0;
	if (open (my $OSREL, "<", "/etc/os-release")) {
		while (my $line = <$OSREL>) {
			if ($line =~ /^PLATFORM_ID=["']?platform:el(\d+)/) {$el = $1}
		}
		close ($OSREL);
	}
	if ($el >= 10) {
		print <<END;

NOTE: This looks like an EL${el}-family system (AlmaLinux/Rocky/RHEL). Minimal
EL10+ installs do not include the xt_* netfilter kernel modules that iptables
needs - they are shipped in the separate kernel-modules-extra package. To fix:

    dnf install kernel-modules-extra-\$(uname -r)
    reboot   (if the modules still fail to load)

then re-run this test. If this is a container, the host kernel must provide
these modules instead.
END
	} else {
		print "\nNOTE: The failures above indicate that the running kernel is missing netfilter\nextension (xt_*) modules. Check that the package providing them for your kernel\nis installed, or that your kernel was built with the required options.\n";
	}
}

sub testiptables {
	my $command = shift;
	my ($childin, $childout);
	my $cmdpid = open3($childin, $childout, $childout, $command);
	my @ipdata = <$childout>;
	waitpid ($cmdpid, 0);
	chomp @ipdata;
	if ($ipdata[0] =~ /not supported|missing kernel module|No chain\/target\/match|Couldn.t load match|Couldn.t find target/i) {$modulefail = 1}
	return $ipdata[0];
}

sub loadmodule {
	my $module = shift;
	my @output;

	eval {
		local $SIG{__DIE__} = undef;
		local $SIG{'ALRM'} = sub {die};
		alarm(5);
		my ($childin, $childout);
		my $pid = open3($childin, $childout, $childout, "modprobe $module");
		@output = <$childout>;
		waitpid ($pid, 0);
		alarm(0);
	};
	alarm(0);

	return @output;
}
