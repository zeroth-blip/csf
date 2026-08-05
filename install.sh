#!/bin/sh
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

# The stateful (SPI) ruleset csf builds depends on the kernel xt_* netfilter
# extension modules. EL10-family minimal installs (AlmaLinux/Rocky/RHEL 10+)
# ship these in the separate kernel-modules-extra package, and without them
# enabling csf can leave the server with DROP policies but no conntrack
# accepts, blocking all outbound TCP. Probe for a working state/conntrack
# match before installing; on EL10-family try to install the missing package
# and abort with a clear message if the kernel still cannot use it.
state_match_works() {
	iptables_probe_ok=0
	if iptables -I OUTPUT -p tcp --dport 9999 -m conntrack --ctstate ESTABLISHED -j ACCEPT >/dev/null 2>&1; then
		iptables_probe_ok=1
	fi
	# Always remove the probe rule - some backends insert successfully while
	# still emitting warnings, and a failed delete is harmless
	iptables -D OUTPUT -p tcp --dport 9999 -m conntrack --ctstate ESTABLISHED -j ACCEPT >/dev/null 2>&1
	if [ "$iptables_probe_ok" = "1" ]; then
		return 0
	fi
	if iptables -I OUTPUT -p tcp --dport 9999 -m state --state ESTABLISHED -j ACCEPT >/dev/null 2>&1; then
		iptables_probe_ok=1
	fi
	iptables -D OUTPUT -p tcp --dport 9999 -m state --state ESTABLISHED -j ACCEPT >/dev/null 2>&1
	[ "$iptables_probe_ok" = "1" ]
}

check_kernel_modules() {
	# iptables may not be installed yet - the panel installers pull it in as a
	# dependency, and csf itself refuses to start if the modules are unusable
	command -v iptables >/dev/null 2>&1 || return 0
	modprobe xt_conntrack >/dev/null 2>&1

	if state_match_works; then
		return 0
	fi

	el_major=""
	if [ -r /etc/os-release ]; then
		el_major=$(sed -n 's/^PLATFORM_ID="*platform:el\([0-9]*\).*/\1/p' /etc/os-release)
	fi

	if [ -n "$el_major" ] && [ "$el_major" -ge 10 ] 2>/dev/null && command -v dnf >/dev/null 2>&1; then
		echo
		echo "The iptables state/conntrack match is not usable with the running kernel."
		echo "EL${el_major} minimal installs ship the xt_* netfilter kernel modules in the"
		echo "separate kernel-modules-extra package. Attempting to install it..."
		echo
		dnf -y install "kernel-modules-extra-$(uname -r)" || dnf -y install kernel-modules-extra
		modprobe xt_conntrack >/dev/null 2>&1
		if state_match_works; then
			echo
			echo "kernel-modules-extra installed and the netfilter modules now work - continuing"
			echo
			return 0
		fi
		echo
		echo "ERROR: The xt_* netfilter kernel modules are still not usable, so csf cannot"
		echo "create the stateful firewall rules that allow reply/outbound traffic. Enabling"
		echo "csf in this state would block all outbound TCP connections, so the installation"
		echo "has been aborted."
		echo
		echo "If kernel-modules-extra was installed for a newer kernel than the one running,"
		echo "reboot into that kernel and re-run this installer:"
		echo
		echo "    dnf install kernel-modules-extra-\$(uname -r)"
		echo "    reboot"
		echo
		echo "If this is a container, the host kernel must provide these modules."
		exit 1
	fi

	echo
	echo "WARNING: The iptables state/conntrack match does not appear to be usable with"
	echo "the running kernel. csf may not be able to create its stateful firewall rules."
	echo "After installation, run 'perl /usr/local/csf/bin/csftest.pl' and resolve any"
	echo "FATAL errors before enabling csf."
	echo
}

check_kernel_modules

echo
echo "Selecting installer..."
echo

if [ -e "/usr/local/cpanel/version" ]; then
	echo "Running csf cPanel installer"
	echo
	sh install.cpanel.sh
elif [ -e "/usr/local/directadmin/directadmin" ]; then
	echo "Running csf DirectAdmin installer"
	echo
	sh install.directadmin.sh
elif [ -e "/usr/local/interworx" ]; then
	echo "Running csf InterWorx installer"
	echo
	sh install.interworx.sh
elif [ -e "/usr/local/cwpsrv" ]; then
	echo "Running csf CentOS Web Panel installer"
	echo
	sh install.cwp.sh
elif [ -e "/usr/local/vesta" ]; then
	echo "Running csf VestaCP installer"
	echo
	sh install.vesta.sh
elif [ -e "/usr/local/CyberCP" ]; then
	echo "Running csf CyberPanel installer"
	echo
	sh install.cyberpanel.sh
else
	echo "Running csf generic installer"
	echo
	sh install.generic.sh
fi
