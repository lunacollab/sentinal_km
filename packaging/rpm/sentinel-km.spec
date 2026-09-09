# SPDX-License-Identifier: Apache-2.0
# sentinel-km -- kernel syscall activity monitor (kprobe ring + daemon).
#
# Build:   packaging/rpm/build.sh            (recommended)
#          rpmbuild -bb --define "_sentinel_version 0.1.0" \
#                  packaging/rpm/sentinel-km.spec
# Requires a kernel source/header tree matching `uname -r`.
#
# The version is injected via _sentinel_version (the authoritative source is
# packaging/dkms/dkms.conf); build.sh reads it there.

Name:           sentinel-km
Summary:        kernel syscall activity monitor (kprobe ring + daemon)
Version:        %{?_sentinel_version}%{!?_sentinel_version:0.1.0}
Release:        1
License:        Apache-2.0
Group:          System Environment/Kernel
Url:            https://example.invalid/sentinel-km
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  gcc make kernel-devel
Requires:       kmod
# Kernel build tree + version-of-interest. build.sh injects _kpath/_kver;
# the RH path defaults to the running kernel.
%global kpath %{?_kpath}%{!?_kpath:%(uname -r)}
%global kver %{?_kver}%{!?_kver:%{kpath}}

%description
kprobe/kretprobe hook set with a zero-copy mmap ring and a small
validating daemon. Ships the kernel module plus userspace consumer.

%prep
%setup -q -n %{name}-%{version}

%build
make -C daemon
make -C kernel KDIR=%{kpath}

%install
rm -rf %{buildroot}
install -d %{buildroot}%{_sbindir}
install -d %{buildroot}/lib/modules/%{kver}/kernel/misc
install -d %{buildroot}/etc/sentinel
install -d %{buildroot}/etc/modprobe.d
install -d %{buildroot}%{_prefix}/lib/systemd/system
install -d %{buildroot}%{_datadir}/doc/%{name}
install -m0755 daemon/sentinel-daemon %{buildroot}%{_sbindir}/
install -m0644 kernel/sentinel_km.ko \
	%{buildroot}/lib/modules/%{kver}/kernel/misc/
install -m0644 packaging/sentinel.conf %{buildroot}/etc/sentinel/
install -m0644 packaging/modprobe.conf %{buildroot}/etc/modprobe.d/sentinel.conf
install -m0644 packaging/systemd/sentinel-daemon.service \
	%{buildroot}%{_prefix}/lib/systemd/system/
install -m0644 LICENSE LICENSE-APACHE README.md \
	%{buildroot}%{_datadir}/doc/%{name}/
install -m0644 packaging/dkms/dkms.conf \
	%{buildroot}%{_datadir}/doc/%{name}/dkms.conf

%post
depmod -a %{kver} >/dev/null 2>&1 || true
if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload >/dev/null 2>&1 || true
fi

%preun
if command -v systemctl >/dev/null 2>&1; then
	systemctl stop sentinel-daemon.service >/dev/null 2>&1 || true
	systemctl disable sentinel-daemon.service >/dev/null 2>&1 || true
fi

%postun
depmod -a %{kver} >/dev/null 2>&1 || true
if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload >/dev/null 2>&1 || true
fi

%files
%{_sbindir}/sentinel-daemon
/lib/modules/%{kver}/kernel/misc/sentinel_km.ko
%config(noreplace) /etc/sentinel/sentinel.conf
%config(noreplace) /etc/modprobe.d/sentinel.conf
%{_prefix}/lib/systemd/system/sentinel-daemon.service
%{_datadir}/doc/%{name}/*

%changelog
* Mon Jan 01 2024 sentinel-km maintainers <maintainers@example.invalid> - %{version}-1
- Initial packaged release
