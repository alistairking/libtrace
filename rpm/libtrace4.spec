Name:           libtrace4
Version:        4.0.7
Release:        1%{?dist}
Summary:        C Library for capturing and analysing network packets

License:        LPGLv3
URL:            https://github.com/LibtraceTeam/libtrace
Source0:        https://github.com/LibtraceTeam/libtrace/archive/%{version}.tar.gz

BuildRequires: gcc
BuildRequires: gcc-c++
BuildRequires: make
BuildRequires: bison
BuildRequires: doxygen
BuildRequires: flex
BuildRequires: libpcap-devel
BuildRequires: numactl-devel
BuildRequires: ncurses-devel
BuildRequires: openssl-devel
BuildRequires: libwandder1-devel
BuildRequires: libwandio1-devel
BuildRequires: dpdk-wand-devel

Requires: dpdk-wand

%description
libtrace is a library for trace processing. It supports multiple input
methods, including device capture, raw and gz-compressed trace, and sockets;
and multiple input formats, including pcap and DAG.

libtrace is developed by the WAND Network Research Group at Waikato
University in New Zealand.

%package        devel
Summary:        Development files for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires:       dpdk-wand-devel

%package        tools
Summary:        Helper utilities for use with the %{name} library
Requires:       %{name}%{?_isa} = %{version}-%{release}

%package -n     libpacketdump4
Summary:        Network packet parsing and human-readable display library
Requires:       %{name}-devel%{?_isa} = %{version}-%{release}

%package -n     libpacketdump4-devel
Summary:        Development files for libpacketdump
Requires:       libpacketdump4%{?_isa} = %{version}-%{release}

%description devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.


%description tools
%{name} is a library for trace processing. These tools perform many common
tasks that are required when analysing and manipulating network traces.

Multiple input methods and formats are supported including device capture,
raw and gz-compressed traces, and sockets.

libtrace is developed by the WAND Network Research Group at Waikato
University in New Zealand.

%description -n libpacketdump4
libpacketdump provides a library which can parse packets and display the
packet contents in a nice human-readable form. The output is similar to that
produced by tcpdump, although the formatting is somewhat more verbose.

libpacketdump is developed by the WAND Network Research Group at Waikato
University in New Zealand.

%description -n libpacketdump4-devel
This package contains development headers and other ancillary files for
the libpacketdump library.

libpacketdump provides a library which can parse packets and display the
packet contents in a nice human-readable form. The output is similar to that
produced by tcpdump, although the formatting is somewhat more verbose.

libpacketdump is developed by the WAND Network Research Group at Waikato
University in New Zealand.

%prep
%setup -q -n libtrace-%{version}

%build
%configure --disable-static --with-man=yes --mandir=%{_mandir} --with-dpdk=yes
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
%make_install
find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%license COPYING
%{_libdir}/libtrace.so.*

%files devel
%{_includedir}/libtrace*
%{_libdir}/libtrace.so
%{_mandir}/man3/*

%files tools
%{_bindir}/*
%{_mandir}/man1/*

%files -n libpacketdump4
%{_libdir}/libpacketdump/*.so
%{_libdir}/libpacketdump/*.protocol
%{_libdir}/libpacketdump.so.*

%files -n libpacketdump4-devel
%{_libdir}/libpacketdump.so
%{_includedir}/libpacketdump.h


%changelog
* Thu May 2 2019 Shane Alcock <salcock@waikato.ac.nz> - 4.0.7-1
- First libtrace package
