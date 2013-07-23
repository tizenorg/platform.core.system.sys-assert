Name:       sys-assert
Summary:    System Assert
Version:    0.3.3
Release:    5
Group:      System/Debug
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001:	%{name}.manifest
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  cmake

%description
System Assert.

%prep
%setup -q
cp %{SOURCE1001} .

%build
export CFLAGS+=" -fPIC"
%ifarch %{arm}
    export CFLAGS+=" -DTARGET"
%endif

%cmake .
make %{?_smp_mflags}

%install
%make_install
mkdir -p %{buildroot}/opt/share/crash/info
mkdir -p %{buildroot}/etc
echo -n "%{_libdir}/libsys-assert.so" > %{buildroot}/%{_sysconfdir}/ld.so.preload

%files
%manifest %{name}.manifest
%attr(775,root,crash) /opt/share/crash
%attr(775,root,crash) /opt/share/crash/info
%license LICENSE.APLv2
%{_bindir}/coredumpctrl.sh
/opt/etc/.debugmode
/usr/lib/sysctl.d/sys-assert.conf
%{_libdir}/libsys-assert.so
%{_sysconfdir}/ld.so.preload
