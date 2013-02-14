Name:       sys-assert
Summary:    libsys-assert (shared object).
Version:    0.3.3
Release:    4
Group:      Framework/system
License:    Apache License, Version 2.0
Source0:    %{name}-%{version}.tar.gz

BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  cmake
Requires(post): coreutils

%description
libsys-assert (shared object).

%prep
%setup -q

%build
export CFLAGS+=" -fPIC"
%ifarch %{arm}
    export CFLAGS+=" -DTARGET"
%endif

cmake . -DCMAKE_INSTALL_PREFIX=/usr

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install
mkdir -p %{buildroot}/usr/share/license
cp LICENSE.APLv2 %{buildroot}/usr/share/license/%{name}
mkdir -p %{buildroot}/usr/lib/systemd/system/basic.target.wants
ln -s ../sys-assert.service %{buildroot}/usr/lib/systemd/system/basic.target.wants/

%post
/sbin/ldconfig
mkdir -p /opt/share/crash/info
chown root:crash /opt/share/crash/info
chmod 775 /opt/share/crash/info

chown root:crash /opt/share/crash
chmod 775 /opt/share/crash

if [ -f %{_libdir}/rpm-plugins/msm.so ]; then
	find /opt/share/crash -print0 | xargs -0 chsmack -a 'sys-assert::core'
	find /opt/share/crash -type d -print0 | xargs -0 chsmack -t
fi

if [ ! -d /.build ]; then
	echo "/usr/lib/libsys-assert.so" >> /etc/ld.so.preload
	chmod 644 /etc/ld.so.preload
fi

%files
%manifest sys-assert.manifest
%{_bindir}/coredumpctrl.sh
%{_bindir}/core-launcher
%{_libdir}/libsys-assert.so
/usr/share/license/%{name}
%{_libdir}/sysctl.d/sys-assert.conf
%{_libdir}/systemd/system/sys-assert.service
%{_libdir}/systemd/system/basic.target.wants/sys-assert.service
