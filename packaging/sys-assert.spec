Name:       sys-assert
Summary:    System Assert
Version:    0.3.3
Release:    5
Group:      System/Other
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001:	%{name}.manifest
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(libunwind)
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

%post
if [ ! -d /.build ]; then
       orig="%{_libdir}/libsys-assert.so"
       pattern=$(echo $orig | sed -e 's|/|\\/|g')
       ret=`sed -n "/${pattern}/p"  %{_sysconfdir}/ld.so.preload`
       if [ -z "$ret" ]; then
          echo "%{_libdir}/libsys-assert.so" >> %{_sysconfdir}/ld.so.preload
       fi
       chmod 644 %{_sysconfdir}/ld.so.preload
fi
/sbin/ldconfig

%postun
orig="%{_libdir}/libsys-assert.so"
pattern=$(echo $orig | sed -e 's|/|\\/|g')
sed -i "/${pattern}/D" %{_sysconfdir}/ld.so.preload
/sbin/ldconfig

%files
%manifest %{name}.manifest
%attr(775,root,crash) /opt/share/crash
%attr(775,root,crash) /opt/share/crash/info
%license LICENSE.APLv2
%{_bindir}/coredumpctrl.sh
/opt/etc/.debugmode
/usr/lib/sysctl.d/sys-assert.conf
%{_libdir}/libsys-assert.so

