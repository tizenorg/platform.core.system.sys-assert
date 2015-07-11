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
BuildRequires:	pkgconfig(libtzplatform-config)
Requires:       libtzplatform-config

%description
System Assert.

%prep
%setup -q
cp %{SOURCE1001} .

%define SYS_ASSERT_ENABLE no

%build
export CFLAGS+=" -fPIC"
%ifarch %{arm} aarch64
    export CFLAGS+=" -DTARGET"
%endif

%cmake . -DTZ_SYS_ETC=%{TZ_SYS_ETC} \
         -DTZ_SYS_SHARE=%{TZ_SYS_SHARE} \
         -DSYS_ASSERT_ENABLE=%{SYS_ASSERT_ENABLE}
make %{?_smp_mflags}

%install
%make_install
mkdir -p %{buildroot}%{TZ_SYS_SHARE}/crash/info

%post
%if %{?SYS_ASSERT_ENABLE} == yes
if [ ! -d /.build ]; then
       orig="%{_libdir}/libsys-assert.so"
       pattern=$(echo $orig | sed -e 's|/|\\/|g')
       ret=$(sed -n "/${pattern}/p"  %{_sysconfdir}/ld.so.preload)
       if [ -z "$ret" ]; then
          echo "%{_libdir}/libsys-assert.so" >> %{_sysconfdir}/ld.so.preload
       fi
       chmod 644 %{_sysconfdir}/ld.so.preload
fi
%endif
/sbin/ldconfig

%postun
%if %{?SYS_ASSERT_ENABLE} == yes
orig="%{_libdir}/libsys-assert.so"
pattern=$(echo $orig | sed -e 's|/|\\/|g')
sed -i "/${pattern}/D" %{_sysconfdir}/ld.so.preload
%endif
/sbin/ldconfig

%files
%manifest %{name}.manifest
%attr(775,root,crash) %{TZ_SYS_SHARE}/crash
%attr(775,root,crash) %{TZ_SYS_SHARE}/crash/info
%license LICENSE.APLv2
%{_bindir}/coredumpctrl.sh
%{TZ_SYS_ETC}/.debugmode
%{_libdir}/libsys-assert.so

%if %{?SYS_ASSERT_ENABLE} == yes
/usr/lib/sysctl.d/sys-assert.conf
%endif

