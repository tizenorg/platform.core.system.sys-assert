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

%post -p <lua>
--Do not run this script inside the build environemt, it will cause issues.
if posix.stat("/.build") == nil then
    local f = assert(io.open("/etc/ld.so.preload", "a"))
    local t = f:write("%{_libdir}/libsys-assert.so")
    f:close()
    posix.chmod("/etc/ld.so.preload", 644)
end


%postun
# TBD: we need to remove the above, otherwise we will fail on everything
#that tries to preload that lib
#

%files
%manifest %{name}.manifest
%attr(775,root,crash) /opt/share/crash
%attr(775,root,crash) /opt/share/crash/info
%license LICENSE.APLv2
%{_bindir}/coredumpctrl.sh
/opt/etc/.debugmode
/usr/lib/sysctl.d/sys-assert.conf
%{_libdir}/libsys-assert.so

