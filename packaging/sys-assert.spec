#sbs-git:slp/pkgs/s/sys-assert sys-assert 0.3.0 8c6fe2f2b76743849583c95c96073692877ab541
Name:       sys-assert
Summary:    libsys-assert (shared object).
Version:    0.3.1
Release:    0
Group:      TBD
License:    LGPL
Source0:    %{name}-%{version}.tar.gz

BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  cmake
BuildRequires:  edje-tools

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

%post
/sbin/ldconfig
mkdir -p /opt/bs/core
chown 0:5000 /opt/bs/core
chmod 775 /opt/bs/core
mkdir -p /opt/share/hidden_storage/SLP_debug
chown 0:5000 /opt/share/hidden_storage
chmod 775 /opt/share/hidden_storage
chown 0:5000 /opt/share/hidden_storage/SLP_debug
chmod 775 /opt/share/hidden_storage/SLP_debug
chmod +x /etc/opt/init/sys-assert.init.sh
/etc/opt/init/sys-assert.init.sh

%files
/usr/bin/*
/usr/lib/*.so*
/etc/udev/rules.d/92-rb-dump.rules
/etc/opt/init/sys-assert.init.sh
/usr/opt/etc/.debugmode
/usr/bin/lockupinfo
/usr/bin/lockupinfo.sh
/usr/lib/libsys-assert.so

