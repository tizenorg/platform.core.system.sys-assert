Name:       sys-assert
Summary:    System Assert
Version:	0.3.0
Release:    1
Group:      TBD
License:    Apache_2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: packaging/sys-assert.manifest 

BuildRequires:  pkgconfig(appcore-efl)
BuildRequires:  pkgconfig(heynoti)
BuildRequires:  pkgconfig(elementary)
BuildRequires:  pkgconfig(utilX)
BuildRequires:  pkgconfig(ui-gadget)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(pmapi)
BuildRequires:  pkgconfig(libcurl)
BuildRequires:  cmake
BuildRequires:  edje-tools

%description
libsys-assert (shared object).

%prep
%setup -q

%build
cp %{SOURCE1001} .
export CFLAGS+=" -fPIC"
%ifarch %{arm}
    export CFLAGS+=" -DTARGET"
%endif

cmake . -DCMAKE_INSTALL_PREFIX=/usr

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}

%make_install

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files 
%manifest sys-assert.manifest
/usr/bin/*
/usr/lib/*.so*
/etc/udev/rules.d/92-rb-dump.rules
/opt/etc/.debugmode

