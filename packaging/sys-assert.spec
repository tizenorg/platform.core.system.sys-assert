Name:       sys-assert
Summary:    Blue screen and bs-viewer ui
Version:    0.2.89
Release:    1
Group:      TBD
License:    LGPL
Source0:    %{name}-%{version}.tar.gz

BuildRequires:  pkgconfig(appcore-efl)
BuildRequires:  pkgconfig(heynoti)
BuildRequires:  pkgconfig(elementary)
BuildRequires:  pkgconfig(utilX)
BuildRequires:  pkgconfig(ui-gadget)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(dnet)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(pmapi)
BuildRequires:  pkgconfig(libcurl)
BuildRequires:  cmake
BuildRequires:  edje-tools

%description
blue screen and bs-viewer ui

%package -n org.tizen.blue-screen
Summary:    blue screen and bs-viewer ui
Group:      TO_BE/FILLED

%description -n org.tizen.blue-screen
blue screen and bs-viewer ui.

%package -n libsys-assert
Summary:    libsys-assert (shared object)
Group:      TO_BE/FILLED
Requires:   %{name} = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libsys-assert
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

%post -n libsys-assert -p /sbin/ldconfig

%postun -n libsys-assert -p /sbin/ldconfig

%files

%files -n org.tizen.blue-screen
/usr/bin/*
/usr/share/*
/opt/share/*
/opt/apps/*

%files -n libsys-assert
/usr/lib/*.so*

