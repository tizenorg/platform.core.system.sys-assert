Name:       sys-assert
Summary:    System Assert
Version:	0.3.0
Release:    1
Group:      TBD
License:    LGPL
Source0:    %{name}-%{version}.tar.gz

BuildRequires:  pkgconfig(utilX)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(pmapi)
BuildRequires:  pkgconfig(libcurl)
BuildRequires:  cmake

%description
System Assert


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
%make_install

mkdir -p %{buildroot}/opt/bs/core
mkdir -p %{buildroot}/opt/share/hidden_storage/SLP_debug
touch %{buildroot}/opt/etc/.debugmode

%post -p /sbin/ldconfig
chown root:5000 /opt/bs/core
chmod 775 /opt/bs/core

chown root:5000 /opt/share/hidden_storage/SLP_debug
chmod 755 /opt/share/hidden_storage
chmod 775 /opt/share/hidden_storage/SLP_debug


# added below for dbg package
DBG_DIR=/home/developer/sdk_tools/usr/lib/debug

if [ -L /usr/lib/debug ]
then
	echo "already exists"
	exit
fi

mkdir -p ${DBG_DIR}
if [ -d /usr/lib/debug ]
then
	cp -a /usr/lib/debug/* ${DBG_DIR}
	rm -rf /usr/lib/debug
fi

ln -sf ${DBG_DIR} /usr/lib/debug

%postun -p /sbin/ldconfig

%files 
/usr/bin/*
/usr/lib/*.so*
/etc/udev/rules.d/*
%dir /opt/bs/core
%dir /opt/share/hidden_storage/SLP_debug
%config(missingok) /opt/etc/.debugmode
