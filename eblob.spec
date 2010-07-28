Summary:	low-level IO library which stores data in huge blob files appending records one after another
Name:		eblob
Version:	0.0.1
Release:	1%{?dist}

License:	GPLv2+
Group:		System Environment/Libraries
URL:		http://www.ioremap.net/projects/eblob
Source0:	%{name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	openssl-devel
BuildRequires:	automake autoconf libtool

%description
libeblob is a low-level IO library which stores data in huge blob files
appending records one after another.

    * fast append-only updates which do not require disk seeks
    * compact index to populate lookup information from disk
    * multi-threaded index reading during starup
    * O(1) data location lookup time
    * ability to lock in-memory lookup index (hash table) to eliminate
    	memory swap
    * readahead games with data and index blobs for maximum performance
    * multiple blob files support (tested with blob-file-as-block-device too)
    * optional sha256 on-disk checksumming
    * 2-stage write: prepare (which reserves the space) and commit
    	(which calculates checksum and update in-memory and on-disk indexes).
	One can (re)write data using pwrite() in between without locks
    * usuall 1-stage write interface
    * flexible configuration of hash table size, flags, alignment
    * defragmentation tool: entries to be deleted are only marked as removed,
    	eblob_check will iterate over specified blob files and actually
	remove those blocks
    * off-line blob consistency checker: eblob_check can verify checksums
    	for all records which have them
    * run-time sync support - dedicated thread runs fsync on all files
    	on timed base

%package devel
Summary: Development files for %{name}
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}


%description devel
libeblob is a low-level IO library which stores data in huge blob files
appending records one after another.

This package contains libraries, header files and developer documentation
needed for developing software which uses the eblob library.

%prep
%setup -q

%build
export LDFLAGS="-Wl,-z,defs"
./autogen.sh
%configure 

make %{?_smp_mflags}

%install
rm -rf %{buildroot}

make install DESTDIR=%{buildroot}
rm -f %{buildroot}%{_libdir}/*.a
rm -f %{buildroot}%{_libdir}/*.la

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc AUTHORS AUTHORS COPYING README
%{_bindir}/*
%{_libdir}/libeblob.so.*


%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/libeblob.so

%changelog
* Sun Jul 28 2010 Evgeniy Polyakov <zbr@ioremap.net> - 0.0.1-1
- Initial build for Fedora.
