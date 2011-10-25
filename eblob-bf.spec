Summary:	low-level IO library which stores data in huge blob files appending records one after another
Name:		eblob
Version:	0.12.16
Release:	1%{?dist}.1

License:	GPLv2+
Group:		System Environment/Libraries
URL:		http://www.ioremap.net/projects/eblob
Source0:	%{name}-%{version}.tar.bz2
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	openssl-devel snappy-devel python-devel
BuildRequires:  python-devel, libtar-devel
%if 0%{?rhel} < 6 || 0%{?fedora} < 10
BuildRequires:  boost141-python, boost141-devel
%else
BuildRequires:  boost-python, boost-devel
%endif
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
    * in-memory index lives in memory mapped file

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
%if 0%{?rhel} < 6 || 0%{?fedora} < 10
CXXFLAGS="-pthread -I/usr/include/boost141" LDFLAGS="-L/usr/lib64/boost141" %configure --with-boost-libdir=/usr/lib64/boost141
%else
%configure
%endif

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
%{_libdir}/lib*.so.*


%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/lib*.so

%changelog
* Tue Oct 25 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.12.16
- Don't compare flags in bsearch callback

* Mon Oct 24 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.12.15
- Do not open index and data files again in eblob_iterate
- Update unsorted indexes of removed records with BLOB_DISK_CTL_REMOVE flag
- Use 50 millions of records in blob by default
- Added eblob_merge (instead of old eblob_defrag) which defragments and
    merges (multiple) blobs into larger one

* Wed Oct 19 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.12.14
- Added bsearch statistics and on-disk lookup debugs
- Use 40 indexes per range block. Use 128 bits per index for bloom.

* Tue Oct 18 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.12.13
- Fixed sorted index bsearch range calculation

* Sat Oct 15 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.12.12
- Added bloom filter in sorted index blocks
- Added tree for range index search

* Wed Oct 12 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.12.11
- Only read mapped data blob if EBLOB_ITERATE_FLAGS_ALL flag is set

* Tue Oct 11 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.12.10
- Returned offline defrag tool
- Drop libssl deps
- Check if record is removed in blob

* Wed Jun 29 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.6.0
- Added snappy compression support
- Added start/max types into iterator. Exoport nice interface outside. (0.5.2)

* Sat Jun 25 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.5.1
- Create new files, if eblob dir is empty

* Sat Jun 25 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.5.0
- Added multiple columns support

* Tue Jun 22 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.4.4
- Added eblob_remove_hashed() and eblob::remove_hashed()

* Tue Jun 21 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.4.3
- Return real data offset, do not force clients to mess with sizeof(struct
	eblob_disk_control)
- Added hashed keys
- Renames write methods
- Switched to fixed-size eblob_key interface
- Added namespace zbr
- Added eblob range query
- Added remove() method
- Added c++ examples

* Tue Jun 7 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.3.13
- Overwrite hash entry if we asked to replace it and sizes match
- Use (part of) provided key as hash table index
- Preallocate more space for hash entries in a bucket
- Save references to open data/index failes in iterator
- Initial implementation of startup defragmentation
- Extended eblob_iterator class to support index and data iterators

* Fri Jun 3 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.3.12
- Use the same mmap file for subsequent starts by default
- Grow and start map file by 1 Gb

* Thu Jun 2 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.3.11
- Do not move entries around, since we are closing down whole mapping anyway
- Use posix_fallocate() to preallocate sufficiently large mmap files
- Added completion callback and matched callback counters into iterator
- Allocate/free mmap_file and use eblob file by default as a base path for mmap file
- truncate map file to 0 at cleanup

* Wed Jun 1 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.3.10
- Remap new portions of backend allocation file at different locations.

* Wed Jun 1 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.3.7
- Use mremap(MREMAP_FIXED | MREMAP_MAYMOVE)

* Wed Jun 1 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.3.5
- Fixed ostringstream and its std::string dereference

* Wed Jun 1 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.3.4
- Added read() methods
- Use ostringstream for mmap file name

* Wed Jun 1 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.3.3
- Added cpp binding

* Tue May 31 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.3.2
- Moved in-memory index into memory mapped file
- Fair number of other changes

* Tue Mar 1 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.1.7-1
- Log level cleanups

* Mon Feb 28 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.1.6-1
- Correctly set index's disk_size to sizeof(struct eblob_disk_control)

* Mon Feb 28 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.1.5-1
- Added index generating defragmenter.

* Tue Feb 8 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.1.2-1
- Do not lock entries in eblob_hash_insert_raw() since they should be locked via mlockall().

* Tue Feb 8 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.1.2-1
- Set memory locking limits to infinity if EBLOB_HASH_MLOCK is set in config.

* Tue Feb 8 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.1.1-1
- Use mlockall(MCL_CURRENT | MCL_FUTURE) to lock all current and future
    allocations when EBLOB_HASH_MLOCK is set.

* Mon Nov 29 2010 Evgeniy Polyakov <zbr@ioremap.net> - 0.1.0-1
- Switched to sha512 and 64-byte IDs

* Sun Jul 28 2010 Evgeniy Polyakov <zbr@ioremap.net> - 0.0.1-1
- Initial build for Fedora.
