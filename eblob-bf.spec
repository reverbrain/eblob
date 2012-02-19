Summary:	low-level IO library which stores data in huge blob files appending records one after another
Name:		eblob
Version:	0.14.4
Release:	1%{?dist}.1

License:	GPLv2+
Group:		System Environment/Libraries
URL:		http://www.ioremap.net/projects/eblob
Source0:	%{name}-%{version}.tar.bz2
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	snappy-devel python-devel
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
%if 0%{?rhel} < 6 || 0%{?fedora} < 10
%{_libdir}/python*/site-packages/eblob*
%else
%{python_sitelib}/eblob*
%endif


%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/lib*.so

%changelog
* Sun Feb 19 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.14.4
- Added raw python blob class
- eblob_remove_all(): when RAM lookup fails check disk
- Deleted eblob_gen_index.cpp

* Thu Feb 16 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.14.3
- Added python eblob constructor that accepts eblob_config structure on input

* Wed Feb 8 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.14.2
- Use allocate/read for checksum calculation when reading small objects
- Skip .tmp files when scanning base names

* Wed Feb 1 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.14.1
- Added start/num parameters to iterate over selected number of blobs

* Mon Jan 30 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.13.13
- Use ssize_t instead of int in eblob_copy_data()

* Sun Jan 29 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.13.12
- Use chunked splice/copy, since we may have really big objects written

* Sun Jan 29 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.13.11
- Allow to rollback preallocation if prepare fails

* Sun Jan 29 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.13.10
- Merge helpers and fixes

* Tue Dec 20 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.13.9
- If we are doing prepare, and there is some old data - reserve 2 times as much as requested

* Tue Dec 20 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.13.8
- Added free space check before trying to reserve space on disk
- Truncate stat file precisely to the number of bytes written
- Fixed cached keys removal

* Mon Dec 19 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.13.7
- Added actual index size checks.
- Update index early in eblob_write_prepare_disk().
- eblob_write() does not need full eblob_write_commit_nolock(), only low-level on-disk part.

* Sun Dec 18 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.13.6
- Fixed cache entry stall list head processing 

* Sun Dec 18 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.13.5
- Fixed cache entry removal

* Sat Dec 17 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.13.4
- If commit provides size, use it as object size. If prepare reuses existing region, do not change its sizes.
- Changed eblob_write_prepare() first to try to check existing region if it is big enough.

* Sat Dec 17 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.13.3
- Initialize allocated memory for ecache to 0

* Sat Dec 17 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.13.2
- Optimize prepare (for eblob_write_prepare() only) call to reuse existing prepared area if its size is big enough

* Thu Dec 15 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.13.1
- Fixed cache balancing

* Thu Dec 15 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.13.0
- Added configurable two-queue cache for read data by Anton Kortunov <toshic.toshic@gmail.com>

* Fri Dec 2 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.12.23
- Added eblob_read_nocsum() - read data without csum check

* Sat Nov 26 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.12.22
- Added eblob_csum_ok()

* Thu Nov 24 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.12.21
- Skip malformed zero entries during iteration
- eblob_fill_write_control_from_ram() should not check whether aligned size is enough when doing read command

* Wed Nov 23 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.12.20
- Initialize eblob_write_control to zeroes in eblob_plain_write()

* Sat Nov 19 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.12.19
- Multiple prepare/commit fixes for POHMELFS. Better write debug.

* Mon Nov 14 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.12.18
- Added array of IO locks to protect state update during IO
- Simplified eblob_write()
- Dropped openssl bits

* Mon Oct 31 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.12.17
- Fill in-memory rbtree and bloom filter for online generated sorted index
- Do not update in-memory structures before pwrite
- Added eblob_get_types function

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
