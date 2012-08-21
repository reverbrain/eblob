Summary:	low-level IO library which stores data in huge blob files appending records one after another
Name:		eblob
Version:	0.17.1
Release:	1%{?dist}.1

License:	GPLv2+
Group:		System Environment/Libraries
URL:		http://www.ioremap.net/projects/eblob
Source0:	%{name}-%{version}.tar.bz2
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%if %{defined rhel} && 0%{?rhel} < 6
BuildRequires:	boost141-devel, boost141-iostreams, boost141-filesystem, boost141-thread, boost141-python, boost141-system, boost141-regex
%else
BuildRequires:	boost-python, boost-devel, boost-filesystem, boost-thread, boost-python, boost-system, boost-regex, boost-iostreams
%endif
BuildRequires:	python-devel
BuildRequires:	snappy-devel
BuildRequires:	cmake >= 2.6

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
export DESTDIR="%{buildroot}"
%if %{defined rhel} && 0%{?rhel} < 6
CXXFLAGS="-pthread -I/usr/include/boost141" LDFLAGS="-L/usr/lib64/boost141" %{cmake} -DBoost_LIB_DIR=/usr/lib64/boost141 -DBoost_INCLUDE_DIR=/usr/include/boost141 .
%else
%{cmake} .
%endif
%if 0%{?rhel} <= 5
%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}
%{!?python_sitearch: %global python_sitearch %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib(1))")}
%endif
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTDIR="%{buildroot}"
rm -f %{buildroot}%{_libdir}/*.a
rm -f %{buildroot}%{_libdir}/*.la

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc AUTHORS README
%{_bindir}/*
%{_libdir}/lib*.so.*
%{python_sitelib}/eblob*


%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/lib*.so

%changelog
* Mon Aug 20 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.17.1
- Fixed 1000-records defragmentation limit
- Use bulk read in iterator

* Sun Aug 19 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.17.0
- Moved to log levels from log masks

* Sat Aug 18 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.16.11
- Turn off timed defrag
- Get rid of stdint, it exists everywhere
- Moved to cmake from autoconf. Courtesy to Vsevolod Velichko <torkvema@gmail.com>

* Wed Aug 08 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.16.10
- Added possibility to start defragmentation on demand

* Fri Aug 03 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.16.9
- Only allow names which are in form of '-.' without suffixes
- Do not return header data in python eblob iterator
- Misc cleanup
- Do not compile example/iterate_send.cpp
- Speedup eblob start using bulk index read

* Thu Jul 05 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.16.8
- Check if file is really opened in iterator.cpp

* Mon Jul 02 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.16.7
- Fix removed flags in indexes

* Mon Jun 25 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.16.6
- Use boost::iostreams::file_source instead of
    boost::iostreams::mapped_file, since the latter leaks
- Added iterator program which sends data to elliptics

* Mon Jun 25 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.16.5
- Dep builds update

* Mon Jun 18 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.16.4
- Use libsnappy1 or snappy (debian-only build)

* Mon Jun 18 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.16.3
- Use libsnappy1 instead of snappy (debian-only build)

* Mon Jun 18 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.16.2
- Added flag which prevents free-space check during write

* Sat Jun 9 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.16.1
- Enable defragmentation

* Thu Jun 7 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.16.0
- Use ioremap::eblob namespace

* Thu May 17 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.15.10
- Fixed Precise build

* Sat Apr 28 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.15.9
- Write 'removed' record in ->prepare(), so it can not be read in parallel. commit() will set correct bit. eblob_write() will do it too.

* Fri Apr 27 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.15.8
- Use correct F_SETFD/FD_CLOEXEC

* Fri Apr 27 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.15.7
- added O_CLOEXEC flags
- Do not return -ENOSPACE when EBLOB_RESERVE_10_PERCENTS is set and size is less than blob-size, but more than 0.1 of total size

* Wed Apr 18 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.15.6
- disable defrag for now

* Tue Apr 17 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.15.5
- Index and data files should be 644 by default to allow others like nginx to read data
- Build deps update

* Fri Apr 6 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.15.4
- Do not sync in separate thread if sync interfal is zero - we will sync on every write anyway
- Added no-footer blob flag
- Added overwrite-commits flags
- Removed posix_fallocate() call
- Added hole detection
- eblob_py_iterator cleanup
- Drop macroses which are not accessible in centos
- Do not include blob.h into namespace

* Fri Mar 23 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.15.3
- Only reserve 10% of free space when EBLOB_RESERVE_10_PERCENTS blob-config-flag is set
- Added prepare/commit methods to cpp bindings
- Unify blob names - rename existing if found
- Generate bloom filter in case of generation sorted index during startup
- Use sleep_time-- instead of --sleep_time to honor 1 second timeouts
- Sync iteration must be protected by b->lock

* Mon Mar 19 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.15.2
- Fixed read-modify-write column update
- Fixed missed column during type remove
- Use correct python path
- Added eblob::truncate()
- Protect bctl->sort update - fixed defragmentation race
- If user does not provide config->log then use stdout logger in cpp binding
- Added eblob.py setup.py extra dist files

* Sun Mar 11 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.15.1
- Fixed leaks
- Rename defragmented blobs just after they are created
- Include cleanups
- Do not use openat()

* Wed Feb 29 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.15.0
- Added 'automatic' test/check tool
- New automatic defragmentation implementation
- Added ::key() method
- Drop iolocks

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
