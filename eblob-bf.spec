Summary:	low-level IO library which stores data in huge blob files appending records one after another
Name:		eblob
Version:	0.19.11
Release:	1%{?dist}.1

License:	GPLv2+
Group:		System Environment/Libraries
URL:		http://www.ioremap.net/projects/eblob
Source0:	%{name}-%{version}.tar.bz2
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%if %{defined rhel} && 0%{?rhel} < 6
%define boost_ver 141
%else
%define boost_ver %{nil}
%endif
BuildRequires:	boost%{boost_ver}-devel, boost%{boost_ver}-filesystem, boost%{boost_ver}-iostreams, boost%{boost_ver}-python, boost%{boost_ver}-regex, boost%{boost_ver}-system, boost%{boost_ver}-thread
BuildRequires:	cmake >= 2.6
BuildRequires:	python-devel

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
CXXFLAGS="-pthread -I/usr/include/boost141" LDFLAGS="-L/usr/lib64/boost141" %{cmake} -DBoost_LIB_DIR=/usr/lib64/boost141 -DBoost_INCLUDE_DIR=/usr/include/boost141 -DBoost_LIBRARYDIR=/usr/lib64/boost141 -DBOOST_LIBRARYDIR=/usr/lib64/boost141 .
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
%doc AUTHORS README.rst
%{_bindir}/*
%{_libdir}/lib*.so.*
%{python_sitelib}/eblob*


%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/lib*.so

%changelog
* Thu Jun 06 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.19.11
- data-sort: added leak note
- blob: added periodic comments
- mobjects: protect against malloc size overflow
- blob: do not place want_defrag in register
- blob: loff_t is used only in __linux__ code
- blob: do not place ctl->thread_num in register
- blob: do not depend on dirname implementation
- stats: it's fine to use asserts in internal functions
- stats: atomically set sort_status
- l2hash: do not depend on rb_node being first structure member
- hash: fix eblob_hash_exit()
- Fixed new base duplicated name leak

* Sat Jun 01 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.19.10
- Lock database on start using lockf() to prevent multiple libeblob instances from using same database simultaneously;
- Introduce new periodic thread for various background tasks;
- Move statistics updates to periodic thread. This almost fully removes statistics update from write path.
-   Also stats update is now atomic - it creates temp file, writes data to it and then uses rename();
- Move heavy statvfs(3) call to periodic thread. This removes around 5-7 system calls (depending on libc implementation)
-   and speeds up write microbenchmarks by factor of two;
- Improved locking in iterator. Previously each following iterator could re-mmap
-   data used by already running iterator. Now we hold bctl for duration of one batch of dcs
-   preventing another thread by remmaping data underneath it;
- Now that we have working locks - allow iterator to proceed along with data-sort;
- Removed old defrag parts for good;
- Misc bugfixes and formatting / comment / CI improvements.

* Thu May 23 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.19.9
- blob: allow to commit no more data than was written
- blob: do not overwrite flags in eblob_plain_write()

* Tue May 21 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.19.8
- blob: re-formatted eblob_write_prepare_disk()
- blob: re-formatted log message
- bloom: do not set bits for removed entries
- Debug. Cleanup.

* Wed May 15 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.19.7
- Revert temporal revets: adaptive mutexes and new bloom-filter design

* Wed May 15 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.19.6
- features: remove include hack for Mac OS X / FreeBSD
- blob: do not read data file on fill()
- More debug on notice log level

* Sun May 12 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.19.4-1
- Revert "blob: switched to adaptive mutexes when available"
- More debug on notice log level

* Thu May 09 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.19.4
- Revert "bloom: reworked bloom filter"

* Mon May 06 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.19.3
- Search eblobs on disk in reverse order.
-   There is a theory that users prefer recently uploaded files, so it is better to search blobs in reverse order

* Tue Apr 30 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.19.2
- Propagate error from iterator callback to calling routine.
-   This will fix various assert on data-sort if badly damaged blob file is provided.
- Do not left garbage on FS if creating new blob failed.
-   This bug can be triggered by setting low open files limit.

* Thu Apr 25 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.19.1
- Do not hold lock while doing fsync
- Codespell grammar nazzi
- Debian package build-depends prettifications

* Mon Apr 22 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.19.0
- bloom: reworked bloom filter
- bloom: optimize bloom computation
- data-sort: actualize comments
- bloom: replace djb with K&R hash
- data-sort: skip sort stage for already sorted bases
- api: added eblob_read_data_nocsum() public API
- bloom: added (probably) usefull notes
- stat: added notes about atomicity of update
- index: allocate index blocks in contious region
- stress: missing whitespace in help
- stress: change default sync to -1
- cpp: add ability to read w/o checksumming
- Merge branch 'master' into devel

* Sat Apr 20 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.18.6
- blob: improved error reporting
- blob: check return code of malloc
- mobjects: simplified eblob_rename_blob
- mobjects: check return code of rename
- data-sort: fixed memory leak in datasort_mkdtemp()
- blob: removed experimental EBLOB_DROP_PAGE_CACHE flag
- blob: switched to adaptive mutexes when available
- stat: speedup statistics update
- misc: move includes to the top to unhide include errors
- blob: improved logging in eblob_try_flush_page_cache()
- blob: fix location of eblob_try_flush_page_cache()
- blob: fixed error handling in eblob_fd_readlink()
- blob: fixed build under Mac OS X

* Wed Apr 03 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.18.5-1
- Another attempt to friendify massive write and random reads

* Wed Apr 03 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.18.5
- Fixed copying of eblob_write_control to data at eblob_write

* Mon Apr 01 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.18.4-1
- Only flush page cache once per eblob_page_cache_flush_counter_max operations.

* Mon Apr 01 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.18.4
- Added optional flag, which tries to free page cache on every read/write. Useful for random read with background (active) write.

* Wed Mar 27 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.18.3
- bindings: python: fix class/struct mismatch
- tests: stress: added block size parameter
- fixed malformed write with EBLOB_NO_FOOTER flag at the end of the blob
- blob: properly handle offset writes when cfg.bsize is set
- mobjects: do not lock hash in common case
- Added defrag status checker function
- Return -EALREADY when defrag already started and client requests is again.
- Log when level == eblob->log_level, not only when level is lower than enabled in eblob.
- rwlock: hash->root_lock is now rwlock
- l2hash: removed unused l2hash lock
- blob: reformatted _eblob_read_ll() log
- blob: more checks to eblob_csum_ok()
- api: protect against misuse via zeroing out wc
- api: replaced hacky eblob_read_flags() with eblob_read_return()
- api: add new API to public interface
- api: simplified eblob_read_ll()
- api: basic protection for eblob_read_ll()
- api: renamed eblob_read_nolock() to eblob_read_ll()
- api: added new write* API
- api: added flag BLOB_DISK_CTL_USR1

* Wed Feb 13 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.18.2
- blob: fix truncation of malformed blobs
- blob: fix error code check
- updated tests
- comments
- fixed setup.py
- misc cleanups

* Mon Jan 28 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.18.1
- Data sort fixes

* Sat Jan 26 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.18.0
- Sort data blobs when doing defragmentation
- A lot of changes for above task made by Alexey Ivanov <SaveTheRbtz@GMail.com>
- Fixed lookup leak

* Sun Dec 16 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.17.8
- data-sort: fixed checkpatch errors
- mobjects: simplified eblob_pagecache_hint()
- data-sort: move eblob_pagecache_hint to mobjects.c
- data-sort: remove useless fields from ram control
- data-sort: l2hash: always set bctl pointer

* Thu Dec 13 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.17.7
- blob: added blob_size_limit config value to explicitly limit bob size
- index: blob: add config variables for index block and bloom
- blob: copy entry regardless of flags if offset is set
- tests update

* Mon Dec 10 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.17.6
- l2hash: fix remove_all when l2hash is used
- tests: also test eblob_remove_all()
- blob: do not hold hash lock whole duration of eblob_remove_all
- tests: use random offset in writes
- examples: merge: added debug information from data blob along with index
- l2hash: protect realloc with b->l2hash_lock
- mobjects: do not leak malloc'ed path
- mobjects: pass only valid fd to close()
- l2hash: destroy on cleanup
- range: removed dead assignments
- mobjects: removed dead assignment
- index: make static analyzer happy
- tests: randomize types
- l2hash: auto extend l2hash array on insert
- l2hash: added safeguards for l2hash
- l2hash: create all types 'in-between' on realloc

* Tue Dec 04 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.17.5
- l2hash: move eblob_realloc_l2hash() to common eblob_realloc_base_type()

* Mon Dec 03 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.17.4
- added datasort tests
- l2hash: Added level two hashing support
- index: fix search_end pointing outside of mmapped area
- index: fixed segfault in index

* Wed Nov 14 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.17.3
- Fixed range iterator and keys found in RAM for supposed-to-be-sorted blobs
- Added google groups link
- added missing eblob_iterate_existing prototype
- added lost libboost-system-dev build-dep
- Use autogenerated major/minor eblob versions.
- add debug to eblob_init for eblob_stat_init errors
- move features to separate file - features.h
- added -W option notes
- -W and -Wextra is the same thing
- added -fno-strict-aliasing notes
- blob: added eblob_pagecache_hint()
- added posix_fadvise test
- move definition of EBADFD to blob.h
- blob: sizeof(char) is 1
- Added timespamps to test
- Link eblob and eblob_static with Boost_SYSTEM_LIBRARIES
- Additional info for Boost on build
- also look for boost system
- replace fdopendir with opendir
- mac os x build fixes
- fixed misstype in merge.cpp

* Thu Sep 06 2012 Evgeniy Polyakov <zbr@ioremap.net> - 0.17.2
- fxd depends generation
- Use small-lettered cmake functions
- Added python support
- Added rpath into binaries
- Spec update
- Move snappy into global build dep
- When linking eblob_regex_iter do not use all boost libs, but only needed

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
