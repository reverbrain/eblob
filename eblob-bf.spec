Summary:	low-level IO library which stores data in huge blob files appending records one after another
Name:		eblob
Version:	0.23.5
Release:	1%{?dist}.1

License:	GPLv2+
Group:		System Environment/Libraries
URL:		http://reverbrain.com/eblob
Source0:	%{name}-%{version}.tar.bz2
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)


%if %{defined rhel} && 0%{?rhel} < 6
BuildRequires:	gcc44 gcc44-c++
%endif

%if %{defined rhel} && 0%{?rhel} < 6
%define boost_ver 141
%else
%define boost_ver %{nil}
%endif
BuildRequires:	boost%{boost_ver}-devel, boost%{boost_ver}-filesystem, boost%{boost_ver}-iostreams, boost%{boost_ver}-python, boost%{boost_ver}-regex, boost%{boost_ver}-system, boost%{boost_ver}-thread
BuildRequires:	cmake >= 2.6
BuildRequires:	python-devel
BuildRequires:	handystats >= 1.10.2

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
export CC=gcc44
export CXX=g++44
CXXFLAGS="-pthread -I/usr/include/boost%{boost_ver}" LDFLAGS="-L/usr/lib64/boost%{boost_ver}" %{cmake} -DBoost_LIB_DIR=/usr/lib64/boost%{boost_ver} -DBoost_INCLUDE_DIR=/usr/include/boost%{boost_ver} -DBoost_LIBRARYDIR=/usr/lib64/boost%{boost_ver} -DBOOST_LIBRARYDIR=/usr/lib64/boost%{boost_ver} .
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


%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/lib*.so

%changelog
* Fri Sep 18 2015 Evgeniy Polyakov <zbr@ioremap.net> - 0.23.5
- build: fixed build: removed useless scope resolution
- blob: added removing `BLOB_DISK_CTL_UNCOMMITTED` from record's flags in `eblob_write_commit_prepare`
- small fix: prevent potential double close in eblob_base_ctl_open()
- datasort: use optional 'datasort_dir' for creating tmp directory for chunks
- doc: put extra comments on BLOB_DISK_CTL_NOCSUM and BLOB_DISK_CTL_CHUNKED_CSUM flags
- plain write: fixed bug with incorrect footer size computing
- make test: run tests/run_tests.sh
- fixed extra pointer referencing in eblob_plain_writev_prepare: used &wc in eblob_dump_wc()

* Tue Sep 08 2015 Evgeniy Polyakov <zbr@ioremap.net> - 0.23.4
- stat: update total/removed records in realtime
- validate wc flags before binlog check
- tests: added crypto test of some crypto library functions: sha512_file(), sha512_file_ctx(), sha512_buffer()
- plain write: use disk_size instead of wc->total_data_size as prepare_disk_size param on defrag (-7 bugfix)
- crypto: fixed invalid processing of data block larger than buffer in sha512_file()/sha512_file_ctx()

* Thu Aug 20 2015 Evgeniy Polyakov <zbr@ioremap.net> - 0.23.3
- fixed writing of wc with flags==0 in plain_write() during defrag after blob close

* Tue Aug 18 2015 Evgeniy Polyakov <zbr@ioremap.net> - 0.23.2
- mobjects: remove .index.sorted for newly created blob

* Tue Aug 04 2015 Evgeniy Polyakov <zbr@ioremap.net> - 0.23.1
- logs: use wc->index instead of wc->bctl->index. Fixed reverbrain/elliptics#639.
- footer: fixed compilation error and warning on wheezy

* Thu Jul 09 2015 Evgeniy Polyakov <zbr@ioremap.net> - 0.23.0
- Bump version higher because of substantial changes

* Thu Jul 09 2015 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.24
- Refactored write control structure - if we have found bctl (blob) to write data to,
- 	it is being hold for duration of all write operations.
- Added chunked checksumming - it adds one 64-bit murmur csum per 1Mb of data
- 	all new writes will use new checksumming, old sha512 per file csum is also supported
- log: increased informativity of some logs - added bctl index and key
- index sort: fixed double mutex unlock and accurate resource release on errors

* Thu Jun 04 2015 Kirill Smorodinnikov <shaitkir@gmail.com> - 0.22.23
- stats: split handystats 'errors' metrics by error code
- csum: removed skipping zero-filled csum - all records without csum should have flag BLOB_DISK_CTL_NOCSUM.
- eblob_merge: fixed bug with incorrect dc comparator
- eblob_to_index: changed error message
- eblob_to_index: removed new lines, added trunc flag, use eblob_convert_disk_control() before writing to index
- eblob_to_index tool: create index from blob file
- log: decreased log level of 'size check failed' message at eblob_fill_write_control_from_ram.
-     The original message is about noncritical E2BIG error which says that 'I can't overwrite old data by new one because new data is bigger.
-     I will write new at the end of last blob.'. So, this message should appear on NOTICE log level.
-

* Wed May 06 2015 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.22
- core: fixed failing write_prepare with -7 if it tries to overwrite record without footer by record with footer
- defrag: fixed auto-defrag on timed and/or scheduled datasort
- defrag: stop
- logs: added index of truncating blob to log

* Fri Apr 17 2015 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.21
- Added BLOB_DISK_CTL_UNCOMMITTED flag which is set for uncommitted records that were prepared but haven't been commmitted yet
- Added eblob_start_defrag_level()

* Fri Mar 27 2015 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.20
- index sort: skip iterating over just sorted index if cache is empty, since there is nothing to flush anyway
- removed unused sha384 functions and unification with elliptics cryptolib
- use interruption-safe read_ll in eblob_find_on_disk
- mmap elimination - mmap() replaced with pread(). Corrupted filesystem may return -EIO for some reads, while
- 	trying to access that data via mmap ends up with SIGBUS signal, which kills whole eblob user.

* Wed Mar 18 2015 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.19
- eblob: more debug in eblob_write_prepare() path

* Tue Mar 17 2015 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.18
- sorting: revert changes which changed sorting logic

* Sat Mar 14 2015 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.17
- defrag: fixed data is sorted check on invalid bctl
- example: get rid of useless example

* Fri Jan 30 2015 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.16
- doc: Added example/statistics.qdoc that describes statistics collected by eblob
- Got rid of react and added using handystats. Added configurable stat_id which identifies eblob instance statistics at handystats.

* Wed Jan 28 2015 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.15
- tests: fixed cpp tests - remove also should use prefixes
- cpp: made messages of all exception thrown by eblob cpp binding in common style.
- 	Also made `remove` and `iterate` to throw exception on error.

* Sat Jan 17 2015 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.14
- indexsort: changed level of log at sanity check while applying binlog. At startup added check that index is unsorted before sort it.
- flags: added EBLOB_AUTO_INDEXSORT: if this flag is set - eblob will force sorting blob's index after the blob is closed
- json: fixed comment indent

* Tue Nov 04 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.13
- index: bctl->sort must be set before filling index block

* Tue Nov 04 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.12
- index: always generate sorted index for all but the last blob at the start
- stats: updates total size of blobs on write_prepare.
- 	eblob_check_free_space use this stat for determining that blob_size_limit is reached.
- iteration: checks ranges on iteration even if index isn't sorted. Use bsearch for checking if the key from ranges.
- stress: added tests for iteration: out of ranges, part of ranges and full range.

* Sat Oct 18 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.11
- defrag: do not spam logs with 'defragmentation is not needed' messages

* Wed Oct 15 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.10
- stat: run periodic statistics task once per second (it is cheap), but dump it into data.stat file once per @periodic_timeout seconds
- core: added base directory (calculated at start time from cfg.file), use it for getting statistics
- Fixed signed/unsigned warnings
- init: fixed possible unintialized errno set

* Tue Oct 14 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.9
- init: set errno if init has failed
- defrag: sort unsorted blobs even if defrag is not needed
- fixed base size (bctl_size) in eblob_check_record
- logs & json stat: added string representation of want_defrag status
- core: added defrag_generation counter that is increased each time when blobs are defraged
- logger: added method for dumping blob config and disk control flags
- spec: fixed bogus dates

* Sun Oct 05 2014 BogusDateBot
- Eliminated rpmbuild "bogus date" warnings due to inconsistent weekday,
  by assuming the date is correct and changing the weekday.
  Sun Jul 28 2010 --> Sun Jul 25 2010 or Wed Jul 28 2010 or Sun Aug 01 2010 or ....
  Tue Jun 22 2011 --> Tue Jun 21 2011 or Wed Jun 22 2011 or Tue Jun 28 2011 or ....

* Thu Oct 02 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.8
- defrag: merge blobs if blob data size (total-removed) is less than 10% of the max blob size, do not take into account number of records
- write: updated space check function commit

* Sun Sep 28 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.7
- base: propagate new base creation error to higher level

* Wed Sep 10 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.6
- config: made periodic_timeout configurable and decreased its default to 15
- json: checks cached json lifetime and if it is greater than doubled timeout of json update, adds 'error' section to json
- json: added caching json statistics in periodic thread and made eblob_stat_json_get return cached json

* Tue Sep 02 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.5
- C++: added method for getting eblob_backend* from eblob object
- code: use tab instead of spaces
- defrag: do not compute want_defrag status for the last base
- datasort: defrag_percentage now checks size of removed records instead of number of removed records
- json_stat:
-       * do not fail all stat if some stats are not available.
-       * fixed gcc warnings with fscanf.

* Fri Aug 15 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.4
- stat: added malloc() return value check
- stat: fixed null-byte json string generation

* Fri Aug 15 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.3
- stat: do not cache statistics in static buffer, it is not thread-safe other backend request can overwrite this data under us

* Wed Aug 13 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.2
- json_stat: added schema with comments of json statistics.
- json_stats: fixed summary statistics output. Added vfs & device statistics from procfs.

* Thu Aug 07 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.1
- disk-lookup: added rich disk-lookup stats: bloom, range array, bsearch and so on
- Defrag: added new state - EBLOB_MERGE_NEEDED and do not defrag one base that could only be merged
- Stats: added config to json statistics

* Tue Jul 22 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.22.0
- iterate: check locally ranges and found keys, skip those keys which do not fit ranges.
- init: get rid of internal random generator initialization.
- interator: initial range iterator implementation, this breaks old unused(?) iterator API.
- 	Caller can provide array of ranges to scan and if we have sorted index for given base_ctl,
- 	we can skip indexes to index blocks which contain our needed keys.
- index_block: get rid of index range tree, use bsearch() to find given range in index_blocks array
- threads: allow calling sync, defrag and periodic tasks on behalf of calling threads, not dedicated threads. Patch from <pavel@wialus.co.nz>
- Removed multithreading at blobs iterations 

* Sat Jul 12 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.46
- Removed index_offset in eblob_base_ctl, replaced its use by index_size.

* Thu Jul 10 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.45
- preallocate: return error if posix_preallocate() failed
- Add BLOB_DISCK_CTL_NOCSUM to record flags if blob has EBLOB_NO_FOOTER flag

* Wed Jul 09 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.44
- csum: do not check csum if there is no footer

* Tue Jul 08 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.43
- timeout: again fixed eblob_event_wait() for negative timeouts

* Sat Jul 05 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.42
- timeout: set eblob wait timeout to unsigned long, so that it would be converted to large number for negative tiemouts

* Thu Jun 19 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.41
- eblob: fixed long eblob stopping time. Patch by Pavel Jurkas from wialus.co.nz
- cpp: added plain_write() method, which is a wrapper on top of eblob_plain_write()
- example: get rid of unused regex iterator, it used old iterator code, which did not take into account ext headers for example
- iterate: updated iterators - exported new iterator similar to what is present in C code, get rid of old iterator class
- log: made eblob_dump_id_len() and friends thread-safe by using per-thread allocated temporal buffers

* Sat May 17 2014 Andrey Kashin <kashin.andrej@gmail.com> - 0.21.40
- warning fixed, ssize_t replaced with int
- stat: detailed monitoring in write_commit_nolock() added
- blob: reserve 2 blob sizes - this is needed for sorting - split+merge
- Fixed garbage in csum-time.
- Added logging eblob_write_commit_footer with csum-time

* Tue May 13 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.39
- defrag: added start/completion time and status statistics
- eblob: added 'defrag' prefix for all defrag/sort related log prints

* Thu May 01 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.38
- Removed looking up for key twice on write.

* Tue Apr 29 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.37
- debian: react version dependency updated to 2.3.1
- debian: react-dbg removed from dependencies

* Mon Apr 28 2014 Andrey Kashin <kashin.andrej@gmail.com> - 0.21.36
- debian: react added to dependencies to eblob and eblob-dbg
- foreign: React version updated
- stat: REMOVED_SIZE stat estimation fixed
- eblob: added comment about eblob_ram_control::size field
- stat: Total size of removed records added

* Wed Apr 23 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.35
- iterator: do not throw exception if there are no more data files to iterate

* Tue Apr 22 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.34
- Added defragmentation methods to cpp binding.
- Added defragmentation methods to python binding.
- Fixed eblob bases which end by slash

* Sat Apr 05 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.33
- cmake: missing locate_library.cmake added
- build: fixed build when react is not in standard packaged place
- build: depend on react developer version for compilation

* Tue Apr 01 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.32
- foreign: React is now shared library
- stat: Tools for exporting trace_id from elliptics added

* Wed Mar 12 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.31
- stat: use atomics instead of locks
- stat: IO stats merged into global eblob stats
- stat: Json statistics. React C bindings.

* Mon Feb 17 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.30
- stat: Time statistics monitoring added.

* Tue Feb 11 2014 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.29
- merge: spelling correction
- Added measurement of the time spent reading and checking object checksum
- Typo fixed

* Mon Dec 02 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.28
- periodic: update stat file once per 30 seconds, do not trash disks every secon
- spec: removed sitelib glob

* Sun Nov 17 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.27
- eblob: get rid of basically unused recover_index_from_blob.py
- python: get rid of old and unsupported python helper

* Sun Nov 17 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.26
- stat: export stat ids, added eblob_stat_get_summary() to read statistics by id

* Mon Nov 11 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.25
- defrag: Fixed accumulation of bases which comes out the limits

* Fri Nov 08 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.24
- merge: allow to merge really old blobs whose indexes always contain 96 as disk_size

* Thu Nov 07 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.23
- license: use eblob is now under LGPLv3
- gitignore: update
- defrag: eblob should delete/unlink blob files containg only removed entries as soon as it detects them

* Mon Oct 21 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.22
- eblob_base_remove() must not remove base ctl from base list, since it will be updated during defragmentation and thus will be lost

* Mon Oct 21 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.21
- Physically delete blobs where all records were already removed.
- Added ability to pass offset to eblob_preallocate

* Fri Sep 27 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.20
- man: reformatted examples
- man: dos2unix
- blob: fix return value in case of eblob_preallocate failure
- Added eblob tool man pages

* Tue Sep 24 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.19
- Use eblob_preallocate() instead of ftruncate(), since the latter may fail to preallocate needed space on disk, and thus mmap() may fail/crash

* Sun Sep 15 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.18
- defrag_percentage is a part of total number of record, not 'accessible' ones
- defrag: mark bctls for defrag based on number of records and size
- Simplify eblob_regex_iter

* Mon Sep 02 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.17
- data-sort: add time-scheduled data-sort

* Fri Aug 30 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.16
- blob: we shouldn't ignore index corruption on iteration
- blob: skip size check on possibly zero-filled records
- examples: merge: allow missed -o if -d is specified
- codespell: committed->commited

* Wed Aug 28 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.15
- blob: improved log message on lockf() failure
- examples: merge: fixed spelling, improved wording
- examples: merge: do not truncate output files on dry run
- examples: merge: add -d to getopt
- Added 'dry-run' mode in eblob_merge

* Fri Aug 23 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.14
- blob: added sanity to record copy
- examples: merge: make errors more obvoius
- examples: merge: prettify usage
- examples: merge: check that open succeeded
- examples: merge: less strict header ckecking
- examples: merge: fixed formatting of error message

* Tue Aug 20 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.13
- stats: simplified stats naming
- stats: accounting for in-memory index size
- hash: keep track of replaced entries
- hash: check rwlock_init return code
- hash: reduce memory consumption by 10%
- hash: simplify hash entry add
- stats: improved stats naming
- blob: moved mutex init to separate function
- examples: merge: skip broken entries

* Tue Aug 20 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.12
- examples: merge: remove useless while condition
- examples: merge: check results of read/write
- examples: merge: introduce -m parameter for max record size
- examples: merge: added even more sanity checks
- examples: merge: check both header for equality

* Mon Aug 19 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.11
- recover_index_from_blob.py: Fixed it in various places now it manages to recover index from data file. Not fast though;
- recover_index_from_blob.py: Allow bases to be passed through command line;
- recover_index_from_blob.py: Improvements to logging.
- blob.py: Removed check for data header vs index header equality;
- blob.py: Fixed infinite loop on iteration over broken bases;
- blob.py: Fixed iteration over removed entries;
- blob.py: Removed commented code;
- blob.py: Reformatted code and added comments;

* Thu Aug 15 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.10
- Now eblob_merge recovers from errors in the middle of base;
- Improved log output. Now it can be grep'd efficiently;
- Fixed error messages formatting.

* Thu Aug 15 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.9
- examples: make eblob_merge more robust
-   This will allow eblob_merge to recover badly damaged bases

* Wed Aug 14 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.8
- blob: fixed sanity check
- blob: fixed possible zero-size allocs
- blob: propagate internal iterator errors to caller
- data-sort: remove redundant code
- blob: move reord check routines to separate function
- index: check index validity on start
- blob: be less strict about index corruptions
- blob: fix eblob_total_elements()
- index: set pointers to NULL in eblob_index_blocks_destroy()
- index: fix possible stat race
- stress: check second's eblob_init() result
- mobjects: fix eblob_index_blocks_fill()'s rc check
- index: explicitly return 0 on success
- mobjects: make sorted index mandatory if it exists.

* Tue Aug 06 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.7
- blob: do not commit to ram until eblob_writev_raw is finished

* Fri Aug 02 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.6
- On defrag split all blobs into sub-groups so they stay within limits imposed by eblob cfg blob_size and records_in_blob and merge each group into one blob
- Removed unused code from logging
- Minor bugfixes for data-sort

* Tue Jul 30 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.5
- blob: improve log mesage on lock fail
- bloom: added loop count to stats
- bloom: improve bloom filter hit rate

* Mon Jul 29 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.4
- blob: removed binlog
- blob: make all bases but one immutable
- binlog: added tiny binlog replacement
- blob: lock bctl on entry removal
- blob: added note about rollback on failure
- blob: use b->lock for b->bases access
- index: do not consider just sorted base an error
- index: whitespace cleanup
- index: improved logging
- index: fix race between data-sort and index lookup
- tests: stress: make tests multithreaded
- tests: stress: more defensive programming
- tests: stress: cleanup previous test on start
- log: remove race in eblob_dump_id_len()
- cmake: use gnu99 standard
- log: simplified logging
- blob: switch from GNU99 [0] array to C99 []
- tests: stress: fail fast on invalid arguments
- tests: stress: align items_num on threads_num boundary
- tests: stress: bump test version
- tests: stress: print test version on start
- blob: use 0xhex format for flags
- codespell: comment fixes
- log: introduce new log level SPAM
- log: removed double 'endl' in log msg
- log: less verbose logging
- mobjects: fixed return code after base creation fail
- mobjects: hint unsorted fd too
- defrag: fixed race between defrag and base addition
- data-sort: fixed assignment before check
- blob: explicitly fix aliasing problems
- cmake: do not link with dl in case of *SAN
- cmake: removed unneeded BSD bits
- mobjects: sort includes
- cmake: removed useless if
- cmake: apply some warnings to C-specific code
- blob: fix multistage write for immutable blobs
- blob: improved logging in multi-stage write
- blob: fix copying of old record on prepare
- tests: stress: return EX_USAGE on positional arguments
- ci: added overwrite-heavy test with many threads
- blob: manually extend blob if copy was requested
- blob: copy seems-to-be-empty records
- data-sort: hold backend lock on binlog start
- blob: blob that are not sorting right now can be mutable

* Mon Jul 22 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.3
- blob: threat 0-sized entry as non-existient on append with EXTHDR
- Fixed llu/off_t format warnings

* Wed Jul 10 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.2
- Use 141 boost
- Tests update
- blob: prealloc space on append
- blob: fix append of non-exisient entries with EXTHDR
- doc: replaced ioremap references with reverbrain
- stats: added forgotten include
- defrag: added even more sanity

* Tue Jul 09 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.1
- Use 153 boost in spec

* Thu Jul 04 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.21.0
- Replaced general purpose BLOB_DISK_CTL_USR1 flag with special BLOB_DISK_CTL_EXTHDR
-   which changes eblob behavior in various ways so that metadata management in elliptics can be implemented efficiently
- Fixed writev() behaviour for iovcnt > 1
- Tests improvements: added writev() tests, improved append and three stage write
- Proper cleanup of bases which are removed due to absence of entries
- Many statistics fixes
- Comment and logging improvements
- Various static analyzer/pedantic fixes

* Mon Jun 24 2013 Evgeniy Polyakov <zbr@ioremap.net> - 0.20.0
- Removed columns
- Heavily rewritten API - made it vectorized
- Removed useless compression
- Extended statistics
- Changed overwrite mode - 'closed' blobs can never be overwritten, 'open' blob (current, the last one) is always overwritten

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

* Wed Jun 22 2011 Evgeniy Polyakov <zbr@ioremap.net> - 0.4.4
  Tue Jun 22 2011 --> Tue Jun 21 2011 or Wed Jun 22 2011 or Tue Jun 28 2011 or ....
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

* Wed Jul 28 2010 Evgeniy Polyakov <zbr@ioremap.net> - 0.0.1-1
  Sun Jul 28 2010 --> Sun Jul 25 2010 or Wed Jul 28 2010 or Sun Aug 01 2010 or ....
- Initial build for Fedora.
