install-exec-hook:
	if test x${DESTDIR} != x; then python setup.py install --root=${DESTDIR}; else python setup.py install --prefix=${prefix}; fi

EXTRA_DIST = eblob.py setup.py
