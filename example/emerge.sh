#!/bin/bash

for f in `ls -1 $1/data.* | egrep -v "index|stat"`; do
	d=`basename $f`

	removed=`eblob_index_info $f.index | grep Removed | awk {'print $3'}`
	if (($removed > 0)); then
		echo `date`": starting $f processing: $removed removed objects"
		eblob_merge -i $f -o $f.new
		if (($? == 0)); then
			rm -f $f $f.index.*
			mv $f.new $f
			mv $f.new.index $f.index
		fi
		echo `date`": completed $f processing"
	fi
done

