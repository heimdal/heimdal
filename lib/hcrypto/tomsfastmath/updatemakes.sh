#!/bin/bash

bash genlist.sh > tmplist

perl filter.pl makefile tmplist
mv -f tmp.delme makefile

perl filter.pl makefile.shared tmplist
mv -f tmp.delme makefile.shared

rm -f tmplist
rm -f tmp.delme
