#!/bin/bash
PATH=/usr/bin:/usr/sbin

die() {
    echo $* >&2
    exit 1
}

NAME=parsegraph_user
PARSEGRAPH_INSTALL=`pkg-config --variable=parsegraph_install parsegraph`

test -z $PARSEGRAPH_INSTALL && die "No install script was found"

! test -e test_install.$$ || die "Install database must not already exist"
$PARSEGRAPH_INSTALL sqlite3 test_install.$$ || die "Install script failed"
test -e test_install.$$ || die "Installed database was not created."
trap 'rm -f test_install.$$' TERM EXIT
