#!/bin/bash
PATH=/usr/bin:/usr/sbin

die() {
    echo $* >&2
    exit 1
}

NAME=parsegraph_user
PARSEGRAPH_USER_INSTALL=`pkg-config --variable=parsegraph_user_install parsegraph_user`

test -z $PARSEGRAPH_USER_INSTALL && die "No install script was found"

! test -e test_user_install.$$ || die "Install database must not already exist"
$PARSEGRAPH_USER_INSTALL sqlite3 test_user_install.$$ || die "Install script failed"
test -e test_user_install.$$ || die "Installed database was not created."
trap 'rm -f test_user_install.$$' TERM EXIT
