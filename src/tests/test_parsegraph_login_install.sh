#!/bin/bash
PATH=/usr/bin:/usr/sbin

die() {
    echo $* >&2
    exit 1
}

PARSEGRAPH_LOGIN_INSTALL=`pkg-config --variable=parsegraph_login_install parsegraph_login`

test -z $PARSEGRAPH_LOGIN_INSTALL && die "No install script was found"

! test -e test_login_install.$$ || die "Install database must not already exist"
$PARSEGRAPH_LOGIN_INSTALL sqlite3 test_login_install.$$ || die "Install script failed"
test -e test_login_install.$$ || die "Installed database was not created."
trap 'rm -f test_login_install.$$' TERM EXIT
