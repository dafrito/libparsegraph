#!/bin/bash
PATH=/usr/bin:/usr/sbin

die() {
    echo $* >&2
    exit 1
}

PARSEGRAPH_INSTALL_USERS=`pkg-config --variable=parsegraph_install_users parsegraph_common`

test -z $PARSEGRAPH_INSTALL_USERS && die "No install script was found"

! test -e test_install_users.$$ || die "Install database must not already exist"
$PARSEGRAPH_INSTALL_USERS sqlite3 test_install_users.$$ || die "Install script failed"
test -e test_install_users.$$ || die "Installed database was not created."
trap 'rm -f test_install_users.$$' TERM EXIT
