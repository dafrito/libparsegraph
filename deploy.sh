#!/bin/bash

make && make check && make install && make rpm
/bin/cp -vuf doc/*html ../server/public_html/doc/
