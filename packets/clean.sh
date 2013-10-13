#!/bin/sh
. ../env/bin/activate
mkdir -p pcaps
rm pcaps/*
rm packets.db
python make_db.py packets.db

