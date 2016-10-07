#!/bin/sh

pylint3 -E setup.py pathspider
python3 -m nose

