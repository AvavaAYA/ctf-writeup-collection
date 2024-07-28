#!/usr/bin/env bash

FILENAME=$(/recv.py)
timeout 20 /gameboi $FILENAME
