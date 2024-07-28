#!/bin/sh
socat TCP-LISTEN:10059,reuseaddr,fork EXEC:./prob,stderr