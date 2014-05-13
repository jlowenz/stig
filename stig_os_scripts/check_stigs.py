#!/usr/bin/env python

from __future__ import print_function
import sys
import stigs_cat1 as cat1

stigs = {}
stigs["cat1"] = [cat1.v1046(),
                 cat1.v11940(),
                 cat1.v27051(),
                 cat1.v39854(),
                 cat1.v44654(),
                 cat1.v39817(),
                 cat1.v44658(),
                 cat1.v4382(),
                 cat1.v4387(),
                 cat1.v4399(),
                 cat1.v27435(),
                 cat1.v27438(),
                 cat1.v50403(),
                 cat1.v50415(),
                 cat1.v50454(),
                 cat1.v50467(),
                 cat1.v50469(),
                 cat1.v50502()]

print("Running CAT I STIG checks for Ubuntu")

results = []
for s in stigs["cat1"]:
    res = s.check()
    results.append((res, str(s), s))
    print(s, file=sys.stderr)
    if not res:
        s.fix()
        
