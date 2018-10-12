#!/bin/env python3
import sys
import re

def extract_build_info(strlines):
    """
    Runs a simple state machines against a fully parsed spec file:

    State 0: %build not found yet.
    State 1: %build was found
    State 2: ./configure was found
    State 3: last line (without slash) of ./configure call was found
    State 4: empty line was found and all build information was complete
    State 5: Something went wrong and next section was found without finishing
    """
    state = 0

    build_start = re.compile("^%build\n")
    configure_start = re.compile("^\s*\.\./configure\s+\\\\\n$")
    configure_consume = re.compile("^\s+.*\\\\\n$")
    configure_consume_last = re.compile("^\s+.*\n$")
    configure_end = re.compile("^\n")

    build_line = []

    for line in strlines:
        # Looking for %build
        if state == 0:
            if build_start.match(line):
                state = 1
            continue

        #%build is found. Look for build_configure.sh
        elif state == 1:
            # build_configure.sh line was found. Ignore all rest
            if configure_start.match(line):
                state = 2
                build_line.append(line.strip()[:-1])
            continue

        #./configure.sh was found, include everying ending in \
        elif state == 2:
            if configure_consume.match(line):
                if line.strip()[:-1]:
                    build_line.append(line.strip()[:-1])
            elif configure_consume_last.match(line):
                build_line.append(line.strip())
                state = 3
            else:
                state = 5

        # last line was found, next line needs to be empty
        elif state == 3:
            if configure_end.match(line):
                state = 4
            else:
                state = 5

        # states 4 or 5 ends the script
        else:
            break

    if state != 4:
        sys.stderr.write("../configure couldn't be found. State=%d\n" %(state))
    else:
        print ('\n'.join(build_line))

def main():
    if len(sys.argv) == 1:
        extract_build_info(sys.stdin)
    else:
        f = open(sys.argv[1])
        extract_build_info(f.readlines())

if __name__ == "__main__":
    if len(sys.argv) > 2 or \
       (len(sys.argv) == 2 and sys.argv[1] == "--help"):
        print("Usage: %s <filename>" % sys.argv[0])
        print("       %s < specfile.spec" % sys.argv[0])
        exit(1)

    main()

