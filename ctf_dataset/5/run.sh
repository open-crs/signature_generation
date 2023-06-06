#!/bin/bash

make
./vul "cd ..; cd ..; cd ..; cd ..; cd ..; cd ..; cd ..; \$(pwd)bin\$(pwd)cat \$(pwd)home\$(pwd)feather\$(pwd)student\$(pwd)licenta\$(pwd)syscall_hooking\$(pwd)ctf_dataset\$(pwd)5\$(pwd)*"
make clean
