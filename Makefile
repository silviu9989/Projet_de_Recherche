# ECC Makefile


all: ecdh main

ecdh: ecdh.c
	gcc WJ/WjCryptLib_AesCtr.c WJ/WjCryptLib_Aes.c ecdh.c -lgmp -o ecdh

main: main.c
	gcc main.c WJ/WjCryptLib_AesCtr.c WJ/WjCryptLib_Aes.c -o main.bin -I/usr/local/include -Os -L/usr/local/lib -lm -lwolfssl

clean:
	rm -f *.o ecdh
	rm -f *.o main.bin
	rm -f input_keys.txt
	rm -f output_points.txt
