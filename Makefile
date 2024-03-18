# ECC Makefile

#removed from main.c: -I/usr/local/include -L/usr/local/lib -lm 

all: ecdh main

ecdh: ecdh.c
	gcc WJ/WjCryptLib_AesCtr.c WJ/WjCryptLib_Aes.c ecdh.c -lgmp -o ecdh

main: main.c
	gcc main.c WJ/WjCryptLib_AesCtr.c WJ/WjCryptLib_Aes.c -o main.bin -Os -lwolfssl

clean:
	rm -f *.o ecdh
	rm -f *.o main.bin
	rm -f input_keys.txt
	rm -f output_points.txt
