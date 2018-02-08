# wolfTPM (TPM 2.0)

This example demonstrates calling the various TPM 2.0 API's.


## Building

1. Build wolfSSL:

```
./autogen.sh
./configure --enable-ecc --enable-sha512 && make
sudo make install
```

2. Build wolfTPM:

```
./configure && make
```


## Platform

This example was written for use on Raspberry Pi® 3 or the STM32 with the CubeMX HAL. This was tested using the Infineon OPTIGATM Trusted Platform Module 2.0 SLB 9670.

To add additional SPI hardware support insert your own interface call in `tpm2_demo.c` for the `TPM2_IoCb` function.


## Sample Output

```
./examples/tpm/tpm_demo
TPM 2.0 Test
TPM2: Caps 0x30000697, Did 0x001b, Vid 0x15d1, Rid 0x10 
TPM2_Startup pass
TPM2_SelfTest pass
TPM2_GetTestResult: Size 10, Rc 0x0
TPM2_IncrementalSelfTest: Rc 0x0, Alg 0x1 (Todo 0)
TPM2_GetCapability: Property FamilyIndicator 0x322e3000
TPM2_GetCapability: Property PCR Count 24
TPM2_GetRandom: Got 32 bytes
TPM2_PCR_Read: Index 0, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 1, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 2, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 3, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 4, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 5, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 6, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 7, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 8, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 9, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 10, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 11, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 12, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 13, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 14, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 15, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 16, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 17, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 18, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 19, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 20, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 21, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 22, Digest Sz 32, Update Counter 20
TPM2_PCR_Read: Index 23, Digest Sz 32, Update Counter 20
TPM 2.0 Test: Return code 0
```


### With Debug Enabled:

```
./examples/tpm/tpm_demo
TPM 2.0 Test
TPM2: Caps 0x30000697, Did 0x001b, Vid 0x15d1, Rid 0x10 
TPM2_Startup pass
TPM2_SelfTest pass
TPM2_GetTestResult: Size 10, Rc 0x0
	00 01 f9 db 00 00 00 00 00 00                   | ..........
TPM2_IncrementalSelfTest: Rc 0x0, Alg 0x1 (Todo 0)
TPM2_GetCapability: Property FamilyIndicator 0x322e3000
TPM2_GetCapability: Property PCR Count 24
TPM2_GetRandom: Got 32 bytes
	ab 37 21 9f 63 7b 16 3a 5f 99 c2 d3 3a 64 16 ea | .7!.c{.:_...:d..
	b4 e8 5f 9e 93 f6 63 3b af da c6 a7 8a df 78 b2 | .._...c;......x.
TPM2_PCR_Read: Index 0, Digest Sz 32, Update Counter 20
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
TPM2_PCR_Read: Index 1, Digest Sz 32, Update Counter 20
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
TPM2_PCR_Read: Index 2, Digest Sz 32, Update Counter 20
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
TPM2_PCR_Read: Index 3, Digest Sz 32, Update Counter 20
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
TPM2_PCR_Read: Index 4, Digest Sz 32, Update Counter 20
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
TPM2_PCR_Read: Index 5, Digest Sz 32, Update Counter 20
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
TPM2_PCR_Read: Index 6, Digest Sz 32, Update Counter 20
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
TPM2_PCR_Read: Index 7, Digest Sz 32, Update Counter 20
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
TPM2_PCR_Read: Index 8, Digest Sz 32, Update Counter 20
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
TPM2_PCR_Read: Index 9, Digest Sz 32, Update Counter 20
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
TPM2_PCR_Read: Index 10, Digest Sz 32, Update Counter 20
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
TPM2_PCR_Read: Index 11, Digest Sz 32, Update Counter 20
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
TPM2_PCR_Read: Index 12, Digest Sz 32, Update Counter 20
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
TPM2_PCR_Read: Index 13, Digest Sz 32, Update Counter 20
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
TPM2_PCR_Read: Index 14, Digest Sz 32, Update Counter 20
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
TPM2_PCR_Read: Index 15, Digest Sz 32, Update Counter 20
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
TPM2_PCR_Read: Index 16, Digest Sz 32, Update Counter 20
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
TPM2_PCR_Read: Index 17, Digest Sz 32, Update Counter 20
	ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff | ................
	ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff | ................
TPM2_PCR_Read: Index 18, Digest Sz 32, Update Counter 20
	ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff | ................
	ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff | ................
TPM2_PCR_Read: Index 19, Digest Sz 32, Update Counter 20
	ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff | ................
	ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff | ................
TPM2_PCR_Read: Index 20, Digest Sz 32, Update Counter 20
	ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff | ................
	ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff | ................
TPM2_PCR_Read: Index 21, Digest Sz 32, Update Counter 20
	ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff | ................
	ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff | ................
TPM2_PCR_Read: Index 22, Digest Sz 32, Update Counter 20
	ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff | ................
	ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff | ................
TPM2_PCR_Read: Index 23, Digest Sz 32, Update Counter 20
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
TPM2_PCR_Read: Index 0, Digest Sz 32, Update Counter 21
	bb 22 75 c4 9f 28 ad 52 ca e6 d5 5e 34 a9 74 a5 | ."u..(.R...^4.t.
	8c 7a 3b a2 6f 97 6e 8e cb be 7a 53 69 18 dc 73 | .z;.o.n...zSi..s
TPM 2.0 Test: Return code 0
```
