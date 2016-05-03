# CryptoMalloc
Encrypt your RAM!!! Allows you to encrypt the physical memory of any process.

# How to use
```bash
# Mac OS X
DYLD_INSERT_LIBRARIES=libcryptomalloc.dylib [application]
# Linux
LD_PRELOAD=cryptomalloc.so [application]
```
