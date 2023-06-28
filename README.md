go-md5mac
===

**go-md5mac** is an implementation of the MD5-MAC algorithm.

The code was reimplemented after the
[Crypto++ Project](https://github.com/weidai11/cryptopp/blob/CRYPTOPP_5_4/md5mac.cpp)
and
[Code-Reading-Book](https://github.com/sghiassy/Code-Reading-Book/blob/master/OpenCL/src/md5mac.cpp)
repositories.

No tests other than my use case for this module has been conducted.
Correctness of code and function is currently not to be expected and is not express or implied.

Example usage

```go
var (
    key     = bytes.Repeat([]uint8{0x41}, 16)
    message = bytes.Repeat([]uint8{0x42}, 32)
	
    digest  = make([]uint8, 16)
    outBuf = make([]uint8, 20)
	
    bufferSize = len(outBuf)
)

// create md5mac instance
mac, err := md5mac.NewMD5MACWithKey(key)
if err != nil {
    return err
}

// update the digest
mac.Update(message)

// finalize into digest
mac.Finalize(digest)

// write digest in outbuf
for i := 0; i < bufferSize; i += md5mac.MACLENGTH {
    copy(outBuf[i:], digest[:])
}
```
