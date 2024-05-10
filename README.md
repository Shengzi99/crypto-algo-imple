# crypto-algo-imple
implementation of crypto &amp; hash algorithm in C/C++ and hardware intrinsics.  加密和哈希算法的C/C++实现，部分算法使用了如AES-NI之类的硬件intrinsics进行加速

## Content
实现了如下加密算法：
+ AES128
+ XTS-AES128
+ SM4

实现了如下Hash函数：
+ SM3
+ SHA3-256

## How to run
```bash
make all
./bin/main #运行所有算法
```

## References
[1] https://gist.github.com/acapola/d5b940da024080dfaf5f 非常好的AES-NI参考。