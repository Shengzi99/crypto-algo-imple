# crypto-algo-imple
implementation of crypto &amp; hash algorithm in C/C++ and hardware intrinsics.  加密和哈希算法的C/C++实现，部分算法使用了如AES-NI之类的硬件intrinsics或CUDA进行加速.  

   
If it helps, please give me a star, thanks! 如果对您有帮助，还请不吝Star本仓库，谢谢！

## Content
实现了如下加密算法：
+ **AES128** (Versions: naive, x86_AES-NI)
+ **SM4** (Versions: naive)
+ **XTS-AES128** (Versions: naive, x86_AES-NI_single/multicore)


实现了如下Hash函数：
+ **SHA3-256/512** (Versions: naive)
+ **SM3** (Versions: naive)


## How to run
```bash
make all
./bin/main #测试所有算法
```

## References
[1] https://gist.github.com/acapola/d5b940da024080dfaf5f 非常好的AES-NI参考  
[2] https://github.com/mjosaarinen/tiny_sha3/tree/master