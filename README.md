# Protocol_Restoration
本项目使用libpcap读pcap报文，然后进行tcp流的乱序重组、与tls1.2中的握手报文解析，利用前缀树可以根据四元组、SNI、证书部分进行流过滤。
- 不考虑ip分片的情况（没有进行ip的分片重组）
- TCP部分完成乱序重组以及数据包的缓冲
- TLS部分只考虑了TLS1.2的情况

# 使用
1. `clone`本项目至Linux平台（Centos或者Ubuntu）
2. 安装所需依赖`libpcap`、`cmake`
3. 编译：
```bash
  cmake -S . -B build 
  cmake --build build
 ```

# 说明
`third_party/openssl`中两个头文件取自`openssl1.1.1s`源代码。
