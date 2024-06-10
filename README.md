
[![GoDoc][1]][2] [![Powered][9]][10] [![MIT licensed][11]][12] [![Build Status][3]][4] [![Go Report Card][5]][6] [![Coverage Statusd][7]][8] [![Sourcegraph][13]][14]

[1]: https://godoc.org/github.com/xtaci/kcp-go?status.svg
[2]: https://pkg.go.dev/github.com/xtaci/kcp-go
[3]: https://travis-ci.org/xtaci/kcp-go.svg?branch=master
[4]: https://travis-ci.org/xtaci/kcp-go
[5]: https://goreportcard.com/badge/github.com/xtaci/kcp-go
[6]: https://goreportcard.com/report/github.com/xtaci/kcp-go
[7]: https://codecov.io/gh/xtaci/kcp-go/branch/master/graph/badge.svg
[8]: https://codecov.io/gh/xtaci/kcp-go
[9]: https://img.shields.io/badge/KCP-Powered-blue.svg
[10]: https://github.com/skywind3000/kcp
[11]: https://img.shields.io/badge/license-MIT-blue.svg
[12]: LICENSE
[13]: https://sourcegraph.com/github.com/xtaci/kcp-go/-/badge.svg
[14]: https://sourcegraph.com/github.com/xtaci/kcp-go?badge


## Introduction

Dev language for [golang](https://golang.org/). 

```
+-----------------+
| SESSION         |
+-----------------+
| ARQ             |
+-----------------+
| CRYPTO(OPTIONAL)|
+-----------------+
| UDP(PACKET)     |
+-----------------+
| IP              |
+-----------------+
| LINK            |
+-----------------+
| PHY             |
+-----------------+
(LAYER MODEL OF KCP-GO)
```


```
          青联互联

--------   青联  Play  ------------
| 青联Play <--------->  XoRPC     |
--------   青联  loT  -------------
| 青联loT <--------->  XoRPC      |
--------   XoRPC   ---------------
| PRUDP  青联可靠UDP传输协议        |
| PMUX   青联多路复用协议           |
| PTUN   青联组网框架              |
--------  XoRPC plugins   --------
| LP        雪崩补丁               |
| NTMP 节点传输模式补丁             |
```