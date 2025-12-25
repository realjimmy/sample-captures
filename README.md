# Sample Captures

一个用于收集、整理和分享各类网络数据包捕获文件（PCAP）的开源项目。

## 📋 项目简介

本项目致力于收集和整理来自不同来源的网络数据包样本，为网络分析、协议研究、安全测试和工具开发提供丰富的测试数据。所有数据包文件均经过分类整理，便于查找和使用。

## 📁 项目结构

```
sample-captures/
├── wireshark-samples/     # Wireshark 官方示例数据包
├── community-shares/      # 社区分享的数据包
├── zeek-samples/          # Zeek 测试数据包
├── scapy/                 # Scapy 数据包构造脚本
└── README.md              # 项目说明文档
```

### 目录说明

#### `wireshark-samples/`
从 Wireshark 官方 Wiki 获取的示例数据包集合，涵盖各种网络协议和场景。

**数据来源**: [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures/#sample-captures)

#### `community-shares/`
由社区成员收集和分享的网络数据包，包括各种实际场景下的抓包数据。

#### `zeek-samples/`
来自 Zeek（原 Bro）开源项目的测试数据包，主要用于网络流量分析和安全监控。

**数据来源**: [Zeek Testing Traces](https://github.com/zeek/zeek/tree/master/testing/btest/Traces)

#### `scapy/`
使用 Scapy 构造数据包的 Python 脚本集合，方便生成测试数据包和进行协议测试。

---

**注意**: 请确保在使用这些数据包时遵守相关法律法规，不得用于非法用途。


