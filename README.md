# 🔐 PY 2FA - 极致安全的本地两步验证器

[![Python Version](https://img.shields.io/badge/Python-3.8.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**PY 2FA** 是一款基于 Python 开发的纯本地、轻量级两步验证（2FA / TOTP）桌面客户端。它专为追求极致隐私和硬核安全的技术爱好者设计，无需联网，所有密钥全部本地加密存储，并内置了多项反窃取防御机制。

## [不会编译?,点我](https://github.com/disimingqianqian/PY-2FA/releases)
## ✨ 核心安全特性

*   **🛡️ 纯本地加密**：采用主密码机制，所有 TOTP 密钥加密保存在本地数据库中，绝不经过任何第三方服务器。
*   **⏱️ NTP 时间同步**：自动连接 NTP 服务器（如 `ntp.tencent.com`）校准本地时间偏移，确保动态验证码永远不会因为系统时间偏差而失效。
*   **🚫 防截屏保护**：调用 Windows 底层 API，防止第三方截图软件、录屏软件或恶意程序抓取验证码（开启保护后，截图工具会显示黑屏）。
*   **🕵️ 防虚拟机运行**：内置环境检测机制，拒绝在 VMware、VirtualBox 等虚拟机中运行，防止密钥在沙箱环境中被批量克隆分析。
*   **📌 系统托盘常驻**：基于 `pystray` 动态绘制系统托盘图标，轻量运行，随用随取，不占用任务栏空间。
*   **🖼️ 动态二维码生成**：内置二维码生成引擎，方便用户快速扫码绑定新账号。

## 🚀 运行环境

*   **操作系统**：Windows 7 +（由于使用了底层 Windows API，暂不支持 Linux / macOS）
*   **Python 环境**：Python 3.8.10 或更高版本
*   **硬件要求**：需要一台物理机（不支持虚拟机）

## 📦 从源码运行

1. **克隆项目到本地**（或直接下载 ZIP 解压）：
   ```bash
   git clone https://github.com/disimingqianqian/PY-2FA.git
   cd PY-2FA
