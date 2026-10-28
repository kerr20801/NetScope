# ⬡ NetScope Matrix — 全方位網路連通矩陣與現場小白排障導航儀

<div align="center">

[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)]()
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://microsoft.com/PowerShell)
[![Zero-Dependency](https://img.shields.io/badge/Fallback-Zero--Dependency%20Pure%20Python-orange.svg)]()
[![PacketScope](https://img.shields.io/badge/Engine-PacketScope%20Inside-blueviolet.svg)](https://github.com/kerr20801/PacketScope)
[![AI Architecture](https://img.shields.io/badge/Co--Architect-Google%20Gemini-cyan.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**專為現場駐點人員、網管工程師、資安窗口與系統維運打造的一站式現場排障神兵利器！**  
**「只有弱的是人，不是 AI！」—— 以頂級現場實戰思維驅動，將複雜全網排障簡化為傻瓜式 4 步推演！**

</div>

---

## 🌟 核心設計哲學：預設現場人員「什麼都不知道」

現場排障最容易犯的錯誤就是「工程師寫給工程師用」，充滿生硬代碼，現場駐點或工讀生完全看不懂：
* **不強加火星名詞**：嚴禁只拋出 `TCP RST`、`ICMP Unreachable`、`STP TCN`、`iptables` 等專業代碼。
* **能自動測的絕不讓現場人員動手**：本機網卡、網關 IP、目標連通、Loop 延遲與 Jitter 全自動背景完成。
* **結論一律講白話人話**：直接大字標記【誰該負責】、【該找誰處理】、【該拔哪條線】！
* **一鍵交差神器**：提供【一鍵複製 LINE / Teams 現場回報單】，現場人員點一下貼給主管即可交差！

---

## 🚀 四大核心模組

### 模組 0：🧭 現場小白極速排障導航儀 (Zero-Knowledge Sequential Triage Navigator ⭐ NEW)
以**「4 階節點證據鏈 (Sequential Hop-by-Hop Triage)」**標準化現場排障順序，長度彈性適配（2 ~ 4 跳）：

1. **💻 節點 1：發起源主機端 (Local Source / Linux 或 Windows)**：
   * 自動取得本機 IP、網卡狀態與預設閘道。
   * 提供本機 Linux / Windows 排查指令包（`ip addr`, `ip route`, `ss -tan`），排除主機自我配置問題。
2. **🖧 節點 2：第一台串接交換機 (First-Hop Switch / 接入交換機)**：
   * **🌀 L2 Loop 環路與廣播風暴快篩**：精準測量第一跳網關 RTT 與延遲抖動 (Jitter)。
   * 若延遲飆破數百毫秒且持續丟包，立即發布 **「🚨 現場發生 L2 迴圈 (Loop)，交換機快被廣播風暴灌爆了！」** 警報。
   * 提供交換機檢查指令一鍵複製（Cisco/Aruba/Junos）與 Log 貼入智慧過濾。
3. **🛡️ 節點 3：網關設備 / 防火牆 (Gateway / Firewall / Core)**：
   * 驗證 L3 跨網段轉發與路由可達性，區分是通暢還是被隱性 Deny 阻斷。
   * 提供網關/防火牆排查指令包（Cisco / FortiGate）。
4. **🐧 節點 4：目的地端點主機 (Target Server / Linux 伺服器)**：
   * 探測目標連接埠狀態：精準區分 `PASS` (通暢)、`REFUSED` (收到 TCP RST，**鐵證證明網路完全暢通，是對方的 Linux 服務根本沒開！**)、`DROP` (防火牆阻擋)。
   * 提供 Linux 伺服器端排查指令包（`ss -tulpn`, `iptables`, `dmesg`）。

* **📋 一鍵複製 LINE / Teams 現場回報單**：
  * 單鍵複製排版精美的回報文本，直接傳入工作群組交差，責任歸屬一目了然！

---

### 模組 1：🚀 主動連通矩陣 & 防火牆驗收 (Active Matrix)
* **Excel 表格貼上即測**：支援直接從 Excel 貼上（逗號、Tab 或空格分隔），每行一筆（`目標IP, Port, 服務說明, 業務分組, 協定(可選)`）。
* **多協定完整支援（TCP / UDP / ICMP）**：
  - 支援全域下拉選單或個別行設定（支援 `tcp`、`udp`、`icmp`、`53/udp`、`udp://` 等語法）。
  - 自動協定辨識：DNS (53)、NTP (123)、SNMP (161)、Syslog (514) 等自動套用 UDP 探測機制。
* **高並發非同步極速探測**：
  - 支援 .NET 非同步 Socket 與 Python 3 執行緒池，**50~100 筆目標 3 秒內全部掃描完畢**！
* **雙重視圖切換**：矩陣方格圖與表格明細視圖，單鍵匯出 UTF-8 BOM CSV 驗收報告。

---

### 模組 2：🔍 封包威脅透視分析器 (PacketScope Threat Engine)
完整整合知名開源專案 [PacketScope](https://github.com/kerr20801/PacketScope) 核心引擎：
* **純前端本機運算**：支援貼上 `sudo tcpdump -tttt -nn -q -i any > capture.txt` 產生的文本或拖曳 `.txt` 檔案，封包資料絕不外傳。
* **Linux 現場必備抓包指令**：`sudo tcpdump -tttt -nn -q -i any > capture.txt`（以 `-i any` 監聽所有網卡，產生 `capture.txt` 拖入網頁即可秒級分析）。
* **6 大威脅偵測模組**：
  1. **Beaconing / C2 心跳**：中位數與截尾變異係數 (MAD / CV) 演算法，容忍掉包與重傳，抓出定時後門。
  2. **DNS 隧道 & DGA 網域**：計算 Shannon 資訊熵，揪出以 DNS 偽裝的機密外洩。
  3. **Port Scan / Host Scan**：30 秒滑動視窗雙指標雙向偵測垂直與水平掃描。
  4. **可疑高危險 Port**：Metasploit (4444)、後門 (1337/31337)、明文 Telnet/VNC/RDP 等。
  5. **流量異常暴增**：CUSUM 基線變化點統計，自動抓出 DDoS 或流量突波。
  6. **資料外洩 (Exfil)**：依時長速率與封包尺寸 IQR 動態研判外傳異常。

---

### 模組 3：🎯 故障即時抓包診斷 (Probe & Sniff)
* 在「主動連通矩陣」測到不通時，點擊 **`🔍 抓包`**，系統立即針對該目標發起連線並擷取底層封包交握歷程。
* 一鍵轉入 PacketScope 引擎進行視覺化分析，清楚印證封包到底是卡在 SYN、收到 RST 還是無回應！

---

## 📁 專案架構

```text
NetScope/
  ├── index.html        # 前端單頁應用 (小白導航儀 + 連通矩陣 + PacketScope + 抓包)
  ├── server.py         # 跨平台 Python 3 原生標準庫伺服器 (Win / Mac / Linux 通用)
  ├── server.ps1        # Windows 原生 PowerShell 非同步伺服器 (免裝 Python 雙擊即用)
  ├── test_engine.py    # 單元測試腳本 (驗證網關探測、Socket 探測、逐跳排障)
  ├── run.sh            # macOS / Linux 一鍵啟動腳本 (POSIX Shell)
  ├── 啟動服務.bat       # Windows 雙軌自動容錯啟動器 (優先 Python，備援 PowerShell)
  ├── mock_packets.txt  # 獨立仿真 tcpdump 封包文字檔 (可直接拖曳分析)
  ├── mock_targets.csv  # 獨立防火牆驗收清單 CSV (可直接 Excel 開啟)
  ├── mock_lab.ps1      # 本機模擬測試服務腳本 (開啟本地 TCP 8080 / UDP 5353 監聽)
  ├── README.md         # 專案詳細說明文件
  └── LICENSE           # MIT 開源授權協議
```

---

## 🚀 跨平台啟動方式

### 🪟 Windows 環境
* **直接滑鼠雙擊 `啟動服務.bat`**。
* 系統自動優先偵測 `python server.py`，若電腦未安裝 Python 則**無縫降級為原生 PowerShell `server.ps1`**，自動彈出瀏覽器。

### 🍎 macOS & 🐧 Linux 環境
* 開啟終端機執行：
  ```bash
  chmod +x run.sh
  ./run.sh
  ```
* 或直接執行：
  ```bash
  python3 server.py
  ```

---

## 👨‍💻 作者與致謝 (Author & Acknowledgement)
* **架構與維護者**：Kerr ([@kerr20801](https://github.com/kerr20801)) & Google Gemini
* **核心哲學**：*「只有弱的是人，不是 AI！(The limitation lies in human direction, not AI.)」*
* **威脅引擎**：源自開源專案 [kerr20801/PacketScope](https://github.com/kerr20801/PacketScope)

---

## 📄 License
MIT License. 歡迎自由修改、分發與用於企業內部維運。
