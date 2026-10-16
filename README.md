# ⬡ NetScope Matrix — 全方位網路連通矩陣與封包威脅透視控制台

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20%7C%20Server-lightgrey.svg)]()
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://microsoft.com/PowerShell)
[![PacketScope](https://img.shields.io/badge/Engine-PacketScope%20Inside-blueviolet.svg)](https://github.com/kerr20801/PacketScope)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

專為網路工程師、資安工程師與系統維運人員打造的**雙輪驅動（主動驗收 + 被動透視）**神兵利器！  
**純原生架構、零外部依賴、免裝 Python / Node.js、本機安全處理不外傳。**

---

## 🌟 解決什麼核心痛點？

在大型專案上線、機房移轉或防火牆開通變更時，工程師最常面臨三大折磨：
1. **主動驗收手動敲到死**：資安或網管開了 50 條 Firewall Policy，工程師要在終端機一筆一筆敲 `Test-NetConnection` 或 `nc -zv`，一筆逾時等 20 秒，50 筆等 15 分鐘。
2. **測不通時不知該怪誰**：不通到底是被防火牆 Silent Drop 丟包？還是 DNS 查不到？還是其實防火牆已經通了，但對方伺服器上的應用程式（MSSQL / IIS / Docker）根本沒啟動？
3. **無 SIEM/NetFlow 時的被動分析難題**：跳板機上只有 `tcpdump` 原始輸出，面對幾萬行文字很難一眼看出有沒有被植入 C2 後門、有沒有人在掃描端口、有沒有資料外洩。

**NetScope 一站式將「主動並發探測」與「被動封包威脅透視 (PacketScope)」深度融合！**

---

## 🚀 三大核心模組

### 模組 1：🚀 主動連通矩陣 & 防火牆驗收 (Active Matrix)
* **Excel 表格貼上即測**：支援直接從 Excel 貼上（逗號、Tab 或空格分隔），每行一筆（`目標IP, Port, 服務說明, 業務分組, 協定(可選)`）。
* **多協定完整支援（TCP / UDP / ICMP）**：
  - 支援全域下拉選單或個別行設定（支援 `tcp`、`udp`、`icmp`、`53/udp`、`udp://` 等靈活語法）。
  - 自動協定辨識：DNS (53)、NTP (123)、SNMP (161)、Syslog (514) 等自動套用 UDP 探測機制。
* **.NET 非同步超高速並發探測**：
  - 底層採用 .NET 非同步 Socket I/O 模型，**50~100 筆目標同時並發發起，3 秒內全部掃描完畢**！
* **智慧故障診斷（維運甩鍋神器 ⭐）**：
  - `🟢 PASS`：
    - **TCP**：TCP 三向交握成功，即時顯示 RTT 延遲毫秒（如 `8ms`）。
    - **UDP**：收到應用服務回應（如 DNS 解析、NTP 校時、SNMP 回應），延遲極準。
    - **ICMP**：Ping 回應正常。
  - `🔴 FIREWALL DROP`：連線逾時，代表防火牆 Policy 未開或路由丟包。
  - `🟠 PORT CLOSED (RST / ICMP Unreachable)`：
    - **TCP**：收到 TCP RST 封包。
    - **UDP**：收到目標主機回應之 **ICMP Port Unreachable (Winsock 10054)**！
    - **重大意義**：證明**防火牆已經開通並抵達目標主機**，是目標伺服器未監聽該 Port（一秒證明非防火牆問題）！
  - `🟣 DNS ERROR`：主機名稱無法被 DNS 解析。
* **雙重視圖切換**：
  - **🔲 視覺化矩陣方格圖**：以卡片呈現連通性、延遲與 `[TCP]` / `[UDP]` / `[ICMP]` 標籤。
  - **📋 表格明細視圖**：支援關鍵字搜尋、狀態篩選與協定篩選。
* **一鍵匯出驗收單**：單鍵匯出 UTF-8 BOM CSV 驗收報告，直接附於工單簽核。
* **🎭 內建一鍵仿真模擬 (Demo 演示)**：無需實體設備，點擊「🎭 一鍵載入仿真驗收結果」立即體驗全狀態矩陣與卡片聯動。

---

### 模組 2：🔍 封包威脅透視分析器 (PacketScope Threat Engine)
完整整合知名開源專案 [PacketScope](https://github.com/kerr20801/PacketScope) 核心引擎：
* **純前端本機運算**：支援貼上 `tcpdump -tttt -nn` 文本或拖曳 `.txt` 檔案，封包資料絕不外傳。
* **6 大威脅偵測模組**：
  1. **Beaconing / C2 心跳**：採用中位數與截尾變異係數 (MAD / CV) 演算法，容忍網路掉包與重傳，精準抓出後門定期回連。
  2. **DNS 隧道 & DGA 網域**：計算 Shannon 資訊熵 (Shannon Entropy)，揪出高亂度網域與以 DNS 偽裝的資料外傳。
  3. **Port Scan / Host Scan**：30 秒滑動視窗雙指標雙向偵測垂直與水平掃描。
  4. **可疑高危險 Port**：偵測 Metasploit (4444)、後門 (1337/31337)、IRC 殭屍網路、明文 Telnet/VNC/RDP 等。
  5. **流量異常暴增**：CUSUM 基線變化點統計，自動抓出 DDoS 或流量突波。
  6. **資料外洩 (Exfil)**：依時長速率與封包尺寸 IQR 動態研判外傳異常。
* **三大即時場景範例**：
  - `🚨 綜合威脅場景` (C2心跳 + 端口掃描 + 巨量外洩 + 流量突波)
  - `🛡️ 純正常業務流量` (展示 0 威脅通過狀態)
  - `💥 DDoS 攻擊流量` (SYN 洪水突波)
* **視覺化圖表**：純 HTML5 Canvas 繪製封包時間軸柱狀圖與 Top 來源 IP 分布圖。
* **封包明細檢索**：支援搜尋、出站/入站/內網方向篩選與 TCP/UDP/ICMP 協定過濾。

---

### 模組 3：🎯 故障即時抓包診斷 (Probe & Sniff)
* **聯動合體技**：在「主動連通矩陣」測到不通時，點擊 **`🔍 抓包`**，系統立即針對該目標發起連線並擷取底層封包交握歷程。
* **支援 TCP 與 UDP 協定追蹤**：自選 TCP 握手（SYN/ACK/RST）或 UDP 探測（Request/ICMP Unreachable）。
* **快速預設選單**：
  - 真實連線測試：Google DNS (8.8.8.8:53 UDP)、Cloudflare (1.1.1.1:443 TCP)、本機服務 (127.0.0.1:8900 TCP)
  - 仿真示範：TCP 握手成功、服務未啟動 RST、防火牆阻擋丟包、UDP ICMP Unreachable
* **一鍵轉入 PacketScope**：產生的封包追蹤可**一鍵轉入 PacketScope 引擎**進行視覺化分析，清楚印證封包到底是卡在 SYN、收到 RST 還是無回應！

---

## 🎭 隨附獨立模擬測試資料包 (Mock Lab Toolkit)

手上沒有測試設備或封包？本專案附贈三款開箱即用之模擬測試套件：

1. **`mock_packets.txt` (標準 tcpdump 封包文字檔)**：
   - 內建 5 種真實世界流量場景（正常 HTTPS、C2 定時心跳、垂直端口掃描、8KB 巨量外洩、DDoS SYN Flood）。
   - 可直接在記事本開啟、複製貼上或拖曳至網頁中進行分析。
2. **`mock_targets.csv` (防火牆驗收清單 CSV)**：
   - 包含 Web、DB、快取、DNS、NTP、Drop、RST、DNS Error 等 18 筆完整目標規則，可直接以 Excel 開啟或貼入分頁 1 測試。
3. **`mock_lab.ps1` (本機微型服務模擬器)**：
   - 執行 `powershell -ExecutionPolicy Bypass -File .\mock_lab.ps1`
   - 自動於本機開啟 TCP 8080 (回應 HTTP 200 OK) 與 UDP 5353 (Echo 回應)，即可在不用外網的環境下體驗 100% 真實 Socket 握手！

---

## 📁 專案架構

```text
NetScope/
  ├── index.html        # 前端單頁應用 (連通矩陣 + PacketScope 引擎 + Canvas 圖表 + 仿真模組)
  ├── server.ps1        # 本機非同步並發探測伺服器 (支援 TCP/UDP/ICMP 並發與抓包)
  ├── 啟動服務.bat       # 一鍵啟動 (自動開啟預設瀏覽器 http://localhost:8900/)
  ├── mock_packets.txt  # 獨立仿真 tcpdump 封包文字檔 (可直接拖曳分析)
  ├── mock_targets.csv  # 獨立防火牆驗收清單 CSV (可直接 Excel 開啟)
  ├── mock_lab.ps1      # 本機模擬測試服務腳本 (開啟本地 TCP 8080 / UDP 5353 監聽)
  ├── README.md         # 專案詳細說明文件
  └── LICENSE           # MIT 開源授權協議
```

---

## 🚀 快速開始

1. 雙擊執行目錄中的 **`啟動服務.bat`**。
2. 預設瀏覽器會自動彈出控制台頁面（`http://localhost:8900/`）。
3. 依照您的需求體驗三大模組：
   - **分頁 1**：點擊 **`🎭 一鍵載入仿真驗收結果`** 立即看視覺化矩陣，或點擊 **`📋 載入企業工單範例`** 發起真實並發探測！
   - **分頁 2**：點擊 **`🚨 載入綜合威脅範例`** 或將 `mock_packets.txt` 拖曳入框，秒速看 AI 統計威脅分析與 Canvas 圖表！
   - **分頁 3**：在下拉選單選擇預設情境，點擊 **`⚡ 發起連線`** 或 **`🎭 載入仿真封包`**，再點擊 **`🚀 一鍵傳送至 PacketScope`**！

---

## 👨‍💻 作者 (Author)
* **Kerr** ([@kerr20801](https://github.com/kerr20801))
* 核心威脅分析演算法源自：[kerr20801/PacketScope](https://github.com/kerr20801/PacketScope)

---

## 📄 License
MIT License. 歡迎自由修改、分發與用於企業內部維運。
