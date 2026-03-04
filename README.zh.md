<h1 align="center">Skill Security Scan</h1>

<p align="center">
  <a href="README.md">English</a> | <strong>繁體中文</strong>
</p>

<p align="center">
  <a href="https://github.com/joneshong-skills/skill-security-scan/blob/main/LICENSE"><img src="https://img.shields.io/github/license/joneshong-skills/skill-security-scan?style=flat-square" alt="License"></a>
  <a href="https://github.com/joneshong-skills/skill-security-scan/stargazers"><img src="https://img.shields.io/github/stars/joneshong-skills/skill-security-scan?style=flat-square" alt="GitHub Stars"></a>
</p>

<p align="center">Claude skill 檔案全面安全掃描 — 偵測 6 大威脅類別，從提示注入到跨 skill 污染。</p>

---

## 功能特色

- **6 大威脅類別** — 提示注入（S1）、權限提升（S2）、資料外洩（S3）、偏見注入（S4）、依賴混淆（S5）、跨 Skill 污染（S6）
- **兩階段分析** — 快速掃描（S1-S3）靜態模式比對，深度掃描（S4-S6）LLM 語意分析
- **批次模式** — 使用 `--all` 一次掃描所有 skill；先跑靜態掃描，僅對標記的 skill 進行深度分析
- **結構化報告** — PASS / WARN / BLOCK 判定，每項發現附帶嚴重等級、檔案:行號參照與修復建議
- **ast-grep 整合** — 結構化程式碼模式偵測，補充正規表示式掃描
- **持續學習** — 掃描後反思迴圈，隨時間更新 `known-patterns.md` 與 `lessons.md`

## 使用方式

### 觸發語句

> "掃描 skill 安全"、"檢查 skill 注入"、"安全稽核"、"skill-security-scan smart-search"

### 範例

```bash
# 掃描單一 skill（快速：S1-S3）
/skill-security-scan smart-search

# 深度掃描 skill（S1-S6）
/skill-security-scan smart-search --deep

# 批次掃描所有 skill
/skill-security-scan --all

# 掃描任意目錄
/skill-security-scan --path /path/to/skill-dir

# 直接執行靜態掃描器
python3 ~/.claude/skills/skill-security-scan/scripts/security-scan.py ~/.claude/skills/smart-search/
```

## 工作流程

1. **解析目標** — 將 skill 名稱對應至完整路徑，或展開 `--all` 取得清單
2. **盤點檔案** — 列出所有檔案；標記異常類型（`.exe`、`.so`、`.dylib`）為 S2 發現
3. **快速掃描（S1-S3）** — 執行 `security-scan.py` 進行靜態模式比對（注入、權限提升、資料外洩）
4. **深度掃描（S4-S6）** — LLM 語意分析偏見注入、依賴混淆與跨 skill 污染
5. **交叉比對** — 與 `known-patterns.md` 比對以過濾誤報
6. **產生報告** — 結構化 Markdown 報告，包含判定結果、發現表格與修復建議

## 整合

| 系統 | 關係 |
|------|------|
| **skill-security-gate**（hook） | 共享 S1-S3 規則；gate 在安裝時攔截，本 skill 按需稽核 |
| **skill-lifecycle** | Phase 2 將此掃描作為晉升硬門檻 |
| **skill-tester** | 可將 T6（安全）測試類別委派給本 skill |
| **create-skill** | 建立後的驗證觸發器 |

## 安裝

1. 將 skill 目錄複製至 `~/.claude/skills/skill-security-scan/`
2. 確認 `scripts/security-scan.py` 可執行：`chmod +x ~/.claude/skills/skill-security-scan/scripts/security-scan.py`
3. 選配：安裝 `ast-grep` 以啟用結構化掃描：`brew install ast-grep`

### 相依套件

- Python 3.12（僅使用標準函式庫）
- ast-grep（`sg`）— 選配，用於結構化模式偵測
- Claude Code — S4-S6 語意分析（深度掃描）必須

## 授權條款

[MIT](LICENSE)
