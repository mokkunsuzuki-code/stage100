# 🔐 QS-TLS (Quantum-Secure TLS) — Stage100
**Author: Motohiro Suzuki**  
**License: MIT License**  
**Version: Stage100 (QS-TLS Draft 1.0 Prototype)**

---

## 🧩 概要
QS-TLS は、量子時代の安全通信を実現するために設計された  
**ハイブリッド暗号化トランスポートプロトコル**です。

本プロトコルは以下の技術を統合しています：

- **QKD（量子鍵配送）由来の共通鍵**
- **X25519（楕円曲線Diffie–Hellman）**
- **SPHINCS+（耐量子署名）**
- **AES-256-GCM（高速・安全な共通鍵暗号）**
- **TLS1.3 風のハンドシェイク構造**
- **独自 Record Layer（暗号化通信フレーム）**
- **KeyUpdate（鍵ローテーション）**

現行の TLS1.3 と、ポスト量子暗号（PQC）および QKD を融合させた  
**世界初構造の量子セキュア通信プロトコル（試作版）**です。

---

## 🚀 Stage100 で実装されている機能

### ✔ Handshake（TLS1.3 型）
1. ClientHello  
2. ServerHello  
3. ServerAuth（SPHINCS+ 署名付き X25519 公開鍵）  
4. ClientKey  
5. Hybrid Key Derivation  
6. Application Data 開始  

### ✔ ハイブリッド鍵生成
HybridKey = HKDF( QKD_key || X25519_shared_secret )

shell
コードをコピーする
AES-256-GCM 用の鍵を安全に導出します。

### ✔ Record Layer（独自設計）
RecordType (1 byte)
Length (2 bytes)
Payload (variable)

yaml
コードをコピーする
TLS1.3 に近い拡張性ある構造を採用。

### ✔ Application Data 暗号化
すべて AES-GCM により暗号化。

### ✔ KeyUpdate（鍵ローテーション）
通信中に鍵を更新しても切れずに継続可能。

### ✔ CloseNotify（安全終了）
TLS と同様に安全にコネクションを終了可能。

---

## 📁 フォルダ構成

stage100/
final_key.bin
crypto_utils.py
pq_sign.py
pq_server_keys.json (自動生成)
qs_tls_common.py
qs_tls_server.py
qs_tls_client.py

yaml
コードをコピーする

---

## 💻 実行方法

### 1. 必要なライブラリのインストール
pip install cryptography

shell
コードをコピーする

### 2. サーバー起動
python3 qs_tls_server.py

shell
コードをコピーする

### 3. クライアント起動
python3 qs_tls_client.py

yaml
コードをコピーする

### 4. 使用できるコマンド
- 通常メッセージ → 双方向暗号通信  
- `/keyupdate` → 鍵ローテーション  
- `/quit` → 安全終了（close_notify）

---

## 🌍 本プロトコルの意義
QS-TLS は **ポスト量子時代の通信の基盤技術**を志向しています。

特徴：

- QKD（量子鍵）× PQC（耐量子暗号）× Modern TLS を統合  
- 現状の研究にも存在しない“個人実装の完全動作プロトコル”  
- 量子通信ネットワーク時代の標準候補になり得る構造  
- 研究・教育・企業評価に即適用可能

本プロトコルは研究目的の試作版として公開されています。

---

## 📜 著作権およびライセンス

### **Copyright © 2025 Motohiro Suzuki**

本プロジェクトは **MIT License** で提供されます。  
自由に利用・複製・改変・商用利用できますが、  
**著作権表示とライセンス文を保持すること**が条件です。

---

## 🔬 Author / Creator
**Motohiro Suzuki**

Original Creator of **QS-TLS (Quantum-Secure TLS Prototype)**  
Stage100: Hybrid QKD × PQC × Modern TLS Protocol Design

---

## ⭐ 今後の発展（Stage101+）
- RFC-style Draft（正式仕様書の作成）
- ファイル転送（Encrypted File Transport）
- 0-RTT / Session Ticket（高速化）
- KeySchedule 拡張（TLS1.3 完全準拠化）
- Network Simulator との統合
- 量子ネットワーク対応（QKD network ↔ QS-TLS）

---
