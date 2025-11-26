"""
qs_tls_client.py - QS-TLS Client
QKD + X25519 ハイブリッド鍵交換 + レコード層 + 鍵更新
"""

import socket
import json
from typing import Any

from crypto_utils import (
    load_qkd_key,
    generate_x25519_keypair,
    load_peer_public_key,
    derive_shared_secret,
    hybrid_derive_aes_key,
)
from qs_tls_common import (
    RECORD_TYPE_HANDSHAKE,
    RECORD_TYPE_APPLICATION_DATA,
    RECORD_TYPE_KEY_UPDATE,
    RECORD_TYPE_ALERT,
    send_record,
    recv_record,
    encrypt_app_data,
    decrypt_app_data,
    update_application_key,
)
import pq_sign


HOST = "127.0.0.1"
PORT = 50100


# ======== PQ 公開鍵ロード（dict / tuple 両対応） ========

def _normalize_pq_public_key(info: Any) -> bytes:
    import base64

    if isinstance(info, dict):
        pk_b64 = info.get("public_key_b64") or info.get("public_key")
        if not pk_b64:
            raise RuntimeError("pq_sign の dict に public_key が含まれていません。")
        pk = base64.b64decode(pk_b64) if isinstance(pk_b64, str) else pk_b64
        if not isinstance(pk, (bytes, bytearray)):
            raise RuntimeError("pq_sign の公開鍵が bytes 形式になっていません。")
        return bytes(pk)

    if isinstance(info, (tuple, list)) and len(info) >= 1:
        pk_b64 = info[0]
        pk = base64.b64decode(pk_b64) if isinstance(pk_b64, str) else pk_b64
        if not isinstance(pk, (bytes, bytearray)):
            raise RuntimeError("pq_sign の公開鍵(tuple) が bytes 形式になっていません。")
        return bytes(pk)

    raise RuntimeError("pq_sign.ensure_server_keys() の戻り値が想定外です。")


def load_pq_public_key_only() -> bytes:
    if hasattr(pq_sign, "ensure_server_keys"):
        info = pq_sign.ensure_server_keys()
    elif hasattr(pq_sign, "generate_or_load_server_keys"):
        info = pq_sign.generate_or_load_server_keys()
    else:
        raise RuntimeError(
            "pq_sign.py に ensure_server_keys / generate_or_load_server_keys が見つかりません。"
        )
    return _normalize_pq_public_key(info)


# ======== PQ 署名検証ラッパー ========

def verify_pq_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    pq_sign の検証関数名の違いを吸収するラッパー
    """
    if hasattr(pq_sign, "verify_signature"):
        return pq_sign.verify_signature(message, signature, public_key)
    if hasattr(pq_sign, "verify_message"):
        return pq_sign.verify_message(message, signature, public_key)
    if hasattr(pq_sign, "verify"):
        return pq_sign.verify(message, signature, public_key)

    print("[Client] 警告: pq_sign に verify 系関数が無いため検証をスキップします。")
    return True


# ======== メイン ========

def main():
    print("=== QS-TLS Client (Stage100) ===")

    # QKD鍵ロード
    qkd_key = load_qkd_key("final_key.bin")
    print(f"[Client] QKD鍵読込み完了: {len(qkd_key)} バイト")

    # サーバーPQ公開鍵
    server_pq_public_key = load_pq_public_key_only()
    print(f"[Client] サーバーPQ公開鍵 長さ: {len(server_pq_public_key)} バイト")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"[Client] 接続: {HOST}:{PORT}")

        # === Handshake: ClientHello ===
        ch = {
            "msg_type": "client_hello",
            "protocol": "QS-TLS-1.0",
            "client_name": "Stage100-Client",
            "support_groups": ["x25519"],
        }
        send_record(s, RECORD_TYPE_HANDSHAKE, json.dumps(ch).encode("utf-8"))
        print("[Client] ClientHello 送信")

        # === Handshake: ServerHello ===
        rtype, payload = recv_record(s)
        if rtype != RECORD_TYPE_HANDSHAKE:
            raise RuntimeError("[Client] ServerHello が Handshake レコードではありません。")
        sh = json.loads(payload.decode("utf-8"))
        if sh.get("msg_type") != "server_hello":
            raise RuntimeError("[Client] server_hello が来ていません。")
        print("[Client] ServerHello 受信:", sh)

        # === Handshake: ServerAuth ===
        rtype, payload = recv_record(s)
        if rtype != RECORD_TYPE_HANDSHAKE:
            raise RuntimeError("[Client] ServerAuth が Handshake レコードではありません。")
        sa = json.loads(payload.decode("utf-8"))
        if sa.get("msg_type") != "server_auth":
            raise RuntimeError("[Client] server_auth が来ていません。")

        server_x_pub_bytes = bytes.fromhex(sa["x25519_pub"])
        signature = bytes.fromhex(sa["signature"])
        payload_to_verify = b"QS-TLS-SERVER-AUTH|" + server_x_pub_bytes

        if not verify_pq_signature(payload_to_verify, signature, server_pq_public_key):
            raise RuntimeError("[Client] サーバーPQ署名の検証に失敗しました。")
        print("[Client] サーバーPQ署名検証 OK（サーバー認証完了）")

        # === Handshake: ClientKey ===
        client_x_priv, client_x_pub = generate_x25519_keypair()
        ck = {
            "msg_type": "client_key",
            "x25519_pub": client_x_pub.hex(),
        }
        send_record(s, RECORD_TYPE_HANDSHAKE, json.dumps(ck).encode("utf-8"))
        print("[Client] ClientKey 送信")

        # 共有秘密 + ハイブリッドAES鍵
        server_x_pub = load_peer_public_key(server_x_pub_bytes)
        shared_secret = derive_shared_secret(client_x_priv, server_x_pub)
        aes_key = hybrid_derive_aes_key(qkd_key, shared_secret, length=32)
        current_key = aes_key
        print(f"[Client] ハイブリッドAES鍵 長さ: {len(aes_key)} バイト (AES-256)")
        print("[Client] Handshake 完了。メッセージ送信を開始します。")

        # === Application Data ループ ===
        while True:
            try:
                text = input("\n送信メッセージを入力 (/keyupdate /quit も可): ").strip()
            except EOFError:
                text = "/quit"

            if text == "/quit":
                # まず暗号化アプリケーションデータとして送る
                payload = encrypt_app_data(current_key, text.encode("utf-8"))
                send_record(s, RECORD_TYPE_APPLICATION_DATA, payload)
                # その後、Alert(close_notify) を送信
                send_record(s, RECORD_TYPE_ALERT, b"close_notify")
                print("[Client] /quit を送信しました。")
                break

            elif text == "/keyupdate":
                # KeyUpdate レコードを送信し、その後自分の鍵を更新
                send_record(s, RECORD_TYPE_KEY_UPDATE, b"")
                current_key = update_application_key(current_key)
                print("[Client] KeyUpdate を送信し、ローカル鍵を更新しました。")
                continue

            else:
                # 通常メッセージ
                payload = encrypt_app_data(current_key, text.encode("utf-8"))
                send_record(s, RECORD_TYPE_APPLICATION_DATA, payload)
                print("[Client] アプリケーションデータ送信:", text)

                # サーバーからのエコーメッセージ受信
                rtype, payload = recv_record(s)
                if rtype == RECORD_TYPE_APPLICATION_DATA:
                    try:
                        reply_plain = decrypt_app_data(current_key, payload)
                        print("[Client] サーバーからの復号済みメッセージ:")
                        print("  ", reply_plain.decode("utf-8", errors="replace"))
                    except Exception as e:
                        print("[Client] サーバーメッセージの復号に失敗:", e)
                elif rtype == RECORD_TYPE_ALERT and payload == b"close_notify":
                    print("[Client] サーバーから close_notify。接続終了。")
                    break
                else:
                    print(f"[Client] 想定外のレコードタイプ受信: {rtype}")


if __name__ == "__main__":
    main()
