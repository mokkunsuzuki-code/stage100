"""
qs_tls_server.py - QS-TLS Server
QKD + X25519 ハイブリッド鍵交換 + レコード層 + 鍵更新
"""

import socket
import json
from typing import Any, Tuple

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
PORT = 50100  # Stage100 用ポート


# ======== PQ鍵ロード（dict / tuple 両対応） ========

def _normalize_pq_keys(info: Any) -> Tuple[bytes, bytes]:
    """
    pq_sign の戻り値を (public_key_bytes, secret_key_bytes) に正規化
    """
    import base64

    # dict の場合
    if isinstance(info, dict):
        pk_b64 = info.get("public_key_b64") or info.get("public_key")
        sk_b64 = info.get("private_key_b64") or info.get("private_key") or info.get("secret_key")
        if not pk_b64 or not sk_b64:
            raise RuntimeError("pq_sign の dict に public_key / private_key が含まれていません。")

        pk = base64.b64decode(pk_b64) if isinstance(pk_b64, str) else pk_b64
        sk = base64.b64decode(sk_b64) if isinstance(sk_b64, str) else sk_b64

        if not isinstance(pk, (bytes, bytearray)) or not isinstance(sk, (bytes, bytearray)):
            raise RuntimeError("pq_sign の鍵が bytes 形式になっていません。")
        return bytes(pk), bytes(sk)

    # tuple/list の場合
    if isinstance(info, (tuple, list)) and len(info) >= 2:
        pk_b64, sk_b64 = info[0], info[1]
        pk = base64.b64decode(pk_b64) if isinstance(pk_b64, str) else pk_b64
        sk = base64.b64decode(sk_b64) if isinstance(sk_b64, str) else sk_b64
        if not isinstance(pk, (bytes, bytearray)) or not isinstance(sk, (bytes, bytearray)):
            raise RuntimeError("pq_sign の tuple 鍵が bytes 形式ではありません。")
        return bytes(pk), bytes(sk)

    raise RuntimeError("pq_sign.ensure_server_keys() の戻り値形式が想定外です。")


def load_or_create_pq_keys() -> Tuple[bytes, bytes]:
    if hasattr(pq_sign, "ensure_server_keys"):
        info = pq_sign.ensure_server_keys()
    elif hasattr(pq_sign, "generate_or_load_server_keys"):
        info = pq_sign.generate_or_load_server_keys()
    else:
        raise RuntimeError(
            "pq_sign.py に ensure_server_keys / generate_or_load_server_keys が見つかりません。"
        )
    return _normalize_pq_keys(info)


# ======== メイン ========

def main():
    print("=== QS-TLS Server (Stage100) ===")

    # QKD鍵ロード
    qkd_key = load_qkd_key("final_key.bin")
    print(f"[Server] QKD鍵読込み完了: {len(qkd_key)} バイト")

    # PQ署名鍵ロード
    pq_public_key, pq_secret_key = load_or_create_pq_keys()
    print(f"[Server] PQ公開鍵長: {len(pq_public_key)} バイト")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[Server] Listening on {HOST}:{PORT} ...")

        conn, addr = s.accept()
        with conn:
            print(f"[Server] クライアント接続: {addr}")

            # === Handshake: ClientHello ===
            rtype, payload = recv_record(conn)
            if rtype != RECORD_TYPE_HANDSHAKE:
                raise RuntimeError("[Server] 最初のメッセージが Handshake ではありません。")

            ch = json.loads(payload.decode("utf-8"))
            if ch.get("msg_type") != "client_hello":
                raise RuntimeError("[Server] client_hello が来ていません。")
            print("[Server] ClientHello 受信:", ch)

            # X25519 鍵ペア生成
            server_x_priv, server_x_pub = generate_x25519_keypair()

            # === Handshake: ServerHello ===
            sh = {
                "msg_type": "server_hello",
                "protocol": "QS-TLS-1.0",
                "group": "x25519",
            }
            send_record(conn, RECORD_TYPE_HANDSHAKE, json.dumps(sh).encode("utf-8"))
            print("[Server] ServerHello 送信")

            # === Handshake: ServerAuth (X25519 + PQ署名) ===
            payload_to_sign = b"QS-TLS-SERVER-AUTH|" + server_x_pub
            if not hasattr(pq_sign, "sign_message"):
                raise RuntimeError("pq_sign.py に sign_message() がありません。")

            signature = pq_sign.sign_message(payload_to_sign, pq_secret_key)

            sa = {
                "msg_type": "server_auth",
                "x25519_pub": server_x_pub.hex(),  # 16進文字列で送る
                "signature": signature.hex(),
            }
            send_record(conn, RECORD_TYPE_HANDSHAKE, json.dumps(sa).encode("utf-8"))
            print("[Server] ServerAuth 送信")

            # === Handshake: ClientKey ===
            rtype, payload = recv_record(conn)
            if rtype != RECORD_TYPE_HANDSHAKE:
                raise RuntimeError("[Server] ClientKey が Handshake レコードではありません。")
            ck = json.loads(payload.decode("utf-8"))
            if ck.get("msg_type") != "client_key":
                raise RuntimeError("[Server] client_key が来ていません。")

            client_x_pub_bytes = bytes.fromhex(ck["x25519_pub"])
            client_x_pub = load_peer_public_key(client_x_pub_bytes)
            print("[Server] ClientKey 受信")

            # 共有秘密 + ハイブリッドAES鍵
            shared_secret = derive_shared_secret(server_x_priv, client_x_pub)
            aes_key = hybrid_derive_aes_key(qkd_key, shared_secret, length=32)
            print(f"[Server] ハイブリッドAES鍵 長さ: {len(aes_key)} バイト (AES-256)")
            print("[Server] Handshake 完了。アプリケーションデータ受信を開始します。")

            # === Application Data ループ ===
            current_key = aes_key
            while True:
                rtype, payload = recv_record(conn)

                if rtype == RECORD_TYPE_APPLICATION_DATA:
                    # 暗号化データの復号
                    try:
                        plaintext = decrypt_app_data(current_key, payload)
                    except Exception as e:
                        print("[Server] 復号に失敗:", e)
                        continue

                    text = plaintext.decode("utf-8", errors="replace")
                    print("[Server] 受信メッセージ:", text)

                    if text == "/quit":
                        print("[Server] クライアントからの終了要求。接続を閉じます。")
                        break

                    # エコー返信
                    reply = f"[Server echo] {text}"
                    enc_payload = encrypt_app_data(current_key, reply.encode("utf-8"))
                    send_record(conn, RECORD_TYPE_APPLICATION_DATA, enc_payload)
                    print("[Server] エコーメッセージ送信")

                elif rtype == RECORD_TYPE_KEY_UPDATE:
                    # 鍵更新
                    current_key = update_application_key(current_key)
                    print("[Server] KeyUpdate 受信 → アプリケーション鍵を更新しました。")

                elif rtype == RECORD_TYPE_ALERT:
                    # 終了通知など（簡易実装）
                    if payload == b"close_notify":
                        print("[Server] close_notify 受信。接続を終了します。")
                        break
                    else:
                        print("[Server] Alert 受信:", payload)
                else:
                    print(f"[Server] 未知のレコードタイプを受信: {rtype}")


if __name__ == "__main__":
    main()
