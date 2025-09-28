import hashlib
import time
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# ========== POW 部分 ==========
def pow(prefix, difficulty):
    target = "0" * difficulty
    nonce = 0
    start_time = time.time()

    while True:
        text = f"{prefix}{nonce}"
        hash_value = hashlib.sha256(text.encode()).hexdigest()
        if hash_value.startswith(target):
            elapsed = time.time() - start_time
            return nonce, text, hash_value, elapsed
        nonce += 1

# ========== RSA 签名 & 验证 ==========
def generate_keys():
    key = RSA.generate(2048)  # 生成 2048 位密钥对
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def sign_message(private_key, message):
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_signature(public_key, message, signature):
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

if __name__ == "__main__":
    nickname = "drake"   # 你的昵称

    # 生成公私钥
    private_key, public_key = generate_keys()

    # POW 找到满足 4 个 0 的哈希
    nonce4, text4, hash4, time4 = pow(nickname, 4)
    print(f"POW 难度 4 -> 花费时间: {time4:.4f}s, 内容: {text4}, 哈希: {hash4}")

    # 使用私钥对消息签名
    signature = sign_message(private_key, text4)
    print(f"签名结果: {signature.hex()}")

    # 使用公钥验证签名
    valid = verify_signature(public_key, text4, signature)
    print(f"验证结果: {'成功' if valid else '失败'}")
