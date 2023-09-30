from flask import Flask, request
from flask import render_template
from ecdsa import SigningKey, SECP256k1
from Crypto.Cipher import AES, ARC4, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding
from hashlib import pbkdf2_hmac
import pyDes
import ast
import hashlib
import random
import pandas as pd
import datetime
import binascii
import json

app = Flask(__name__)

# ホーム
@app.route('/')
def home():
	title = "Crypt Technology"
	return render_template("index.html", title=title)

# 秘密鍵・公開鍵
@app.route('/publickey', methods=['GET'])
def publickey():
	title = "秘密鍵・公開鍵"
	return render_template("publickey.html", title=title)

@app.route('/publickey', methods=['POST'])
def publickey_make():
	title = "秘密鍵・公開鍵"
	secret_key = SigningKey.generate(curve = SECP256k1)
	secret_key_hex = secret_key.to_string().hex()
	public_key = secret_key.verifying_key
	public_key_hex = public_key.to_string().hex()
	return render_template("publickey.html", secret_key=secret_key_hex, public_key=public_key_hex, title=title)

# AES暗号化
@app.route('/aes', methods=['GET'])
def aes():
	title = "AES暗号化"
	return render_template("aes.html", title=title)

@app.route('/aes', methods=['POST'])
def aes_encrypt():
	title = "AES暗号化"
	targetText = request.form.get('text')
	passPhrase = request.form.get('passphrase')
	salt = get_random_bytes(16)
	iv = get_random_bytes(16)

	key = pbkdf2_hmac('sha256', bytes(passPhrase, encoding='utf-8'), salt, 50000, int(128/8))
	aes = AES.new(key, AES.MODE_CBC, iv)
	data = Padding.pad(targetText.encode('utf-8'), AES.block_size, 'pkcs7')
	encrypted = aes.encrypt(data)

	return render_template("aes.html", encrypted=encrypted, salt=salt, iv=iv, title=title)

# DES暗号化
@app.route('/des', methods=['GET'])
def des():
	title = "DES暗号化"
	return render_template("des.html", title=title)

@app.route('/des', methods=['POST'])
def des_encrypt():
	title = "AES暗号化"
	targetText = request.form.get('text')
	key = "DESCRYPT"
	iv = b"\0\0\0\0\0\0\0\0"
	k = pyDes.des(key, pyDes.CBC, iv, pad=None, padmode=pyDes.PAD_PKCS5)
	encrypted = k.encrypt(targetText)

	return render_template("des.html", encrypted=encrypted, key=key, iv=iv, title=title)

# RC4ストリーム暗号
@app.route('/rc4', methods=['GET'])
def rc4():
	title = "RC4ストリーム暗号"
	return render_template("rc4.html", title=title)

@app.route('/rc4', methods=['POST'])
def rc4_encrypt():
	title = "RC4ストリーム暗号"
	targetText = request.form.get('text').encode('utf-8')
	key = request.form.get('key').encode('utf-8')
	cipher = ARC4.new(key)
	encrypted = cipher.encrypt(targetText)

	return render_template("rc4.html", encrypted=encrypted, title=title)

# RSA暗号
@app.route('/rsa', methods=['GET'])
def rsa():
	title = "RSA暗号"
	return render_template("rsa.html", title=title)

@app.route('/rsa', methods=['POST'])
def rsa_encrypt():
	title = "RSA暗号"
	targetText = request.form.get('text').encode('utf-8')
	keyPair = RSA.generate(1024)
	pubKey = keyPair.publickey()

	encryptor = PKCS1_OAEP.new(pubKey)
	encrypted = encryptor.encrypt(targetText)

	return render_template("rsa.html", encrypted=encrypted, privateKey=keyPair, publicKey=pubKey, title=title)

# hash化
@app.route('/hash', methods=['GET'])
def hash():
	title = "ハッシュ化"
	return render_template("hash.html", title=title)

@app.route('/hash', methods=['POST'])
def hash_sha256():
	title = "ハッシュ化"
	sha256 = hashlib.sha256()
	targetText = request.form.get('text')
	sha256.update(targetText.encode())
	hashed = sha256.hexdigest()

	return render_template("hash.html", hashed=hashed, title=title)

# 擬似乱数
@app.route('/random', methods=['GET'])
def random_generate():
	title = "擬似乱数生成"
	return render_template("random.html", title=title)

@app.route('/random', methods=['POST'])
def random_generated():
	title = "擬似乱数生成"
	start = request.form.get('start')
	end = request.form.get('end')
	step = request.form.get('step')
	num = random.randrange(int(start), int(end), int(step))

	return render_template("random.html", num=num, title=title)

# 電子署名
@app.route('/signature', methods=['GET'])
def signature():
	title = "電子署名"
	return render_template("signature.html", title=title)

@app.route('/signature', methods=['POST'])
def signatured():
	title = "電子署名"
	secret_key_A_str = "7bdd8ccab9efc9119264eef9ac65d8ae405c6ca91f64b3315923ac34fe41d1aa"
	public_key_B_str = "3eee2b9991f112655af91f12b13503771b842d550356d3794f528927ce7e4fd124cdee9d0d9b1afd0a3d53724cfcad64131f43ff28ef28f1a216523237ecd260"

	secret_key_A = SigningKey.from_string(binascii.unhexlify(secret_key_A_str), curve=SECP256k1)
	public_key_A = secret_key_A.verifying_key
	public_key_A_str = public_key_A.to_string().hex()
	time_now = datetime.datetime.now(datetime.timezone.utc).isoformat()

	unsigned_transaction = {"time": time_now, "sender": public_key_A_str, "receiver": public_key_B_str, "amount": 3}
	transaction = json.dumps(unsigned_transaction).encode('utf-8')
	signature = secret_key_A.sign(transaction)

	return render_template("signature.html", signature=signature, transaction=transaction, title=title)

if __name__ == '__main__':
	app.run(debug=True, host='192.168.56.10', port=8000)