来源 网络 未知
https://github.com/zengfr/ida-pro-idb-database/tree/main/demo/2

def hexdump(payload, length=0):
    '''
    Represent byte string as hex -- for debug purposes
    '''
    return ':'.join('{0:02x}'.format(c) for c in payload[:length] or payload)

def hexload(data):
    return bytes(bytearray((int(x, 16) for x in data.split(':'))))
def bytes2bin(bytes):
    arr = []
    for v in [m for m in bytes]:
        arr.append(
            [(v & 128) >> 7, (v & 64) >> 6, (v & 32) >> 5, (v & 16) >> 4, (v & 8) >> 3, (v & 4) >> 2, (v & 2) >> 1,
             v & 1])
    return [i for j in arr for i in j]
 
 
def bin2bytes(arr):
    length = len(arr) // 8
    arr1 = [0 for _ in range(length)]
    for j in range(length):
        arr1[j] = arr[j * 8] << 7 | arr[j * 8 + 1] << 6 | arr[j * 8 + 2] << 5 | arr[j * 8 + 3] << 4 | arr[
            j * 8 + 4] << 3 | arr[j * 8 + 5] << 2 | arr[j * 8 + 6] << 1 | arr[j * 8 + 7]
    return bytes(arr1)
 
import gmpy2

RSA_SK = '''-----BEGIN RSA PRIVATE KEY-----
-----END RSA PRIVATE KEY-----'''
# openssl genrsa 512
PKCS_MAGIC = bytes.fromhex('0001FFFF FFFFFF00')


def bignum_to_bytes(num: int, pad: int = 0) -> bytes:
    """将大数按大端序转换为字节序列"""
    hexstr = hex(num)[2:]
    hexstr = '0' + hexstr if len(hexstr) % 2 else hexstr
    hex_arr = [int(hexstr[i: i + 2], 16) for i in range(0, len(hexstr), 2)]
    hex_arr.reverse()
    if pad and len(hex_arr) != pad:
        hex_arr.extend([0] * (pad - len(hex_arr)))
    hex_arr.reverse()
    return bytes(hex_arr)


def bytes_to_bignum(data: bytes) -> int:
    """解析大端序存储的大数"""
    data_arr = list(map(lambda b: f"{b:02X}", data))
    return int(''.join(data_arr), 16)


def rsa512_pkcs_v1_5_encrypt(d: int, N: int, data: bytes) -> int:
    """精简版的加密"""
    assert len(data) == 32
    M = PKCS_MAGIC + data
    M = bytes_to_bignum(M)
    return int(gmpy2.powmod(M, d, N))


def rsa512_pkcs_v1_5_decrypt(e: int, N: int, data: bytes) -> bytes:
    assert len(data) == 64
    C = bytes_to_bignum(data)
    M = gmpy2.powmod(C, e, N)
    M = bignum_to_bytes(M, 64)
    assert M[0:32] == PKCS_MAGIC and len(M) == 64
    M = M[32:]
    print(bytelist_to_hexstr(M))
    return M
import ideacipher

BLOCK_SIZE = 8
def idea_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    plaintext = b''
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        if len(block) == BLOCK_SIZE:
            plaintext += bytes(ideacipher.decrypt(block, key))
        else:
            for b in block:
                plaintext += struct.pack('<B', (b ^ 0xc5) & 0xff)
    return plaintext


def idea_encrypt(key: bytes, plaintext: bytes) -> bytes:
    cipher = b''
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i + BLOCK_SIZE]
        if len(block) == BLOCK_SIZE:
            cipher += bytes(ideacipher.encrypt(block, key))
        else:
            for b in block:
                cipher += struct.pack('<B', (b ^ 0xc5) & 0xff)
    return cipher
def pack_str(s: str) -> bytes:
    """将字符串打包"""
    num = len(s)
    assert num < 0xffffffff
    if num < 0xff:
        return struct.pack('<B', num) + s.encode()
    else:
        return b'\xff' + struct.pack('>I', num) + s.encode()


def seralize_node(node) -> bytes:
    out = b''
    if isinstance(node, dict):
        out += b'\x0c'
        out += struct.pack('<B', len(node))
        for k, v in node.items():
            out += pack_str(k)
            out += seralize_node(v)
    elif isinstance(node, (list, tuple)):
        for v in node:
            out += seralize_node(v)
    elif isinstance(node, str):
        out += b'\x06'
        out += pack_str(node)
    elif isinstance(node, int):
        out += b'\x03'
        out += struct.pack('>I', node)
    elif isinstance(node, DateTime):
        out += b'\x0a'
        out += node.seralize()
    elif isinstance(node, bool):
        if node:
            out += b'\x01'
        else:
            out += b'\x02'
    else:
        raise NotImplemented('S')
    return out


def seralize2(json_data):
    data = struct.pack('>IHH', 0xffffffff, 0x01, 0x02) + seralize_node(json_data)  # flag + type + version
    return data
def gen_lic(json_data):
    # 序列化数据
    data = struct.pack('>I', 0xffffffff) + seralize2(json_data)
    print('证书内容：', data)
    # 计算MD5
    checksum = md5()
    checksum.update(data)
    checksum = checksum.hexdigest()
    print('校验和：', checksum)
    checksum = hexstr_to_bytelist(checksum)
    # 对称加密
    idea_key = '000100020c024544000100020c024544'
    idea_key = hexstr_to_bytelist(idea_key)
    data = idea_encrypt(idea_key, data)
    print('密文：', bytelist_to_hexstr(data).replace(' ', ''))
    # 非对称加密
    rsa_plaintext = idea_key + checksum
    RSA_KEYPAIR = RSA.importKey(RSA_SK)
    N = RSA_KEYPAIR.n
    e = RSA_KEYPAIR.e
    d = RSA_KEYPAIR.d
    rsa_cipher = rsa512_pkcs_v1_5_encrypt(d, N, rsa_plaintext)
    print('RSA N: ', bytelist_to_hexstr(bignum_to_bytes(N, 64)))
    print('RSA e: ', bytelist_to_hexstr(bignum_to_bytes(e, 32)))
    print('RSA d: ', bytelist_to_hexstr(bignum_to_bytes(d, 32)))
    data = bignum_to_bytes(rsa_cipher, 64) + data
    # base64编码
    data = base64.b64encode(data)
    print('证书: ', data.decode())
    print('编码后证书: ', quote_from_bytes(data, safe=''))