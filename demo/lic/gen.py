import time
import json
import base64
import hashlib

from my_aes import My_AES_CBC


Aes_key = '9B8FD68A366F4D03'.encode()
Aes_IV = '305FB72D83134CA0'.encode('utf-8')
    
    
def getActiveCode(machine_code):
    encrypt_code = My_AES_CBC(Aes_key, Aes_IV).encrypt(machine_code)
    active_code = hashlib.md5(encrypt_code).hexdigest().upper()
    return active_code

def getTimeLimitedCode(machine_code, ts):
    active_code = getActiveCode(machine_code)
    data = {
        "code": active_code,
        "endTs": ts,
    }
    text = json.dumps(data);
    
    encrypt_code = My_AES_CBC(Aes_key, Aes_IV).encrypt(text)
    active_code = base64.b32encode(encrypt_code)
    return active_code.decode()
    
if __name__ == '__main__':
    machine_code = input('请输入机器码:')
    str_time = input('请输入到期时间，格式如：2023-05-20 12:00:00 \n')
    if not str_time:
      str_time='2099-12-21 12:00:00'
    time_array = time.strptime(str_time, '%Y-%m-%d %H:%M:%S')
    timestamp = int(time.mktime(time_array))
    active_code = getTimeLimitedCode(machine_code, timestamp)
    
    print('限时激活码:', active_code)
    with open('lic.txt', 'wb') as f:
      f.write(bytes(active_code, encoding="utf-8"))
    input('Press Enter to exit…')