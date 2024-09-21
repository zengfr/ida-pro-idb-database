import wmi
import os
import time
import json

import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from my_aes import My_AES_CBC
 

class Register:
    def __init__(self):
        self.Aes_key = '9B8FD68A366F4D03'.encode()
        self.Aes_IV = '305FB72D83134CA0'.encode('utf-8')
        
        self.pre_str = "HJDKAH"   # 前缀
        self.suf_str = "SDFDTY"   # 后缀
        
        # 获取机器码，机器码由以下四部分拼接组成
        # 1、CPU序列号  2、MAC地址 3.硬盘序列号 4.主板序列号
        self.m_wmi = wmi.WMI()
 
    #cpu序列号 16位
    def get_cpu_serial(self):
        cpu_info = self.m_wmi.Win32_Processor()
        if len(cpu_info) > 0:
            serial_number = cpu_info[0].ProcessorId
            return serial_number
        else:
            return "ABCDEFGHIJKLMNOP"
 
    #硬盘序列号 15位
    def get_disk_serial(self):
        disk_info = self.m_wmi.Win32_PhysicalMedia()
        disk_info.sort()
        if len(disk_info) > 0:
            serial_number = disk_info[0].SerialNumber.strip()
            return serial_number
        else:
            return "WD-ABCDEFGHIJKL"
 
    #mac地址 12位
    def get_mac_address(self):
        for network in self.m_wmi.Win32_NetworkAdapterConfiguration():
            mac_address = network.MacAddress
            if mac_address != None:
                return mac_address.replace(":", "")
        return "ABCDEF123456"
 
    #主板序列号 14位
    def get_board_serial(self):
        board_info = self.m_wmi.Win32_BaseBoard()
        if len(board_info) > 0:
            board_id = board_info[0].SerialNumber.strip().strip('.')
            return board_id
        else:
            return "ABCDEFGHIJKLMN"
 
    # 拼接生成机器码
    def getMachineCode(self):
        mac_address = self.get_mac_address()
        cpu_serial = self.get_cpu_serial()
        disk_serial = self.get_disk_serial()
        board_serial = self.get_board_serial()
        
        combine_str = self.pre_str + mac_address + cpu_serial + disk_serial + board_serial + self.suf_str
        combine_byte = combine_str.encode("utf-8")
        machine_code = hashlib.md5(combine_byte).hexdigest()
        return machine_code.upper()
 
    # AES_CBC 加密
    def Encrypt(self, plain_text):
        e = My_AES_CBC(self.Aes_key, self.Aes_IV).encrypt(plain_text)
        return e
        
    # AES_CBC 解密
    def Decrypt(self, encrypted_text):
        d = My_AES_CBC(self.Aes_key, self.Aes_IV).decrypt(encrypted_text)
        return d
    
    
    # 获取注册码，验证成功后生成注册文件
    def regist(self):
        machine_code = self.getMachineCode()
        print('请发送', machine_code, '到13900000000获取注册码')
        with open('code.txt', 'wb') as f:
          f.write(bytes(machine_code, encoding="utf-8"))
        key_code = input('请输入激活码:')
        if key_code:
            try:
                register_str = base64.b32decode(key_code)
                decode_key_data = json.loads(self.Decrypt(register_str))
            except:
                print("激活码错误，请重新输入！")
                return self.regist()
            
            active_code = decode_key_data["code"].upper()
            end_timestamp = decode_key_data["endTs"]
        
            encrypt_code = self.Encrypt(machine_code)
            md5_code = hashlib.md5(encrypt_code).hexdigest().upper()

            if md5_code != active_code:
                print("激活码错误，请重新输入！")
                return self.regist()
            
            curTs = int(time.time())
            if curTs >= end_timestamp:
                print("激活码已过期，请重新输入！")
                return self.regist()
                
            time_local = time.localtime(end_timestamp)
            dt = time.strftime("%Y-%m-%d %H:%M:%S", time_local)
            print("激活成功！有效期至 %s" %dt)
            with open('register.bin', 'wb') as f:
                f.write(register_str)
            return True
        else:
            return False
 
 
    # 打开程序先调用注册文件，比较注册文件中注册码与此时的硬件信息编码后是否一致
    def checkAuthored(self):
    
        if not os.path.exists("register.bin"):
            return False

        with open("register.bin", "rb") as f:
            key_code = f.read()
            
        if not key_code:
            return False
            
        # 本地计算激活码
        machine_code = self.getMachineCode()
        encrypt_code = self.Encrypt(machine_code)
        md5_code = hashlib.md5(encrypt_code).hexdigest().upper()

        # 解析激活码和到期时间
        try:
            decode_key_data = json.loads(self.Decrypt(key_code))
            active_code = decode_key_data["code"].upper()
            end_timestamp = decode_key_data["endTs"]
            curTs = int(time.time())
        except:
            print("激活码失效，请重新激活！")
            return False

        # 校验
        if md5_code != active_code:
            print("激活码失效，请重新激活！")
            return False
        
        curTs = int(time.time())
        if curTs >= end_timestamp:
            print("激活码失效，请重新激活！")
            return False

        return True

if __name__ == '__main__':
    register = Register()
    while(not register.checkAuthored()):
        register.regist()
        
    print("Hello World!")
    
    input('Press Enter to exit…')