#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-12-18 23:42:48
# @Author  : dagaoya (dagaoya@qq.com)
# @Link    : https://dagaoya.github.io

import base64
from Crypto.Cipher import AES

'''
采用AES对称加密算法
'''
# str不是16的倍数那就补足为16的倍数
def add_to_16(value):
    while len(value) % 16 != 0:
        value += '\0'
    return str.encode(value)  # 返回bytes
#加密方法
def encrypt_AES():
    # 秘钥
    key = 'UITN25LMUQC436IM'
    # 待加密文本
    text = 'abc123def456'
    # 初始化加密器
    aes = AES.new(add_to_16(key), AES.MODE_ECB)
    #先进行aes加密
    encrypt_aes = aes.encrypt(add_to_16(text))
    #用base64转成字符串形式
    encrypted_text = str(base64.encodebytes(encrypt_aes), encoding='utf-8')  # 执行加密并转码返回bytes
    print(encrypted_text)
#解密方法
def decrypt_AES(text):
    # 秘钥
    key = 'UITN25LMUQC436IM'
    # 密文
    #text = 'PN0Eo7jGMYpuNDnswiHrxg=='
    # 初始化加密器
    aes = AES.new(add_to_16(key), AES.MODE_ECB)
    #优先逆向解密base64成bytes
    base64_decrypted = base64.decodebytes(text.encode(encoding='utf-8'))
    #执行解密密并转码返回str
    decrypted_text = str(aes.decrypt(base64_decrypted),encoding='utf-8').strip()
    #print(decrypted_text)
    for i in range(16):#删除非法字符
        decrypted_text = decrypted_text.replace(chr(0x00+i),'')
    return(decrypted_text.replace(chr(0x10),''))

#测试
text = decrypt_AES('AcxO7gWOGzNOW38R/wvq9NAFHy5lV2v9L9JYOUoaMvk=')



print(text)
#批量
clear_text = open('2.txt','w')
with open('users.txt','r') as encrypt_pass:
    for line in encrypt_pass:
        passwd = line.split('\t')[1]
        clear_passwd = decrypt_AES(passwd)
        line = line.strip() + '\t"' + clear_passwd + '"\n'
        clear_text.write(line)

clear_text.close()
encrypt_pass.close()
