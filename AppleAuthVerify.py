#-*- coding: UTF-8 -*-
import sys
import os
import base64
import types
import json
import ast
# pip install below
import requests
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# node.js example: https://www.jianshu.com/p/2036987a22fb

# Global Vars
PemPath = './appleAuthPem.pem'

def formatBase64(str):
  missing_padding = len(str) % 4
  if missing_padding != 0:
      str += b'='* (4 - missing_padding)
      str = str.replace("_", "/")
      str = str.replace("-", "+")
  return str

def decode_base64_data(data):
#    """Decode base64, padding being optional.
#        :param data: Base64 data as an ASCII byte string
#        :returns: The decoded byte string.
#        """
    data = formatBase64(data)
    data = base64.b64decode(data)
    print "Decode base64: "
    print data
    return data

# analysis of RSA key into modulus and exponent
def showModAndExpOnConsole(pemPath):
    print "---------------------RSA Publickey modulus and exponent---------------------"
    command = "openssl rsa -in " + pemPath + " -pubin -text"
    os.system(command)

def decodeAppleAuthResp(response):
    keysString = response.content
    # string => dict. https://www.cnblogs.com/OnlyDreams/p/7850920.html
    # eval => ast.literal_eval. http://www.php.cn/python-tutorials-376459.html
    keysInfo = ast.literal_eval(keysString)

    publickeyList = keysInfo["keys"]
    publickeyInfo = {}
    publicKeyN = ''
    publicKeyE = ''
    if len(publickeyList) > 0:
        publickeyInfo = publickeyList[0]
        for (key,value) in publickeyInfo.items():
            if key is 'n':
                publicKeyN = value
            elif key is 'e':
                publicKeyE = value
    print "---------------------Apple Auth API Response---------------------"
    print "Modulus base64:\n" ,publicKeyN
    print 'Exponent base64:\n',publicKeyE
    if len(publicKeyN) > 0 and len(publicKeyE) > 0:
        return {'n':publicKeyN,'e':publicKeyE}
    else:
        return None

def fetchApplePublicNeAndEx():
    try:
        response = requests.get("https://appleid.apple.com/auth/keys", timeout=15)
        return decodeAppleAuthResp(response)
    except requests.exceptions.RequestException as e:
        print e
        return None

# create public key from n and e
def createApplePublicKey(): 

    publicKeyInfo = fetchApplePublicNeAndEx()
    if publicKeyInfo is None:
        print "Get no publick key info"
        return

    # decode base64 string to be used as modulus(n) and exponent(e) components for
    # constructing the RSA public key object
    # https://www.cnblogs.com/wswang/p/7717997.html

    fn = publicKeyInfo['n']
    fe = publicKeyInfo['e']

    fn = formatBase64(fn)
    fn = base64.b64decode(fn).encode('hex')

    fe = formatBase64(fe)
    fe = base64.b64decode(fe).encode('hex')

    # hex => dex
    n = int(fn,16)
    e = int(fe,16)

    print "---------------------Apple RSA Publickey n and e---------------------"
    print "Modulus hex:",fn
    print "Exponent hex:",fe

    # rsa_pubkey_pair = rsa.PublicKey(n, e)
    # https://blog.csdn.net/guyongqiangx/article/details/74989644
    rsa_pubkey = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
    pem = rsa_pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print "---------------------Apple RSA Publickey---------------------"
    print pem
    return pem

def writePEMinFile(pemString,pemFileName):
    if pemString is None:
        return
    with open(pemFileName, 'w+') as f:
        f.writelines(pemString.decode())

def verifyWithPublicKey(content,sign,publickey):
    if content is None or sign is None or publickey is None:
        return False
    # verify sign
    publickey.verify(
        sign,
        content,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
        )
    return True

def jwtVerify(jwtString,publickey,aud):
    if jwtString is None or publickey is None or aud is None:
        return False
    try:
        # audience is required: https://segmentfault.com/a/1190000010312468
        content = jwt.decode(jwtString, publickey, audience=aud, algorithms=['RS256'])
        infoList = jwtString.split('.')
        if len(infoList) < 3:
            return False
        header = infoList[0]
        payload = infoList[1]

        header = decode_base64_data(header)
        payload = decode_base64_data(payload)

        header = json.loads(header)
        payload = json.loads(payload)
        flag = cmp(content,payload)
        if flag == 0:
            return True
        else:
            return False
    except Exception as e:
        print "Exception for decoding JWT:",e
        return False

def appleJWTVerify(jwtString,aud):
    # create key from modulus and exponent
    publickey = createApplePublicKey() 
    ## write key
    writePEMinFile(publickey,PemPath)
    ## analysis public key
    # showModAndExpOnConsole(PemPath)

    # aud = 'com.example.apple-samplecode.juiceHC8RE2RV86'
    return jwtVerify(jwtString,publickey,aud)

def main(jwtString,aud):
    flag = appleJWTVerify(jwtString,aud)
    print "---------------------Apple Verified---------------------"
    if flag:
        print "Auth Verified!"
    else:
        print "Fail to verify!"
    return flag

if __name__ == '__main__':
	main(sys.argv[1],sys.argv[2])

