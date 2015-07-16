__author__ = 'zhangjian'

import urllib3
#import sys

BLOCK_SIZE = 128

TARGET = 'http://crypto-class.appspot.com/po?er='
#TARGET = 'http://www.baidu.com/'
cipher = 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'
hex2num = {'0':0, '1':1, '2':2, '3':3, '4':4, '5':5, '6':6, '7':7, '8':8, '9':9, 'a':10,
           'b':11, 'c':12, 'd':13, 'e':14, 'f':15}
blocks = [cipher[i*BLOCK_SIZE/4:(i+1)*BLOCK_SIZE/4] for i in range(len(cipher)/32)]
dic = ''' etoanihsrdluwmycgf,bp.kv'"I-T;_HAWMSB!j?ExLCDzPJNq:YOGRFU1XK*V()Q/023548697][$@Z#%&'''

def num2hexstr(num):
    str = ''
    while num>0:
        str = hex(num%16)[2:] + str
        num /= 16
    if len(str)%2 == 1:
        str = '0' + str
    return str


def hexxor(str1,str2):
    if len(str1)>len(str2):
        t1 = str1[:(len(str1)-len(str2))]
        t2 = ''
        for i in range(len(str2)):
            t2 += hex((hex2num[str1[len(t1)+i]] ^ hex2num[str2[i]]))[2:]
    else:
        t1 = str2[:(len(str2)-len(str1))]
        t2 = ''
        for i in range(len(str1)):
            t2 += hex((hex2num[str2[len(t1)+i]] ^ hex2num[str1[i]]))[2:]
    return t1 + t2

#--------------------------------------------------------------
# padding oracle
#--------------------------------------------------------------
class PaddingOracle(object):
    def query(self, q):
        http = urllib3.PoolManager()
        target = TARGET + q    # Create query URL
        #print target
        req = http.request('GET',target)
        #print req.status
        if req.status == 404:
            return True
        return False

    def decrypt(self,IV,ct):
        pad_num = self.padding_test(IV,ct)
        text = num2hexstr(pad_num)*pad_num
        for i in range(pad_num+1,17):
            pad = num2hexstr(i)*i
            print 'padding: '+pad
            for c in dic:
                IV_guess = hexxor(IV,num2hexstr(ord(c))+text)
                IV_guess = hexxor(IV_guess,pad)
                if self.query(IV_guess+ct):
                    text = num2hexstr(ord(c)) + text
                    break
        return text

    def padding_test(self,IV,ct):
        if not self.query(IV+ct):
            return 0

        for i in range(16):
            IV_guess = hexxor(IV,'01'+'00'*(15-i))
            if not self.query(IV_guess+ct):
                return 16-i
        return 0


if __name__ == "__main__":
    po = PaddingOracle()
    print (po.decrypt(blocks[0],blocks[1])+po.decrypt(blocks[1],blocks[2])+po.decrypt(blocks[2],blocks[3])).decode('hex')       # Issue HTTP query with the given argument