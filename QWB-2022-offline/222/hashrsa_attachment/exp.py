# hashlib.shake_128(CODE[2:]).digest(16) + hashlib.sha256(CODE[2:]).digest() + hashlib.md5(CODE[2:]).digest()
import hashlib, os, solve, math, datetime

score_best = 27749821798869682728240156453782301861124646663328872791737345875983025897112197998899015006352489330240694506735629649322700575131654602856434449
score_forcmp = score_best // 2**384
'''
shellcode: b'O\xe72\xa4 1\x05\x88\xe3\x00\xda\x0f\xecm$Q'
payload: 00006ea4dd64312696dcf650c95068cec8c8
2^484.5729240449884
'''

while True:
    CODE = os.urandom(64)
    score = int.from_bytes(hashlib.md5(CODE).digest(), 'little')
    if score < score_forcmp:
        print(CODE)
        ret = int(solve.send_shellcode((b'TT' + CODE).hex()))
        print(ret)
        print(f'New score: 2^{math.log2(ret)}')
        assert ret // 2**384 == score
        assert ret // 2**384 < score_forcmp
        assert ret < score_best
        score_forcmp = score
        score_best = ret
        with open('bestCODE.txt', 'w') as f:
            print((b'TT' + CODE).hex(), file = f)
