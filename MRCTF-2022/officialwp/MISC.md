# MRCTF Misc部分wp
[toc]

## ppd

因为考的比web杂，加之有一点点点点脑洞，所以就扔到了misc

观察包的话可以发现前端默认随机了一个username发了一个start请求

回包里有两件事一个``debug``一个``enc``

![](https://md.buptmerak.cn/uploads/upload_6cf9f85f00e7b09df7e40080708e7262.png)

如果手动构造用户名去``start``就会观察到这个``enc``和``debug``是有关系的，甚至``username``如果为``aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa``的话会观察到相同的密文节

那么很容易联想到是某种ecb模式的分组密码。这里我们已经控制了加密机，那就可以构造出我们想要的任意密文分组了。

所以回过头来看题目名ppd就是密文分组拼拼多，把通过注入用户名构造的密文分组按128位一组拼一下，就能获得拿到100进度的用户enc了。

在前端中找到提交逻辑，提交就可以获取flag
## Spy_Dog
使用合理的任意算法根据指定图片构造对抗样本即可
```python
import cv2
import struct
import base64
import tensorflow as tf
import numpy as np
from PIL import Image
from keras import backend as K
from keras.models import load_model
from pwn import *
tf.compat.v1.disable_eager_execution()

def getHack():
    model = load_model("D:/data/back/model/simplenn.model")
    model_input_layer = model.layers[0].input
    model_output_layer = model.layers[-1].output

    original_img = cv2.imread("another.bmp")
    original_img = cv2.resize(original_img, (128, 128))
    original_img = np.expand_dims(original_img, axis = 0)

    original_img = original_img.astype(np.float32)
    original_img /= 255.
    target_img = np.copy(original_img)

    max_change_above = original_img + 0.039
    max_change_below = original_img - 0.039
    target_type = 1

    loss_function = model_output_layer[0, target_type]
    gradient_funtion = K.gradients(loss_function, model_input_layer)[0]
    grab_loss_and_gradient_from_model = K.function([model_input_layer, K.learning_phase()], (loss_function, gradient_funtion))
    index = 1
    e = 0.007
    loss = 0.02
    while loss < 0.99999:
        loss, gradients = grab_loss_and_gradient_from_model([target_img, 0])
        n = np.sign(gradients)
        target_img = target_img + n * e
        target_img = np.clip(target_img, max_change_below, max_change_above)
        target_img = np.clip(target_img, -1.0, 1.0)
        print("batch:{} Cost:{:.8}%".format(index, loss * 100))
        index = index + 1
        
    output_img = target_img[0]
    output_img *= 255.
    output_img = output_img.astype(np.uint8)
    another = original_img[0]*255.
    another = another.astype(np.uint8)

    cv2.imwrite("output.bmp", output_img)

def main():
    img = base64.b64encode(open('output.bmp','rb').read())
    r = remote('ip', port)
    r.recvuntil(">")
    r.sendline("3")
    r.recvuntil(">")
    r.sendline(img.decode())
    r.recvuntil("5.run away")
    r.recvuntil(">")
    r.sendline("4")
    r.interactive()

if __name__ == '__main__':
    getHack()
    main()
```

## jpeg and the tree

本题的考点是jpeg图片中的冗余哈夫曼编码，每张图片都在第二个哈夫曼表中隐藏了4个比特

首先介绍一下jpeg灰度图大概的编码流程吧：

1. 将图片分块，每一块8x8像素
2. 将小块的像素值减去128
3. 对小块进行DCT变换，其中DCT变换后矩阵的左上角的数据被称为DC，其他63个数据被称为AC
4. 对DCT变换后矩阵进行zigzag变换，将二维矩阵变换为一维数组，其中数组第一个值为DC，其余为AC
5. 对DC值进行delta编码，对AC值进行run-length编码
6. 将DC值和AC值分别哈夫曼编码
7. 当数据的比特数不能被8整除时，在最后补1
8. 将`\xff`替换为`\xff00`

想要更加详细了解jpeg编码方式，可以参考 https://www.cnblogs.com/Arvin-JIN/p/9133745.html 和 https://yasoob.me/posts/understanding-and-writing-jpeg-decoder-in-python

我自己也写了一个jpeg编码器，大家也可以看一下，找找bug![](https://md.buptmerak.cn/uploads/upload_b83fd47221f5240d3403da601a097276.png) 
链接是 https://github.com/john-dooe/jpeg-encoder-python

既然jpeg编码的过程中使用了哈夫曼编码，那么解析jpeg就一定需要哈夫曼解码，也就需要哈夫曼表
jpeg文件中的dht就是用来存储哈夫曼表的，在jpeg灰度图中存在两个dht，一个存储DC数据的哈夫曼表，一个存储AC数据的哈夫曼表

![](https://md.buptmerak.cn/uploads/upload_8a4c0c99bd45b52cb3ec0eba87588ba0.png)

dht存储哈夫曼表的方式是范式哈夫曼，这里dht的结构和范式哈夫曼编码就不赘述，具体可以参考 https://zhuanlan.zhihu.com/p/72044095

看一下题目中0.jpg的第二个dht（蓝色部分）：

![](https://md.buptmerak.cn/uploads/upload_840b8a9656d41cbd011f325933b36d20.png)

可以看到0x42前后都是很多0x00，如果了解dht结构，就可以看出哈夫曼编码的长度都是7位，这就很奇怪了，说明有点东西

然后在hint中说明了出题灵感来自Google CTF 2021，可以查到是DAVID AND THE TREE这题
这题的考点是zip压缩包中的冗余哈夫曼编码，这个zip中的txt数据不存在E这个字母，但是在哈夫曼表中却存在，于是flag就是由E的哈夫曼编码拼起来的

这道题也是这个思路，但是不像Google CTF那题直接给出冗余的是E，这题需要自己找出每张图片中没有用到的哈夫曼编码，也就需要找一个jpeg解码器
我使用的解码器是 https://github.com/yohhoy/picojdec

我在decode_scan函数后面加上了几行，来找到第二个dht中没有用到的哈夫曼编码，并打印出来：

```python=
defined_code_list = sorted(list(set(hdec[1].huffcode)))
used_code_list = sorted(list(set(hdec[1].used_code)))

if len(defined_code_list) != len(used_code_list):
    for defined_code in defined_code_list:
        if used_code_list.count(defined_code) == 0:
            unused_code = '0123456789abcdef'[defined_code]
            print(unused_code, end='', flush=True)
```

然后在主函数中循环读取每个文件：

```python=
if __name__ == '__main__':
    for i in range(78):
        with Reader(f'jpeg and the tree/{i}.jpg') as r:
            image = parse_stream(r)
```

解题脚本我放在了 https://pan.baidu.com/s/1c0eFtc7qylYKVFAlHzfMXw?pwd=26i5
直接运行picojdec.py就行

运行结果：

![](https://md.buptmerak.cn/uploads/upload_071e47a8dc968c16f32601396767bc50.png)

![](https://md.buptmerak.cn/uploads/upload_348313ac0e73e2cd7f950bb094d2707b.png)

MRCTF{3c5c1da80d5c2aea9cab040186694731}

## Bleach!
### 前言
其实本来都没有什么好想法，但是看到了rtp协议这种东西，恰逢课内在学水印，同时也做了wav——lsb这种东西。于是出了一道wavlsb+rtp提取的题。倒不是很难。
但唯一问题有两个：一个是 需要给出一些wav的参数。比如 频率、模式、图片size等等。 这个我是准备直接放到题目里了。到时候看大家能否找到。至于LSB，如果能够好好的使用频谱分析软件观察，肯定是可以发现其中隐藏的信息的。
### poc
```python=
# 导入wave音频文件处理库
import wave
# 导入图像处理库
import cv2
# 导入数学计算库
import numpy as np
# 导入绘图库
import matplotlib.pyplot as plt

# 计算NC值的函数
def NC(template, img):
    template = template.astype(np.uint8)
    img = img.astype(np.uint8)
    return cv2.matchTemplate(img, template, cv2.TM_CCORR_NORMED)[0][0]


# 设置水印图像的宽高
wm_height = 400
wm_width = 400

# 读取携密音频
wav = wave.open('part0.wav', 'rb')
nchannels, sampwidth, framerate, nframes, comptype, compname = wav.getparams()
time = nframes / framerate

# 以字节方式读取携密音频的数据
frames = wav.readframes(nframes)

# 将字节数据转换为numpy数组
data = np.frombuffer(frames, dtype=np.uint8)

# LSB提取水印
wm = np.zeros(wm_height * wm_width, dtype=np.uint8)
for i in range(len(wm)):
    wm[i] = data[i] % 2 * 255

# 从一维转为二维矩阵
wm = np.reshape(wm, (wm_height, wm_width))

# 以灰度图模式读取水印图像
wm_original = cv2.imread('bupt64.bmp', cv2.IMREAD_GRAYSCALE)

# 计算NC值
nc = NC(wm_original, wm)
print(f'NC = {nc * 100} %')

# 保存提取出的水印图像
cv2.imwrite('wm.bmp', wm)

# 展示嵌入图像、水印原图像和提取出的水印图像
plt.figure(figsize=(15, 6))

plt.subplot(131)
plt.plot(data)
plt.title('Embedded Audio')
plt.xticks([]), plt.yticks([])

plt.subplot(132)
plt.imshow(wm_original, 'gray')
plt.title('Original Watermark')
plt.xticks([]), plt.yticks([])

plt.subplot(133)
plt.imshow(wm, 'gray')
plt.title('Extracted Watermark')
plt.xticks([]), plt.yticks([])

plt.show()

```
提取出的效果会差一点。不过还是能看清的(是因为我把位宽度一个设置成8bit一个设置成16bit了)
![](https://md.buptmerak.cn/uploads/upload_c31498b3a263e6097314e89d9ce81942.png)

看到了 W&M选手利用原始数据直接提出了一份非常清晰的。感觉也是可以的。
## ReadLongNovel


### LV1:
 模糊搜索定位段落+机器阅读理解获取答案
 脚本见附件目录下 l1.py
 耗时约: 1人*5min

### LV2:
利用jieba与gensim工具包
 模糊搜索定位段落+人工阅读寻找答案
 脚本见附件目录下 l2.py
 耗时约: 1人*25min

### LV3:
 全队通力合作,人工读完小说寻找答案
 耗时约: 4人*1h

PS:
```
    网络上找到(网友上传/dog)的全书txt文本,方便很多。附件中附带下载好的novel.txt。仅供学习,24小时内删除。
```
附上脚本效果图
![过程](https://img-blog.csdnimg.cn/d5a8eb4dd7fe4997915c3cf02c01c68c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAdnBlcjEyMw==,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
![结果](https://img-blog.csdnimg.cn/6b3bdb0d269045fdabd9d510f76fd027.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAdnBlcjEyMw==,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

多线程适配的ubuntu20,win下未测试
附件下载地址: 链接：https://pan.baidu.com/s/124Tp3317mMNvoKBOlVYK_w?pwd=1234 --来自百度网盘超级会员V3的分享)



## connecting...
打开题目压缩包,将题目文件夹connecting...整个解压

进入后,看到一个3d模型和一段声音
![obj预览图](https://md.buptmerak.cn/uploads/upload_1d129132ba356203982d87353900db69.png)
事实上就一个粗糙的3d骨架,没啥有效信息。

右键以文本模式打开obj文件,Obj文件中，开头是一系列的特征标签，提示存储的是什么样的数据。一些常用的标签有：
V——顶点几何信息
Vt——纹理坐标
Vn——顶点法向量
F——face 面（三角形的三个顶点）
在``` f #/#/# #/#/# #/#/#```中发现可疑数据,用16进制转ASCII字符,得到M3R7aIcTF,为音频隐写密码

![PasswordForMP3Stego](https://md.buptmerak.cn/uploads/upload_497f4f1a39d1387d6551b80f2cdf1f2e.png)

检查mm_frame.png文件,发现其Metadata中的copyright下包含这个人名" Fabien Petitcolas "这里用PhotoShops
![](https://md.buptmerak.cn/uploads/upload_c59a1d4ee3576c2a1f38da56932e29c5.png)


通过谷歌进行社工,第一条就是他的博客
![](https://md.buptmerak.cn/uploads/upload_b529fcadd3a923a34f2243d94c427b1f.png)

点击进入到```Info Hiding ```专栏,找到 MP3Stego项目,按照使用教程,对sound.wav进行解密即可。
![](https://md.buptmerak.cn/uploads/upload_10460c665ecaee33eabac5ec23bcf604.png)

得到一串Base32,解码后拿到Flag
```MRCTF{WIFI_2022_connect_successfully!}```
## pixel
根据题目提示蓝，猜测与蓝色通道有关，发现大多数pixel蓝色值为255 少量不为255，尝试提取blue不为255的点恢复原图。当然这里直接所有图片异或也能得到不一样的原图和做法，都可以。
```python
from PIL import Image
res = Image.new('RGB',(512,512))
for i in range(512):
    print(i)
    img = Image.open("{}.png".format(i))
    for y in range(512):
        for x in range(512):
            color = img.getpixel((x,y))
            if color[2]!=255:
                res.putpixel((x,y),color)
res.save('original.bmp')
```
看到red0或者blue0通道（根据你的做法）有lsb隐写，再看到原图上的zigzag，用zigzag逆变换遍历一下。
```python
from PIL import Image
import numpy as np
def Zmartix_inverse(m,n):
    result, count = [], 0
    result = np.zeros((m,n),int)
    i, j = 0, 0
    while count < m * n:
        up = True
        while up == True and i >= 0 and j < n:
            result[i][j]=count
            i -= 1
            j += 1
            count += 1

        if j <= n - 1:
            i += 1

        else:
            i += 2
            j -= 1
        up = False
        while up == False and i < m and j >= 0:
            result[i][j]=count
            i += 1
            j -= 1
            count += 1

        if i <= m - 1:
            j += 1

        else:
            j += 2
            i -= 1
    return result
original = Image.open('original.bmp')
final = Image.new("RGB",original.size)
temp = Zmartix_inverse(512,512)
for y in range(len(temp)):
    for x in range(len(temp[0])):
        final.putpixel((x,y),original.getpixel((int(temp[y][x]%512),int(temp[y][x]//512))))
final.save('flag.bmp')

```
出现了比较明显的Arnold变换特征，也给出了密钥20和22，变换一下。
```python
from PIL import Image
def generateKeyofEncrypt(a,b):
    return [[1,a],[b,a*b+1]]
def generateKeyofDencrypt(a,b):
    return [[a*b+1,-a],[-b,1]]
def arnold(img,key):
    width = img.size[0]
    height = img.size[1]
    res = Image.new("RGB",img.size)
    for y in range(height):
        for x in range(width):
            color = img.getpixel((x,y))
            x_new = (key[0][0]*x+key[0][1]*y)%width
            y_new = (key[1][0]*x+key[1][1]*y)%height
            res.putpixel((x_new,y_new),color)
    return res
def main():
    a,b=20,22
    img = Image.open("flag.bmp")
    key_encrypt = generateKeyofEncrypt(a,b)
    key_dencrypt = generateKeyofDencrypt(a,b)
    arnold(img,key_dencrypt).show()
main()

```