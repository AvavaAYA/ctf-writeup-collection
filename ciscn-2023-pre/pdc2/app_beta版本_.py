
pk2sk = {"luoji":"⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛","⬛⬛⬛⬛⬛":"08cf63685e6f437262271dfca4e7d981"}
pcs = set()
base64_charset = ⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛


def channel_log(channel, t, message):
    logging.info("channel(%s) %s %s" % (channel.label, t, message))

def channel_send(channel, message):
    channel_log(channel, ">", message)
    channel.send(message)

async def on_shutdown(app):
    # close peer connections
    coros = [pc.close() for pc in pcs]
    await asyncio.gather(*coros)
    pcs.clear()

async def index(request):
    content  = "欢迎访问行星防御理事会(PDC)面壁人作战方案管理系统！\n"
    content += "如果您是面壁人，请访问“tell2me”管理您的作战方案！ \n"  
    return web.Response(content_type="text/html", text=content)

async def tell(request):
    try:
        params = await request.json()
    except json.decoder.JSONDecodeError:
        content = "PDC 已经记录了您这次访问行为，普通民众请勿随意访问此系统！"
        return web.Response(status=403, content_type="text/html", text=content)
    if "⬛⬛⬛⬛⬛" not in params.keys():
        content = "PDC 已经记录了您这次访问行为，普通民众请勿随意访问此系统！"
        return web.Response(status=403, content_type="text/html", text=content)
    else:
        submitToken = str(params["⬛⬛⬛⬛⬛"])
        if len(submitToken) < 32 + 13 + 5:
            content = "PDC 已经记录了您这次攻击行为！"
            return web.Response(status=403, content_type="text/html", text=content)
        else:
            pk = submitToken[45:]
            sk = ""
            for pkKey in pk2sk.keys():
                if pkKey in pk:
                    sk = pk2sk[pkKey]
            if sk == "":
                content = "PDC 已经记录了您这次攻击行为！"
                return web.Response(status=403, content_type="text/html", text=content)
            else:
                timeStamp = int(round(time.time()) * 1000)
                signText = f"{submitToken[32:45]}-{sk}"
                md5Object = hashlib.md5()
                md5Object.update(signText.encode())
                if md5Object.hexdigest().upper() != submitToken[:32]:
                    content = "PDC 已经记录了您这次攻击行为！"
                    return web.Response(status=403, content_type="text/html", text=content)
                elif(timeStamp - int(submitToken[32:45]) < 600000):
                    if submitToken[45:50] == '⬛⬛⬛⬛⬛':
                        if "⬛⬛⬛" not in params.keys() or "⬛⬛⬛⬛" not in params.keys():
                            content = "您好，⬛⬛⬛⬛⬛！"
                            return web.Response(content_type="text/html", text=content)
                        else:
                            offer = RTCSessionDescription(sdp=params["⬛⬛⬛"], type=params["⬛⬛⬛⬛"])
                            pc = RTCPeerConnection()
                            pcs.add(pc)
                            @pc.on("datachannel")
                            def on_datachannel(channel):
                                @channel.on("message")
                                def on_message(message):
                                    channel_log(channel, "<", message)
                                    if isinstance(message, str) and message.startswith("⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛"):
                                        command = message.split("⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛:")[-1]
                                        if command == 'ls':
                                            channel_send(channel, "app.py  editDatabase  <secret>.db  start.sh")
                                        elif command == 'cat flag':
                                            channel_send(channel, "cat: flag: No such file or directory")
                                        else:
                                            channel_send(channel, f"{command}: command not found")
                            @pc.on("connectionstatechange")
                            async def on_connectionstatechange():
                                logging.info(f"Connection state is {pc.connectionState}")
                                if pc.connectionState == "failed":
                                    await pc.close()
                                    pcs.discard(pc)
                            await pc.setRemoteDescription(offer)
                            description = sdp.SessionDescription()
                            logging.info(description.host)
                            # send answer
                            answer = await pc.createAnswer(description)
                            logging.info(description.host)
                            await pc.setLocalDescription(answer)
                            logging.info(description.host)
                            logging.info(pc.localDescription)
                            
                            return web.Response(
                                content_type="application/json",
                                text=json.dumps(
                                    {"sdp": pc.localDescription.sdp, "type": pc.localDescription.type}
                                ),
                            )
                    elif submitToken[45:50] == '⬛⬛⬛⬛⬛':
                        if "sdp" not in params.keys() or "type" not in params.keys():
                            content = "您好，⬛⬛⬛⬛！"
                            return web.Response(content_type="text/html", text=content)
                        else:
                            offer = RTCSessionDescription(sdp=params["⬛⬛⬛"], type=params["⬛⬛⬛⬛"])
                            pc = RTCPeerConnection()
                            pcs.add(pc)
                            @pc.on("datachannel")
                            def on_datachannel(channel):
                                @channel.on("message")
                                def on_message(message):
                                    channel_log(channel, "<", message)
                                    if isinstance(message, str) and message.startswith("⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛"):
                                        command = message.split("⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛:")[-1]
                                        checkPassed = True
                                        for commandChar in command:
                                            if commandChar not in base64_charset:
                                                channel_send(channel, f"检测到非法字符！")
                                                checkPassed = False
                                                break
                                        if checkPassed:
                                            print(["./editDatabase",command],flush=True)
                                            proc = subprocess.Popen(["./editDatabase",command], stdout=subprocess.PIPE)
                                            outinfo, errinfo = proc.communicate()
                                            status = proc.wait()
                                            reply = ""
                                            if outinfo == None and errinfo == None:
                                                reply = "系统无回应"
                                            elif outinfo != None and errinfo != None:
                                                reply = outinfo.decode()+errinfo.decode()
                                            elif outinfo != None:
                                                reply = outinfo.decode()
                                            elif errinfo != None:
                                                reply = errinfo.decode()
                                            print(reply.replace('\n',''),flush=True)
                                            channel_send(channel, reply.replace('\n',''))
                                            

                            @pc.on("connectionstatechange")
                            async def on_connectionstatechange():
                                logging.info(f"Connection state is {pc.connectionState}")
                                if pc.connectionState == "failed":
                                    await pc.close()
                                    pcs.discard(pc)
                            await pc.setRemoteDescription(offer)
                            description = sdp.SessionDescription()
                            # send answer
                            answer = await pc.createAnswer(description)
                            await pc.setLocalDescription(answer)
                            
                            return web.Response(
                                content_type="application/json",
                                text=json.dumps(
                                    {"sdp": pc.localDescription.sdp, "type": pc.localDescription.type}
                                ),
                            )
                    else:
                        content = "PDC 已经记录了您这次攻击行为！"
                        return web.Response(status=403, content_type="text/html", text=content)
                else:
                    content = "PDC 已经记录了您这次攻击行为！"
                    return web.Response(status=403, content_type="text/html", text=content)

def query_parse(req):
    obj = req.query_string
    queryitem = []
    if obj:
        query = req.query.items()
        for item in query:
            queryitem.append(item)
        return dict(queryitem)
    else:
        return None

async def download(request):
    query = query_parse(request)
    if query == None or 'file' not in query.keys():
        content = "PDC 已经记录了您这次访问行为，普通民众请勿随意访问此系统！"
        return web.Response(status=403, content_type="text/html", text=content)
    filename = query.get('file')
    file_dir = '⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛'
    file_path = os.path.join(file_dir, filename)
    if filename == 'editDatabase':
        if query == None or 'token' not in query.keys():
            content = "PDC 已经记录了您这次访问行为，普通民众请勿随意访问此系统！"
            return web.Response(status=403, content_type="text/html", text=content)
        else:
            submitToken = query.get('token')
            if len(submitToken) < 32 + 13 + 5:
                content = "PDC 已经记录了您这次攻击行为！"
                return web.Response(status=403, content_type="text/html", text=content)
            else:
                pk = submitToken[45:]
                sk = ""
                for pkKey in pk2sk.keys():
                    if pkKey in pk:
                        sk = pk2sk[pkKey]
                if sk == "":
                    content = "PDC 已经记录了您这次攻击行为！"
                    return web.Response(status=403, content_type="text/html", text=content)
                else:
                    timeStamp = int(round(time.time()) * 1000)
                    signText = f"{submitToken[32:45]}-{sk}"
                    md5Object = hashlib.md5()
                    md5Object.update(signText.encode())
                    if md5Object.hexdigest().upper() != submitToken[:32]:
                        content = "PDC 已经记录了您这次攻击行为！"
                        return web.Response(status=403, content_type="text/html", text=content)
                    elif(timeStamp - int(submitToken[32:45]) < 1000):
                        if submitToken[45:50] != 'luoji':
                            content = "PDC 已经记录了您这次攻击行为！"
                            return web.Response(status=403, content_type="text/html", text=content)
                        else:
                            if os.path.exists(file_path):
                                async with aiofiles.open(file_path, 'rb') as f:
                                    content = await f.read()
                                if content:
                                    response = web.Response(
                                        content_type='application/octet-stream',
                                        headers={'Content-Disposition': 'attachment;filename={}'.format(filename)},
                                        body=content)
                                    return response
                                else:
                                    return web.Response(status=404, content_type="text/html", text="文件为空")
                            else:
                                return web.Response(status=404, content_type="text/html", text="文件未找到")
    elif filename != '⬛⬛⬛⬛⬛⬛⬛':
        content = "PDC 已经记录了您这次访问行为，普通民众请勿随意访问此系统！"
        return web.Response(status=403, content_type="text/html", text=content)
    else:
        if os.path.exists(file_path):
            async with aiofiles.open(file_path, 'rb') as f:
                content = await f.read()
            if content:
                response = web.Response(
                    content_type='application/octet-stream',
                    headers={'Content-Disposition': 'attachment;filename={}'.format(filename)},
                    body=content)
                return response
            else:
                return web.Response(status=404, content_type="text/html", text="文件为空")
        else:
            return web.Response(status=404, content_type="text/html", text="文件未找到")

if __name__ == "__main__":
    app = web.Application()
    app.on_shutdown.append(on_shutdown)
    app.router.add_get("/", index)
    app.router.add_get("/download", download)
    app.router.add_post("/tell2me", tell)
    web.run_app(
        app, access_log=None, host='0.0.0.0', port='23333'
    )