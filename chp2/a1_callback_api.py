# coding=utf-8
"""
@Author: Freshield
@Contact: yangyufresh@163.com
@File: a1_callback_api.py
@Time: 2021-10-25 15:54
@Last_update: 2021-10-25 15:54
@Desc: None
@==============================================@
@      _____             _   _     _   _       @
@     |   __|___ ___ ___| |_|_|___| |_| |      @
@     |   __|  _| -_|_ -|   | | -_| | . |      @
@     |__|  |_| |___|___|_|_|_|___|_|___|      @
@                                    Freshield @
@==============================================@
"""
import time
import datetime
import hashlib
from flask import Flask, request, make_response
from xml.etree import cElementTree
from WXBizMsgCrypt import WXBizMsgCrypt

app = Flask(__name__)

TOKEN = '202l01Y21j7NoteBook'
EncodingAESKey = 'MhSIVdhI5IvYtuYQkr3v6pGWkSDBBppC1AxpnqQ4uY1'
AppID = 'wx551666085d521c3c'


@app.route('/', methods=['GET', 'POST'])
def wechat_auth():
    if request.method == 'GET':
        # 进行微信的ip和端口认证
        token = TOKEN
        query = request.args
        print(f'auth request: query{query}\n')

        signature = query.get('signature', '')
        timestamp = query.get('timestamp', '')
        nonce = query.get('nonce', '')
        echostr = query.get('echostr', '')
        content = [token, timestamp, nonce]
        content.sort()
        item = ''.join(content)
        hashmsg = hashlib.sha1(item.encode('utf-8')).hexdigest()
        if hashmsg == signature:
            return echostr
        return '请检查请求, 重新发送!'
    elif request.method == 'POST':
        # 进行信息的处理
        xml_data = request.stream.read()  # 接收消息
        query = request.args
        et = cElementTree.fromstring(xml_data)
        print(xml_data.decode('utf8'))
        print(query)

        master = et.find("ToUserName").text if et.find("ToUserName") is not None else ""
        encrypt = et.find('Encrypt').text if et.find('Encrypt') is not None else ""
        the_time = int(time.time())
        text_template = """
                    <xml>
                    <ToUserName><![CDATA[{}]]></ToUserName>
                    <FromUserName><![CDATA[{}]]></FromUserName>
                    <CreateTime>{}</CreateTime>
                    <MsgType><![CDATA[{}]]></MsgType>
                    <Content><![CDATA[{}]]></Content>
                    <FuncFlag>0</FuncFlag>
                    </xml>
                    """

        if encrypt != '':
            timestamp = query.get('timestamp', '')
            nonce = query.get('nonce', '')
            msg_signature = query.get('msg_signature', '')

            encrypt_test = WXBizMsgCrypt(TOKEN, EncodingAESKey, AppID)
            xml_data = xml_data.decode('utf8')
            ret, xml_data = encrypt_test.DecryptMsg(xml_data, msg_signature, timestamp, nonce)
            print(f'decode xml_data: {xml_data}')
            et = cElementTree.fromstring(xml_data)

        user = et.find("FromUserName").text if et.find("FromUserName") is not None else ""
        msgtype = et.find("MsgType").text if et.find("MsgType") is not None else ""
        content = et.find("Content").text if et.find("Content") is not None else ""
        recognition = et.find("Recognition").text if et.find("Recognition") is not None else ""
        format = et.find("Format").text if et.find("Format") is not None else ""
        if content in ['?', '？']:
            content = time.strftime("%D_%H-%M-%S")

        response_data = text_template.format(user, master, the_time, msgtype, content)
        print(f'response data: {response_data}')

        if encrypt != '':
            ret, response_data = encrypt_test.EncryptMsg(response_data, nonce)
            print(f'encrypt response data: {response_data}')
    else:
        response_data = 'unknown method'

    response = make_response(response_data)
    return response


if __name__ == '__main__':
    # 此文件为测试服务器使用的文件，和正式服务器主要区别在于端口和文件名
    # 文件名不同目的在于区分不同的启动服务，方便kill进程
    app.run(host="0.0.0.0", port=9666, debug=False)

