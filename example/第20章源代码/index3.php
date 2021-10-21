<?php
/*
    方倍工作室 http://www.fangbei.org/
    CopyRight 2015 All Rights Reserved
*/
require_once("WXBizMsgCrypt.php");
$encodingAesKey = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
$token = "FangBei";
$corpId = "wx82e2c31215d9a5a7";

class wechatCallbackapiTest extends WXBizMsgCrypt
{
    //验证URL有效
    public function valid()
    {
		$sVerifyMsgSig = $_GET["msg_signature"];
		$sVerifyTimeStamp = $_GET["timestamp"];
		$sVerifyNonce = $_GET["nonce"];
		$sVerifyEchoStr = $_GET["echostr"];

		$sEchoStr = "";
		$errCode = $this->VerifyURL($sVerifyMsgSig, $sVerifyTimeStamp, $sVerifyNonce, $sVerifyEchoStr, $sEchoStr);
		if ($errCode == 0) {
			// 验证URL成功，将sEchoStr返回
			echo $sEchoStr;
		}
    }

    //响应消息
    public function responseMsg()
    {
		$sReqMsgSig = $_GET['msg_signature'];
		$sReqTimeStamp = $_GET['timestamp'];
		$sReqNonce = $_GET['nonce'];
		$sReqData = $GLOBALS["HTTP_RAW_POST_DATA"];
		$sMsg = "";  // 解析之后的明文
		$this->logger(" DE \r\n".$sReqData);

		$errCode = $this->DecryptMsg($sReqMsgSig, $sReqTimeStamp, $sReqNonce, $sReqData, $sMsg);
		$this->logger(" RR \r\n".$sMsg);
		$postObj = simplexml_load_string($sMsg, 'SimpleXMLElement', LIBXML_NOCDATA);
		$RX_TYPE = trim($postObj->MsgType);

		//消息类型分离
		switch ($RX_TYPE)
		{
			case "event":
				$sRespData = $this->receiveEvent($postObj);
				break;
			case "text":
				$sRespData = $this->receiveText($postObj);
				break;
			default:
				$sRespData = "unknown msg type: ".$RX_TYPE;
				break;
		}
		$this->logger(" RT \r\n".$sRespData);
		//加密
		$sEncryptMsg = ""; //xml格式的密文
		$errCode = $this->EncryptMsg($sRespData, $sReqTimeStamp, $sReqNonce, $sEncryptMsg);
		$this->logger(" EC \r\n".$sEncryptMsg);
		echo $sEncryptMsg;
    }

    //接收事件消息
    private function receiveEvent($object)
    {
        $content = "";
        switch ($object->Event)
        {
			case "subscribe":
                $content = "欢迎关注企业号";
                break;
            case "enter_agent":
                $content = "欢迎进入企业号应用";
                break;
            default:
                $content = "receive a new event: ".$object->Event;
                break;
        }

        $result = $this->transmitText($object, $content);
        return $result;
    }

    //接收文本消息
    private function receiveText($object)
    {
        $keyword = trim($object->Content);
        $content = time();
		$result = $this->transmitText($object, $content);
        return $result;
    }

    //回复文本消息
    private function transmitText($object, $content)
    {
		if (!isset($content) || empty($content)){
			return "";
		}

		$xmlTpl = "<xml>
	<ToUserName><![CDATA[%s]]></ToUserName>
	<FromUserName><![CDATA[%s]]></FromUserName>
	<CreateTime>%s</CreateTime>
	<MsgType><![CDATA[text]]></MsgType>
	<Content><![CDATA[%s]]></Content>
</xml>";
		$result = sprintf($xmlTpl, $object->FromUserName, $object->ToUserName, time(), $content);

        return $result;
    }

    //日志记录
    public function logger($log_content)
    {
        $max_size = 500000;
        $log_filename = "log.xml";
        if(file_exists($log_filename) and (abs(filesize($log_filename)) > $max_size)){unlink($log_filename);}
        file_put_contents($log_filename, date('Y-m-d H:i:s').$log_content."\r\n", FILE_APPEND);
    }
}

$wechatObj = new wechatCallbackapiTest($token, $encodingAesKey, $corpId);
$wechatObj->logger(' http://'.$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF'].(empty($_SERVER['QUERY_STRING'])?"":("?".$_SERVER['QUERY_STRING'])));
if (!isset($_GET['echostr'])) {
    $wechatObj->responseMsg();
}else{
    $wechatObj->valid();
}

?>