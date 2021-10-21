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
}

$wechatObj = new wechatCallbackapiTest($token, $encodingAesKey, $corpId);
if (!isset($_GET['echostr'])) {
    $wechatObj->valid();
}
?>