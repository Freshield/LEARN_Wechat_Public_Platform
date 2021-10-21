<?php

/*
    方倍工作室
    CopyRight 2014 All Rights Reserved
*/
require_once('config.php');   //引用配置

class class_weixin
{
	var $appid = APPID;
	var $appsecret = APPSECRET;

    //构造函数，获取Access Token
	public function __construct($appid = NULL, $appsecret = NULL)
	{
        if($appid && $appsecret){
            $this->appid = $appid;
			$this->appsecret = $appsecret;
        }

        $url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=".$this->appid."&secret=".$this->appsecret;
        $res = $this->http_request($url);
        $result = json_decode($res, true);
        //save to Database or Memcache
        $this->access_token = $result["access_token"];
        $this->lasttime = time();
	}


    //发送客服消息，已实现发送文本，其他类型可扩展
	public function send_custom_message($touser, $type, $data)
    {
        $msg = array('touser' =>$touser);
        $msg['msgtype'] = $type;
        switch($type)
        {
			case 'text':
				$msg[$type]    = array('content'=>urlencode($data));
				break;
			case 'news':
				$msg[$type]    = array('articles'=>$data);
				break;
            default:
                $msg['text']   = array('content'=>urlencode("不支持的消息类型 ".$type));
                break;
        }
		$url = "https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token=".$this->access_token;
		return $this->http_request($url, urldecode(json_encode($msg)));
	}

    //https请求（支持GET和POST）
    protected function http_request($url, $data = null)
    {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, FALSE);
        if (!empty($data)){
            curl_setopt($curl, CURLOPT_POST, 1);
            curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
        }
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        $output = curl_exec($curl);
        curl_close($curl);
        return $output;
    }
}
