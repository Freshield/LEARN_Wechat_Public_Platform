<?php

/*
    方倍工作室 http://www.fangbei.org/
    CopyRight 2014 All Rights Reserved
*/

/*
    require_once('weixin.class.php');
    $weixin = new class_weixin();
*/
header("Content-type: text/html; charset=utf-8");
define('APPID',         "wx3e87b959a615f377"); 
define('APPSECRET',     "");



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

        // //1. 数据库形式
        // /*
        // DROP TABLE IF EXISTS `wx_token`;
        // CREATE TABLE IF NOT EXISTS `wx_token` (
          // `id` int(1) NOT NULL,
          // `type` varchar(20) NOT NULL,
          // `expire` varchar(16) NOT NULL,
          // `value` varchar(600) NOT NULL,
          // PRIMARY KEY (`id`)
        // ) ENGINE=MyISAM DEFAULT CHARSET=utf8;

        // INSERT INTO `wx_token` (`id`, `type`, `expire`, `value`) VALUES
        // (1, 'access_token', '1425534992', 't3oyW9fRnOWKQHQhZXoEH-pgThhjmnCqTVpaLyUD'),
        // (2, 'jsapi_ticket', '', '');
        // */
        // $con = mysql_connect(MYSQLHOST.':'.MYSQLPORT, MYSQLUSER, MYSQLPASSWORD);
        // mysql_select_db(MYSQLDATABASE, $con);
        // $result = mysql_query("SELECT * FROM `wx_token` WHERE `type` = 'access_token'");
        // while($row = mysql_fetch_array($result))
        // {
            // $this->access_token = $row['value'];
            // $this->expires_time = $row['expire'];
            // break;
        // }
        // if (time() > ($this->expires_time + 3600)){
            // $url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=".$this->appid."&secret=".$this->appsecret;
            // $res = $this->http_request($url);
            // $result = json_decode($res, true);
            // $this->access_token = $result["access_token"];
            // $this->expires_time = time();
            // mysql_query("UPDATE `wx_token` SET `expire` = '$this->expires_time', `value` = '$this->access_token' WHERE `type` = 'access_token';");
        // }

        // //2. 缓存形式
        // if (isset($_SERVER['HTTP_APPNAME'])){        //SAE环境，需要开通memcache
            // $mem = memcache_init();
        // }else {                                        //本地环境，需已安装memcache
            // $mem = new Memcache;
            // $mem->connect('localhost', 11211) or die ("Could not connect");
        // }
        // $this->access_token = $mem->get($this->appid);
        // if (!isset($this->access_token) || empty($this->access_token)){
            // $url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=".$this->appid."&secret=".$this->appsecret;
            // $res = $this->http_request($url);
            // $result = json_decode($res, true);
            // $this->access_token = $result["access_token"];
            // $mem->set($this->appid, $this->access_token, 0, 3600);
        // }

        //3. 本地写入
        $res = file_get_contents('access_token.json');
        $result = json_decode($res, true);
        $this->expires_time = $result["expires_time"];
        $this->access_token = $result["access_token"];

        if (time() > ($this->expires_time + 3600)){
            $url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=".$this->appid."&secret=".$this->appsecret;
            $res = $this->http_request($url);
            $result = json_decode($res, true);
            $this->access_token = $result["access_token"];
            $this->expires_time = time();
            file_put_contents('access_token.json', '{"access_token": "'.$this->access_token.'", "expires_time": '.$this->expires_time.'}');
        }

        // //4. 实时拉取
        // $url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=".$this->appid."&secret=".$this->appsecret;
        // $res = $this->http_request($url);
        // $result = json_decode($res, true);
        // $this->access_token = $result["access_token"];
        // $this->expires_time = time();
    }


    /*
    *  PART4 JS SDK 签名
    *  PHP仅用于获得签名包，需要配合js一起使用
    */
    // require_once('weixin.class.php');
    // $weixin = new class_weixin();
    // $signPackage = $weixin->GetSignPackage();

    //生成长度16的随机字符串
    public function createNonceStr($length = 16) {
        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        $str = "";
        for ($i = 0; $i < $length; $i++) {
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }
        return $str;
    }
	
    //获得微信卡券api_ticket
    public function getCardApiTicket()
    {
		/*
        //1. 数据库形式，与Access Token共用同一张表，mysql在创建微信类时初始化
        $result = mysql_query("SELECT * FROM `wx_token` WHERE `type` = 'cardapi_ticket'");
        while($row = mysql_fetch_array($result))
        {
            $this->cardapi_ticket = $row['value'];
            $this->cardapi_expire = $row['expire'];
            break;
        }
        if (time() > ($this->cardapi_expire + 3600)){
            $url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?type=wx_card&access_token=".$this->access_token;
            $res = $this->http_request($url);
            $result = json_decode($res, true);
            $this->cardapi_ticket = $result["ticket"];
            $this->cardapi_expire = time();
            mysql_query("UPDATE `wx_token` SET `expire` = '".$this->cardapi_expire."', `value` = '".$this->cardapi_ticket."' WHERE `type` = 'cardapi_ticket';");
        }
        return $this->cardapi_ticket;
        */
		
        //2. 写文件，有改动，待测试 20150430
        $res = file_get_contents('cardapi_ticket.json');
        $result = json_decode($res, true);
        $this->cardapi_ticket = $result["cardapi_ticket"];
        $this->cardapi_expire = $result["cardapi_expire"];

        if (time() > ($this->cardapi_expire + 3600)){
            $url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?type=wx_card&access_token=".$this->access_token;
            $res = $this->http_request($url);
            $result = json_decode($res, true);
            $this->cardapi_ticket = $result["ticket"];
            $this->cardapi_expire = time();
            file_put_contents('cardapi_ticket.json', '{"cardapi_ticket": "'.$this->cardapi_ticket.'", "cardapi_expire": '.$this->cardapi_expire.'}');
        }
        return $this->cardapi_ticket;
    }
	
	//cardSign卡券签名
	/*
	$obj['api_ticket']          = "ojZ8YtyVyr30HheH3CM73y";
	$obj['timestamp']           = "1404896688";
	$obj['nonce_str']           = "jonyqin";
	$obj['card_id']             = "pjZ8Yt1XGILfi-FUsewpnnolGgZk";
	$signature  = get_cardsign($obj);
	*/
	public function get_cardsign($bizObj)
	{
		//字典序排序
		asort($bizObj);
		//URL键值对拼成字符串
		$buff = "";
		foreach ($bizObj as $k => $v){
		$buff .= $v;
		}
		//sha1签名
		return sha1($buff);
	}
	
    //获得JS API的ticket
    private function getJsApiTicket() 
    {
		/*
        //1. 数据库形式，与Access Token共用同一张表，mysql在创建微信类时初始化
        $result = mysql_query("SELECT * FROM `wx_token` WHERE `type` = 'jsapi_ticket'");
        while($row = mysql_fetch_array($result))
        {
            $this->jsapi_ticket = $row['value'];
            $this->jsapi_expire = $row['expire'];
            break;
        }
        if (time() > ($this->jsapi_expire + 3600)){
            $url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?type=jsapi&access_token=".$this->access_token;
            $res = $this->http_request($url);
            $result = json_decode($res, true);
            $this->jsapi_ticket = $result["ticket"];
            $this->jsapi_expire = time();
            mysql_query("UPDATE `wx_token` SET `expire` = '".$this->jsapi_expire."', `value` = '".$this->jsapi_ticket."' WHERE `type` = 'jsapi_ticket';");
        }
        return $this->jsapi_ticket;
        */
		
        //2. 写文件，有改动，待测试 20150430
        $res = file_get_contents('jsapi_ticket.json');
        $result = json_decode($res, true);
        $this->jsapi_ticket = $result["jsapi_ticket"];
        $this->jsapi_expire = $result["jsapi_expire"];

        if (time() > ($this->jsapi_expire + 3600)){
            $url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?type=jsapi&access_token=".$this->access_token;
            $res = $this->http_request($url);
            $result = json_decode($res, true);
            $this->jsapi_ticket = $result["ticket"];
            $this->jsapi_expire = time();
            file_put_contents('jsapi_ticket.json', '{"jsapi_ticket": "'.$this->jsapi_ticket.'", "jsapi_expire": '.$this->jsapi_expire.'}');
        }
        return $this->jsapi_ticket;
    }

    //获得签名包
    public function getSignPackage() {
        $jsapiTicket = $this->getJsApiTicket();
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
        $url = "$protocol$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
        $timestamp = time();
        $nonceStr = $this->createNonceStr();
        $string = "jsapi_ticket=$jsapiTicket&noncestr=$nonceStr&timestamp=$timestamp&url=$url";
        $signature = sha1($string);
        $signPackage = array(
                            "appId"     => $this->appid,
                            "nonceStr"  => $nonceStr,
                            "timestamp" => $timestamp,
                            "url"       => $url,
                            "signature" => $signature,
                            "rawString" => $string
                            );
        return $signPackage;
    }
    
    //HTTP请求（支持HTTP/HTTPS，支持GET/POST）
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
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, TRUE);
        $output = curl_exec($curl);
        curl_close($curl);
        return $output;
    }

    //日志记录
    private function logger($log_content)
    {
        if(isset($_SERVER['HTTP_APPNAME'])){   //SAE
            sae_set_display_errors(false);
            sae_debug($log_content);
            sae_set_display_errors(true);
        }else if($_SERVER['REMOTE_ADDR'] != "127.0.0.1"){ //LOCAL
            $max_size = 500000;
            $log_filename = "log.xml";
            if(file_exists($log_filename) and (abs(filesize($log_filename)) > $max_size)){unlink($log_filename);}
            file_put_contents($log_filename, date('Y-m-d H:i:s').$log_content."\r\n", FILE_APPEND);
        }
    }
}
