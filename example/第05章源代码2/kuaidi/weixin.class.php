<?php

/*
    方倍工作室 http://www.fangbei.org/
    CopyRight 2014 All Rights Reserved
*/

require_once('config.php');

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
        $this->access_token = $result["access_token"];
        $this->expires_time = time();
    }

    //创建菜单
    public function create_menu($button, $matchrule = NULL)
    {
        foreach ($button as &$item) {
            foreach ($item as $k => $v) {
                if (is_array($v)){
                    foreach ($item[$k] as &$subitem) {
                        foreach ($subitem as $k2 => $v2) {
                            $subitem[$k2] = urlencode($v2);
                        }
                    }
                }else{
                    $item[$k] = urlencode($v);
                }
            }
        }

        if (isset($matchrule) && !is_null($matchrule)){
            foreach ($matchrule as $k => $v) {
                $matchrule[$k] = urlencode($v);
            }
            $data = urldecode(json_encode(array('button' => $button, 'matchrule' => $matchrule)));
            $url = "https://api.weixin.qq.com/cgi-bin/menu/addconditional?access_token=".$this->access_token;
        }else{
            $data = urldecode(json_encode(array('button' => $button)));
            $url = "https://api.weixin.qq.com/cgi-bin/menu/create?access_token=".$this->access_token;
        }
        $res = $this->http_request($url, $data);
        return json_decode($res, true);
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
