<?php
$appid = "wx3f88af80a4c0a09d";
$appsecret = "123";
$url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=$appid&secret=$appsecret";

$output = http_request($url);
$jsoninfo = json_decode($output, true);
$access_token = $jsoninfo["access_token"];

//永久二维码
for ($i = 1; $i<= 8; $i++) {
    $scene_id = $i;
    $qrcode = '{"action_name": "QR_LIMIT_SCENE", "action_info": {"scene": {"scene_id": '.$scene_id.'}}}';

    $url = "https://api.weixin.qq.com/cgi-bin/qrcode/create?access_token=$access_token";
    $result = http_request($url, $qrcode);
    $jsoninfo = json_decode($result, true);
    $ticket = $jsoninfo["ticket"];
    $url = "https://mp.weixin.qq.com/cgi-bin/showqrcode?ticket=".urlencode($ticket);
    $imageInfo = downloadWeixinFile($url);

    $filename = "qrcode".$scene_id.".jpg";
    $local_file = fopen($filename, 'w');
    fwrite($local_file, $imageInfo["body"]);
    fclose($local_file);
}

//http请求
function http_request($url, $data = null)
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

//下载文件
function downloadWeixinFile($url)
{
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_HEADER, 0);    
    curl_setopt($ch, CURLOPT_NOBODY, 0);    //只取body头
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $package = curl_exec($ch);
    $httpinfo = curl_getinfo($ch);
    curl_close($ch);
    $imageAll = array_merge(array('body' =>$package), array('header' =>$httpinfo)); 
    return $imageAll;
}
