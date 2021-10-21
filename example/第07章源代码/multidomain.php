<?php
require_once('weixin.class.php');
$weixin = new class_weixin();
$openid = "";
if (!isset($_GET["code"])){
    $redirect_url = 'http://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
    $jumpurl = $weixin->oauth2_authorize($redirect_url, "snsapi_base", "123");
    Header("Location: $jumpurl");
    exit();
}else{
    $oauth2_info = $weixin->oauth2_access_token($_GET["code"]);
    if ($_GET["domain"] == 1){
        $href = "http://www.a.com/?accesstoken=".$oauth2_info['access_token']."&openid=".$oauth2_info['openid'];
    }else if ($_GET["domain"] == 2){
        $href = "http://www.b.com/?accesstoken=".$oauth2_info['access_token']."&openid=".$oauth2_info['openid'];
    }else if ($_GET["domain"] == 3){
        $href = "http://www.c.com/?accesstoken=".$oauth2_info['access_token']."&openid=".$oauth2_info['openid'];
    }
    Header("Location: $href");
    exit();
}
?>
