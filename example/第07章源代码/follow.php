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
    $access_token = $weixin->oauth2_access_token($_GET["code"]);
    $openid = $access_token['openid'];
    $info = $weixin->get_user_info($openid);
    if ($info["subscribe"] == 1){
        $href = "http://www.baidu.com/";
    }else{
        $href = "http://mp.weixin.qq.com/s?__biz=MzA5NzM2MTI4OA==&mid=203240737&idx=1&sn=007bbbe06fb89cbce76d6f8b619acc1a&scene=0#wechat_redirect";
    }
    Header("Location: $href");
    exit();
}
?>
