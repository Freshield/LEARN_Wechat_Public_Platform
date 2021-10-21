<?php
require_once('weixin.class.php');
$weixin = new class_weixin();

if (!isset($_GET["code"])){
    $redirect_url = 'http://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
    $jumpurl = $weixin->oauth2_authorize($redirect_url, "snsapi_userinfo", "123");
    Header("Location: $jumpurl");
}else{
    $access_token_oauth2 = $weixin->oauth2_access_token($_GET["code"]);
    $userinfo = $weixin->oauth2_get_user_info($access_token_oauth2['access_token'], $access_token_oauth2['openid']); 
}
?>
<!DOCTYPE html>
<html lang="zh-cn">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width,initial-scale=1,user-scalable=0">
        <title>网页授权Demo</title>
        <link rel="stylesheet" href="css/weui.min.css">
        <link rel="stylesheet" href="css/example.css">
    </head>
    <body ontouchstart="">
        <div class="container js_container">
            <div class="page cell">
                <div class="hd">
                    <h1 class="page_title">微信网页授权</h1>
                    <p class="page_desc">方倍工作室 出品</p>
                </div>
                <div class="bd">
                    <div class="weui_cells_title">个人信息</div>
                    <div class="weui_cells">
                        <div class="weui_cell">
                            <div class="weui_cell_bd weui_cell_primary">
                                <p>OpenID</p>
                            </div>
                            <div class="weui_cell_ft"><?php echo $userinfo["openid"];?></div>
                        </div>
                        <div class="weui_cell ">
                            <div class="weui_cell_bd weui_cell_primary">
                                <p>头像</p>
                            </div>
                            <div class="weui_cell_ft"><img src="<?php echo str_replace("/0","/46",$userinfo["headimgurl"]);?>"></div>
                        </div>
                        <div class="weui_cell">
                            <div class="weui_cell_bd weui_cell_primary">
                                <p>昵称</p>
                            </div>
                            <div class="weui_cell_ft"><?php echo $userinfo["nickname"];?></div>
                        </div>
                        <div class="weui_cell">
                            <div class="weui_cell_bd weui_cell_primary">
                                <p>性别</p>
                            </div>
                            <div class="weui_cell_ft"><?php echo $userinfo["sex"];?></div>
                        </div>
                        <div class="weui_cell">
                            <div class="weui_cell_bd weui_cell_primary">
                                <p>地区</p>
                            </div>
                            <div class="weui_cell_ft"><?php echo $userinfo["country"];?> <?php echo $userinfo["province"];?> <?php echo $userinfo["city"];?></div>
                        </div>
                        <div class="weui_cell">
                            <div class="weui_cell_bd weui_cell_primary">
                                <p>语言</p>
                            </div>
                            <div class="weui_cell_ft"><?php echo $userinfo["language"];?></div>
                        </div>
                    </div>

                </div>
            </div>
        </div>
    </body>
</html>