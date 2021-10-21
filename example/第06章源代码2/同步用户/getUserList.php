<?php
require_once('weixin.class.php');
$weixin = new class_weixin();

require_once('mysql.class.php');
$db = new class_mysql();

//拉取用户列表
$userlist = $weixin->get_user_list();
for($i = 0; $i < count($userlist["data"]["openid"]); $i++)
{
    $openid = $userlist["data"]["openid"][$i];
    $mysql_state = "INSERT INTO `tp_user` (`id`, `openid`) VALUES (NULL, '".$openid."');";
    $result = $db->query($mysql_state);
}
echo "over";

// Header("Location: updateUserInfo.php");
?>
