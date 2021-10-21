<?php
header("Content-type: text/html; charset=utf-8");

require_once('weixin.class.php');
$weixin = new class_weixin();

require_once('mysql.class.php');
$db = new class_mysql();

$mysql_state = "SELECT * FROM `tp_user` WHERE `subscribe` = '' LIMIT 0, 1";
$result = $db->query_array($mysql_state);

$sexes = array("", "男", "女");
if (count($result) > 0){
    $openid = $result[0]["openid"];
    var_dump($openid);
    $info = $weixin->get_user_info($openid);
    var_dump($info);
    $mysql_state2 = "UPDATE `tp_user` SET 
        `sex` = '".$sexes[$info['sex']]."', 
        `country` = '".$info['country']."', 
        `province` = '".$info['province']."', 
        `city` = '".$info['city']."', 
        `headimgurl` = '".$info['headimgurl']."',
        `subscribe` = '".$info['subscribe_time']."'
        WHERE `openid` = '".$openid."';";
	$result = $db->query($mysql_state2);
    $mysql_state3 = "UPDATE `tp_user` SET `nickname` = '".$info['nickname']."' WHERE `openid` = '".$openid."';";
	$result = $db->query($mysql_state3);
    echo "<script language=JavaScript> location.replace(location.href);</script>";
}else{
    echo "over";
}


// for($i = 0; $i < count($userlist["data"]["openid"]); $i++)
// {
	// $newuser = true;
	// $openid = $userlist["data"]["openid"][$i];
	// for($j = 0; $j < count($result); $j++)
	// {
		// if ($result[$j]["openid"] == $openid)
		// {
			// $newuser = false;
			// break;
		// }
	// }
	// // break;
	// if ($newuser){
		// // var_dump($openid."#######");
		// // var_dump($result);
		
		// $info = $weixin->get_user_info($openid);
		// //性别中文
		// $sexes = array("", "男", "女");
		// $info['sex'] = $sexes[$info['sex']];
		// //昵称中含有' 引起sql语法出错
		// $info['nickname'] = str_replace("'","",$info['nickname']);

		// $mysql_state = "INSERT INTO `tp_user` (`id`, `openid`, `nickname`, `remark`, `sex`, `country`, `province`, `city`, `latitude`, `longitude`, `location`, `headimgurl`, `latest`) VALUES (NULL, '".$openid."', '".$info['nickname']."', '".$info['remark']."', '".$info['sex']."', '".$info['country']."', '".$info['province']."', '".$info['city']."', '', '', '', '".$info['headimgurl']."', '".$info['subscribe_time']."');";
		// $result = $db->query($mysql_state);

		// $mysql_state2 = "UPDATE `tp_user` SET `latest` = '".$info['subscribe_time']."' WHERE `openid` = '".$openid."';";
		// $result = $db->query($mysql_state2);
	// }

// }

// Header("Location: user_list.php");
?>
