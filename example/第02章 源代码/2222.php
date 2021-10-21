<?php
$con = mysql_connect("localhost:3306","root","root");
mysql_query("SET NAMES 'UTF8'");
mysql_select_db("book", $con);
mysql_query("UPDATE `wx_user` SET `telephone` = '15999521234' WHERE `openid` = 'o7Lp5t6n59DeX3U0C7Kric9qEx-Q';");
mysql_close($con);
?>