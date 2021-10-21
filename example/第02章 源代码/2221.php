<?php
$con = mysql_connect("localhost:3306","root","root");
mysql_query("SET NAMES 'UTF8'");
mysql_select_db("book", $con);
mysql_query("INSERT INTO `wx_user` (`id`, `openid`, `username`, `telephone`) VALUES (NULL, 'oLp5t6n59DeX3U0C7KricqEx-Q', '方倍', '15987654321');");
mysql_close($con);
?>