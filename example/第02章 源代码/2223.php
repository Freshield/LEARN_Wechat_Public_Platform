<?php
$con = mysql_connect("localhost:3306","root","root");
mysql_query("SET NAMES 'UTF8'");
mysql_select_db("book", $con);
$result = mysql_query("SELECT * FROM `wx_user` WHERE `openid` = 'o7Lp5t6n59DeX3U0C7Kric9qEx-Q';");
while($row = mysql_fetch_array($result))
{
	echo $row['username']." ".$row['telephone'];
	echo "<br />";
}
mysql_close($con);
?>
