<?php
$x=10; 
$y=6;
echo ($x + $y); // 输出 16
echo "<br>";
echo ($x - $y); // 输出 4
echo "<br>";
echo ($x * $y); // 输出 60
echo "<br>";
echo ($x / $y); // 输出 1.6666666666667
echo "<br>";
echo ($x % $y); // 输出 4
echo "<br>";
$z=5;
$z *= 6;
echo $z; // 输出 30
echo "<br>";
$x="Hello";
$x .= " weixin!";
echo $x; // 输出 Hello weixin!
echo "<br>";
$i=5;
echo $i--; // 输出 5
echo "<br>";
$a=50;
$b=90;
var_dump($a > $b);

$max = ($a>=$b) ? $a : $b;
echo $max; // 输出 90
?>