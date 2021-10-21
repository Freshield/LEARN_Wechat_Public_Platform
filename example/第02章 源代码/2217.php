<?php
$office = array('word', 'excel', 'outlook', 'access'); 
$arrlength=count($office);

for($x=0;$x<$arrlength;$x++) {
  echo $office[$x];
  echo "<br>";
}

$age=array("张三"=>"25","李四"=>"27","王五"=>"33");

foreach($age as $key=>$value) {
  echo "Key=" . $key . ", Value=" . $value;
  echo "<br>";
}
?>