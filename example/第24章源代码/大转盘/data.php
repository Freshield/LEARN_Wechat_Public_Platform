<?php

// $openid = $_GET["openid"];
// $candidate = $_GET["candidate"];
// logger2($_GET['token']);
// logger2($_GET['t']);
// // error 是否中奖 ok 中奖， 
// // message 提示说明
// // prizelevel 奖品等级
// logger2($_GET['time']);
// logger2($_GET['openid']);
// logger2($_GET['tel']);
if (rand(1, 1000) <= 400){
    //将中奖记录写入数据库
    // logger2($_GET['time']);
    // logger2($_GET['openid']);
    // logger2($_GET['tel']);
    echo '{
        "error": "ok",
        "message": "奖品为iPhone5",
        "prizelevel": "2", 
        "success": "y"
    }';
}

function logger2($log_content)
{
    if(isset($_SERVER['HTTP_BAE_ENV_APPID'])){   //BAE
        require_once "BaeLog.class.php";
        $logger = BaeLog::getInstance();
        $logger ->logDebug($log_content);
    }else if (isset($_SERVER['HTTP_APPNAME'])){   //SAE
        sae_set_display_errors(false);
        sae_debug($log_content);
        sae_set_display_errors(true);
    }else {
        $max_size = 100000;
        $log_filename = "log.xml";
        if(file_exists($log_filename) and (abs(filesize($log_filename)) > $max_size)){unlink($log_filename);}
        file_put_contents($log_filename, date('H:i:s')." ".$log_content."\r\n", FILE_APPEND);
    }
}
?>