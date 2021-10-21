<?php
require_once('wxjssdk.class.php');
$weixin = new class_weixin();
$signPackage = $weixin->GetSignPackage();
?>

<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=2.0, minimum-scale=1.0, user-scalable=no" />
    <meta name="format-detection" content="telephone=no" />
    <title>位置</title>
    <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=0">
    <link rel="stylesheet" href="http://demo.open.weixin.qq.com/jssdk/css/style.css">
</head>
<body ontouchstart="">
</body>
<script src="https://res.wx.qq.com/open/js/jweixin-1.1.0.js"></script>
<script>
    wx.config({
        debug: false,
        appId: '<?php echo $signPackage["appId"];?>',
        timestamp: <?php echo $signPackage["timestamp"];?>,
        nonceStr: '<?php echo $signPackage["nonceStr"];?>',
        signature: '<?php echo $signPackage["signature"];?>',
        jsApiList: [
            'checkJsApi',
            'openLocation',
            'getLocation',
          ]
    });

    wx.ready(function () {
        
        //自动执行的
        wx.checkJsApi({
            jsApiList: [
                'getLocation',
            ],
            success: function (res) {
            }
        });
    
        //如果不支持则不会执行
        wx.getLocation({
            success: function (res) {
                alert(JSON.stringify(res));
                alert('经度' + res.longitude + '纬度' + res.latitude);
                alert('纬度' + res.latitude);
          },
          cancel: function (res) {
                alert('用户拒绝授权获取地理位置');
          }
        });
      
    });

    wx.error(function (res) {
        alert(res.errMsg);
    });
 </script>
</html>
