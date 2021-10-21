<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta name="viewport" content="width=device-width,height=device-height,inital-scale=1.0,maximum-scale=1.0,user-scalable=no;">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black">
    <meta name="format-detection" content="telephone=no">
    <title>幸运大转盘抽奖</title>
    <link href="css/activity-style.css" rel="stylesheet" type="text/css">
  </head>

  <body class="activity-lottery-winning" >
    <div class="main" >
      <script type="text/javascript">
        var loadingObj = new loading(document.getElementById('loading'),{radius:20,circleLineWidth:8});
        loadingObj.show();
      </script>
      <div id="outercont"  >
        <div id="outer-cont">
          <div id="outer"><img src="img/activity-lottery-5.png"></div>
        </div>
        <div id="inner-cont">
          <div id="inner"><img src="img/activity-lottery-2.png"></div>
        </div>
      </div>
      <div class="content"  >
        <div class="boxcontent boxyellow" id="result" style="display:none" >
          <div class="box">
            <div class="title-orange"><span>恭喜你中奖了</span></div>
            <div class="Detail">
              <p>你中了：<span class="red" id="prizelevel" ></span></p>
              <p class="red" id="red">你可向公众号发送【中奖】查询您的中奖结果!  </p>
            </div>
          </div>
        </div>
        <div class="boxcontent boxyellow">
          <div class="box">
            <div class="title-green"><span>奖项设置：</span></div>
            <div class="Detail">
              <p>一等奖：iphone6 奖品数量：10 </p>
              <p>二等奖：ipad6 。 奖品数量：20 </p>
              <p>三等奖：ipad mini2奖品数量：100 </p>
              <p>四等奖：iphone6 。奖品数量：10 </p>
              <p>五等奖：ipad6 。  奖品数量：20 </p>
              <p>六等奖：ipad mini 奖品数量：100 </p>
            </div>
          </div>
        </div>
        <div class="boxcontent boxyellow">
          <div class="box">
            <div class="title-green">活动说明：</div>
            <div class="Detail">
              <p>本次活动每人可以转 3 次 </p>
              <p>亲，大奖转出来，祝您好运哦！!  </p>
            </div>
          </div>
        </div>
      </div>

    </div>

    <script src="js/jquery.js" type="text/javascript"></script>
    <script src="js/alert.js" type="text/javascript"></script>
    <script type="text/javascript">
      $(function() {
        window.requestAnimFrame = (function() {
          return window.requestAnimationFrame || window.webkitRequestAnimationFrame || window.mozRequestAnimationFrame || window.oRequestAnimationFrame || window.msRequestAnimationFrame ||
          function(callback) {
            window.setTimeout(callback, 1000 / 60)
          }
        })();
        var totalAngle  = 0;
        var steps = [];
        var loseAngle = [36, 96, 156, 216, 276,336];
        var winAngle = [6, 66, 126,186,246,306];
        var prizeLevel;
        var count = 0;
        var now = 0;
        var a = 0.01;
        var outter, inner, timer, running = false;
        function countSteps() {
          var t = Math.sqrt(2 * totalAngle / a);
          var v = a * t;
          for (var i = 0; i < t; i++) {
            steps.push((2 * v * i - a * i * i) / 2)
          }
          steps.push(totalAngle)
        }
        function step() {
          outter.style.webkitTransform = 'rotate(' + steps[now++] + 'deg)';
          outter.style.MozTransform = 'rotate(' + steps[now++] + 'deg)';
          outter.style.oTransform = 'rotate(' + steps[now++] + 'deg)';
          outter.style.msTransform = 'rotate(' + steps[now++] + 'deg)';
          if (now < steps.length) {
            requestAnimFrame(step)
          } else {
            running = false;
            setTimeout(function() {
              if (prizeLevel != null) {
                var levelName= new Array("", "一等奖", "二等奖", "三等奖", "四等奖", "五等奖", "六等奖")
                // var levelName = "";
                // if (prizeLevel == 1) {
                  // levelName = "一等奖"
                // } else if (prizeLevel == 2) {
                  // levelName = "二等奖"
                // } else if (prizeLevel == 3) {
                  // levelName = "三等奖"
                // } else if (prizeLevel == 4) {
                  // levelName = "四等奖"
                // } else if (prizeLevel == 5) {
                  // levelName = "五等奖"
                // } else if (prizeLevel == 6) {
                  // levelName = "六等奖"
                // }
                $("#prizelevel").text(levelName[prizeLevel]);
                $("#result").slideToggle(500);  //显示中奖结果
                $("#outercont").slideUp(500)    //隐藏转盘
              } else {
                alert("亲，继续努力哦！")
              }
            },
            200)
          }
        }
        function start(deg) {
          deg = deg || loseAngle[parseInt(loseAngle.length * Math.random())];
          running = true;
          clearInterval(timer);
          totalAngle  = 360 * 1 + deg;
          steps = [];
          now = 0;
          countSteps();
          requestAnimFrame(step)
        }
        window.start = start;
        outter = document.getElementById('outer');
        inner = document.getElementById('inner');
        i = 10;
        $("#inner").click(function() {
          if (running) return;
          if (count >= 3) {
            alert("您已经抽了 3 次奖,不能再抽了,下次再来吧!");
            return
          }
          //没有获得中奖json返回，让用户退出
          if (prizeLevel != null) {
            alert("亲，你不能再参加本次活动了喔！下次再来吧~");
            return
          }
          $.ajax({
            url: "data.php",
            dataType: "json",
            data: {
              openid: "o7MB9jg5Oi_VNIZzeBX9mWPZP3Y4",
              time: (new Date()).valueOf()
            },
            beforeSend: function() {
              running = true;
              timer = setInterval(function() {
                i += 5;
                outter.style.webkitTransform = 'rotate(' + i + 'deg)';
                outter.style.MozTransform = 'rotate(' + i + 'deg)'
              },
              1)
            },
            success: function(data) {
              //达到最大抽奖次数
              if (data.error == "max_times") {
                alert("您已经抽了 3 次奖,不能再抽了,下次再来吧!");
                count = 3;
                clearInterval(timer);
                return
              }
              //已中奖
              if (data.error == "ok") {
                $("#tel").val(data.tel);
                $("#red").text(data.message);
                // alert(data.message);
                count = 3;
                clearInterval(timer);
                prizeLevel = data.prizelevel;
                start(winAngle[data.prizelevel - 1]);
                return
              }
              //未中奖则累加次数
              running = false;
              count++
              prizeLevel = null;
              start()
            },
            //未获取json返回时
            error: function() {
              // alert(data.message);
              prizeLevel = null;
              start();
              running = false;
              count++
            },
            timeout: 4000
          })
        })
      });

      //保存用户中奖信息，手机号
      $("#save-btn").bind("click",
      function() {
        var btn = $(this);
        var tel = $("#tel").val();
        if (tel == '') {
          alert("请输入手机号");
          return
        }

        var submitData = {
          openid: 20,
          // code: $("#sncode").text(),
          tel: tel
        };
        $.post('data.php', submitData,
        function(data) {
          if (data.error == "ok") {
            alert(data.message);
            $("#result").slideUp(500);  //隐藏中奖结果
            $("#outercont").slideToggle(500)    //显示转盘
            return
          }
        },
        "json")
      });

    </script>
  </body>
</html>