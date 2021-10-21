<?php
namespace app\admin\controller;
use think\Controller;
use think\Db;
use think\Session;
use app\admin\model\MessageModel;

class Message extends Controller
{
	public function _initialize()
    {
        // 初始化的时候检查用户登录状态
		if(!Session::has('username')){
			$this->redirect('login/index');
		}
	}

    public function index()
    {
        //48小时有交互用户
        $condition['heartbeat']  = array('gt',(time() - 172800));
        $list = Db::name('user')->where($condition)->select();

        // 获取用户数
        $this->assign('total', count($list));

        //获取已有消息
        $message = MessageModel::get(3);
        $this->assign('message', $message->toArray());

        // 渲染模板输出
        return $this->fetch();
    }

    public function send()
    {
        //更新并存储当前消息
        $message = new MessageModel;
        // save方法第二个参数为更新条件
        $message->save(['title' => $_POST['title'],
                        'description' => $_POST['description'],
                        'picurl' => $_POST['picurl'],
                        'url' => $_POST['url'],
                        'date' => date("Ymd",time())
                      ],['id' => $_POST['id']]);
        
        // 1和2为客服消息， 3为模板消息
        if ($_POST['id'] == "3"){
            $condition = null;
        }else{
            $condition['heartbeat']  = array('gt',(time() - 172800));
        }
        $userlist = Db::name('user')->where($condition)->select();
        
        //准备微信类
        $weixin = new \weixin\Wxapi();
        $data = array();
        $data[] = array("title"=>$_POST['title'], "description"=>$_POST['description'], "picurl"=>$_POST['picurl'], "url" =>$_POST['url']);
        
        //遍历发送
        $array = array();
        foreach ($userlist as &$user) {
            $openid = $user['openid'];
            // $url = U('User/sendMsg',array('openid'=>$user['openid']));
            // $array[] = array('url'=>$url);
            // // dump($url);
            if ($_POST['id'] == "3"){
                $template = array('touser' => $openid,
                                  'template_id' => "_yFpVtfHd0pSWy6ffApi6isjY8HmmWC8aKW-Uqz8viU",
                                  'url' => $_POST['url'],
                                  'topcolor' => "#0000C6",
                                  'data' => array('content'    => array('value' => $_POST['description'],
                                                                      'color' => "#743A3A",
                                                                    ),
                                                )
                );
                $result = $weixin->send_template_message($template);
            }else{
                $result = $weixin->send_custom_message($openid, "news", $data);
            }
            var_dump($openid);
            var_dump($result);
        }
        // $template = array('touser' => "ojpX_jlvBDzjmdY3Ake9GVp9rldE",
                          // 'template_id' => "_yFpVtfHd0pSWy6ffApi6isjY8HmmWC8aKW-Uqz8viU",
                          // 'url' => "",
                          // 'topcolor' => "#0000C6",
                          // 'data' => array('content'    => array('value' => $_POST['description'],
                                                              // 'color' => "#743A3A",
                                                            // ),
                                        // )
        // );
        // $result = $weixin->send_template_message($template);
        // var_dump($result);
        
    }
    

    public function send2()
    {
        // //更新并存储当前消息
        // $message = new MessageModel;
        // $message->save(['title' => $_POST['title'],
                        // 'description' => $_POST['description'],
                        // 'picurl' => $_POST['picurl'],
                        // 'url' => $_POST['url'],
                        // 'date' => date("Ymd",time())
                      // ],['id' => $_POST['id']]);

        // //获取48小时用户列表
        // $condition['heartbeat']  = array('gt',(time() - 172800));
        // $userlist = Db::name('user')->where($condition)->select();
        
        // //准备微信类及群发图文
        // $weixin = new \weixin\Wxapi();
        // $data = array();
        // $data[] = array("title"=>$_POST['title'], "description"=>$_POST['description'], "picurl"=>$_POST['picurl'], "url" =>$_POST['url']);
        
        // $result = $weixin->send_custom_message("ojpX_jig-gyi3_Q9fHXQ4rdHniQs", "news", $data);
        // var_dump($result);
    }
}
