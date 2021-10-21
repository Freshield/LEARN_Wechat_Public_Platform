<?php
namespace app\admin\controller;
use think\Controller;
use think\Db;
use org\Verify;
use think\Request;
use think\Session;

class Login extends Controller
{
    public function index()
    {
        return $this->fetch("index");
    }

    public function index2($name = 'World')
    {
        return 'Hello,' . $name . '！';
    }

    public function index3()
    {
        $data = Db::name('data')->find();
        $this->assign('result', $data);
        return $this->fetch();
    }

    public function doLogin(){
        // var_dump($_POST);
        $username = Request::instance()->param('username');
        $password = Request::instance()->param('password');
        $verifycode = Request::instance()->param('verifycode');

        //验证规则验证
        $result = $this->validate(compact('username', 'password', "verifycode"), 'AdminValidate');
        if(true !== $result){
            $this->error($result);
        }

        //检查验证码
        $verify = new Verify();
        if (!$verify->check($verifycode)) {
            $this->error('验证码错误');
        }

        //检查用户名
        $hasUser = db('admin')->where('username', $username)->find();
        if(empty($hasUser)){
            $this->error('用户名或密码错误');
        }

        //检查密码
        if(md5($password) != $hasUser['password']){
            $this->error('用户名或密码错误！');
        }
        Session::set('username',$username);
        $this->redirect('index/index');
    }

    //验证码
    public function checkVerify()
    {
        $verify = new Verify();
        $verify->imageH = 32;
        $verify->imageW = 100;
        $verify->length = 4;
        $verify->useNoise = false;
        $verify->fontSize = 14;
        return $verify->entry();
    }

    //退出
    public function doLogout(){
        //清除Session登录状态
        Session::clear();
        $this->redirect('login/index');
    }
}
