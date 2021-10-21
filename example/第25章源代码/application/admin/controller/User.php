<?php
namespace app\admin\controller;
use think\Controller;
use think\Db;
use think\Session;

class User extends Controller
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
        // 查询用户数据 并且每页显示15条数据
        $list = Db::name('user')->order('heartbeat desc')->paginate(15);
        // var_dump($list);

        // 把分页数据赋值给模板变量list
        $this->assign('list', $list);
        // 渲染模板输出
        return $this->fetch();
    }

    public function accesstoken()
    {
        $weixin = new \weixin\Wxapi();
        dump($weixin);
    }


	public function updateList(){
        //获取微信用户列表
        $weixin = new \weixin\Wxapi();
        $result = $weixin->get_user_list();

        //获取本地用户列表
        $openidlist = Db::name('user')->column('openid');
        // dump($openidlist);
        
        //计算未更新用户列表
        $intersection = array_diff($result["data"]["openid"], $openidlist);

        //同步入库
        $data = array();
        foreach ($intersection as &$openid) {
            $data[] = array('openid'=>$openid);
        }
        $insertresult = Db::name('user')->insertAll($data);
        
        $this->success('更新了'.count($intersection).'个用户','index');
	}

	public function updateInfo(){
        $weixin = new \weixin\Wxapi();

         //获取本地用户列表
        $updateUser = Db::name('user')->where('subscribe','')->limit(100)->select();
       
        if (count($updateUser) > 0){
            $municipalities = array("北京", "上海", "天津", "重庆", "香港", "澳门");
            $sexes = array("", "男", "女");

            $new = 0;
            foreach ($updateUser as &$user) {
                $new ++;
                $info = $weixin->get_user_info($user['openid']);
                // var_dump($info);
                $data = array();
                $data['nickname'] = str_replace("'", "", $info['nickname']);
                $data['sex'] = $sexes[$info['sex']];
                $data['country'] = $info['country'];
                $data['province'] = $info['province'];
                $data['city'] = (in_array($info['province'], $municipalities))?$info['province'] : $info['city'];
                $data['headimgurl'] = $info['headimgurl'];
                $data['subscribe'] = $info['subscribe_time'];
                $data['heartbeat'] = $info['subscribe_time'];
                $data['remark'] = $info['remark'];
                $data['tagid'] = $info['tagid_list'];
                
                Db::name('user')->where('openid', $user['openid'])->update($data);// 根据条件更新记录
            }

            $this->success('更新了'.$new.'个用户','updateInfo');
        }else{
            $this->success('更新完成','index');
        }
	}
    
	public function rank()
    {
        $arr = Db::name('user')->field('city,COUNT(`city`) total')->where('city','<>','')->group('city')->order('total desc')->limit(15)->select();
		$this->assign('list', $arr);
		return $this->fetch();
	}
    
	public function delete($id){
        if (!empty($id)) {
            $result = Db::name('user')->where('id',$id)->delete();
            if (0 != $result) {
                $this->success('删除成功！');
            } else {
                $this->error('删除出错！');
            }
        } else {
            $this->error('ID错误！');
        }
	}

    public function test()
    {
        $data = Db::name('data')->find();
        $this->assign('result', $data);
        return $this->fetch();
    }
}
