<?php
namespace app\admin\controller;
use think\Controller;
use think\Db;
use think\View;
use think\Session;

class Index extends Controller
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
        return $this->fetch();
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
    
    public function hello($name = 'World', $city = '')
    {
        return 'Hello,' . $name . '! You come from ' . $city . '.';
    }


	// 后台首页 查看系统信息
	public function main() {
		
        
        // $mysql= M()->query("select VERSION() as version");
    	// $mysql=$mysql[0]['version'];
    	// $mysql=empty($mysql)?L('UNKNOWN'):$mysql;
        
		$info = array(
			'操作系统'=>PHP_OS,
			'运行环境'=>$_SERVER["SERVER_SOFTWARE"],
			'PHP运行方式'=>php_sapi_name(),
            'PHP版本'=>PHP_VERSION,
            // 'MySQL版本'=>$mysql,
			'ThinkPHP版本'=>THINK_VERSION,
			'上传附件限制'=>ini_get('upload_max_filesize'),
			'执行时间限制'=>ini_get('max_execution_time').'秒',
			'服务器时间'=>date("Y年n月j日 H:i:s"),
			// '北京时间'=>gmdate("Y年n月j日 H:i:s",time()+8*3600),
			'服务器域名'=>$_SERVER['SERVER_NAME'],
            '服务器IP'=>gethostbyname($_SERVER['SERVER_NAME']),
			'剩余空间'=>round((@disk_free_space(".")/(1024*1024)),2).'M',
         
			);
		// dump($info);
		$this->assign('info',$info);
		return $this->fetch();
	}
}
