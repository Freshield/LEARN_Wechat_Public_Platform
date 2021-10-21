<?php
header("Content-type: text/html; charset=utf-8");

//APPID
define('APPID', "wxbd22762e0e24f123");
//商户id，10025915
define('MCHID', "1002378");
//微信支付密钥，商户平台中，账户设置->安全设置->API安全->API密钥：api设置
define('PARTNERKEY',"11111111111111111111111111111111");
//用户OpenID
$openid = "ozh-4jg4F8zkHlz-xmUavAJzrXEo";


//以下接口均已调试成功，需要你自行对接到自己的系统中。



//现金红包
$money = 101;
$sender = "方倍";
$obj2 = array();
$obj2['wxappid']         	= APPID;
$obj2['mch_id']         	= MCHID;
$obj2['mch_billno']			= MCHID.date('YmdHis').rand(1000, 9999);
$obj2['client_ip']    		= $_SERVER['REMOTE_ADDR'];
$obj2['re_openid']         	= "ozh-4jg4F8zkHlz-xmUavAJzrXEo";
$obj2['total_amount']       = $money;
$obj2['min_value']         	= $money;
$obj2['max_value']         	= $money;
$obj2['total_num']         	= 1;
$obj2['nick_name']      	= $sender;
$obj2['send_name']      	= $sender;
$obj2['wishing']        	= "恭喜发财";
$obj2['act_name']      		= $sender."红包";
$obj2['remark']      		= $sender."红包";

var_dump($obj2);

$url = 'https://api.mch.weixin.qq.com/mmpaymkttransfers/sendredpack';
$wxHongBaoHelper2 = new WxPay();
$result = $wxHongBaoHelper2->pay($url, $obj2);
var_dump($result);



// //裂变红包
// $money = 501;
// $sender = "方倍";
// $obj3 = array();
// $obj3['wxappid']         	= APPID;
// $obj3['mch_id']         	= MCHID;
// $obj3['mch_billno']			= MCHID.date('YmdHis').rand(1000, 9999);
// // $obj3['client_ip']    		= $_SERVER['REMOTE_ADDR'];
// $obj3['re_openid']         	= "orgvAt8BtFG33GCbrLgKZR8eNTKg";
// $obj3['total_amount']       = $money;
// $obj3['amt_type']         	= "ALL_RAND";
// // $obj3['max_value']         	= $money;
// $obj3['total_num']         	= 3;
// // $obj3['nick_name']      	= $sender;
// $obj3['send_name']      	= $sender;
// $obj3['wishing']        	= "恭喜发财";
// $obj3['act_name']      		= $sender."红包";
// $obj3['remark']      		= $sender."红包";


// var_dump($obj3);

// $url = 'https://api.mch.weixin.qq.com/mmpaymkttransfers/sendgroupredpack';
// $wxHongBaoHelper3 = new WxPay();
// $result = $wxHongBaoHelper3->pay($url, $obj3);
// var_dump($result);




// //企业付款
// $obj1 = array();
// $obj1['openid']         	= "ozh-4jg4F8zkHlz-xmUavAJzrXEo";
// $obj1['amount']         	= "101";
// $obj1['desc']        		= "毛小二付款";
// $obj1['mch_appid']         	= APPID;
// $obj1['mchid']         		= MCHID;
// $obj1['partner_trade_no']	= MCHID.date('YmdHis').rand(1000, 9999);
// $obj1['spbill_create_ip']   = $_SERVER['REMOTE_ADDR'];
// $obj1['check_name']      	= "FORCE_CHECK";
// $obj1['re_user_name']    	= "方倍";

// var_dump($obj1);
// $url = 'https://api.mch.weixin.qq.com/mmpaymkttransfers/promotion/transfers';
// $wxHongBaoHelper = new WxPay();
// $result = $wxHongBaoHelper->pay($url, $obj1);
// var_dump($result);




// // //红包查询(含现金红包和裂变红包)
// // $obj4 = array();
// // $obj4['appid']         		= APPID;
// // $obj4['mch_id']         	= MCHID;
// // $obj4['mch_billno']			= "1253901501201508011624442581";
// // $obj4['bill_type']         	= "MCHT";
// // var_dump($obj4);

// // $url = 'https://api.mch.weixin.qq.com/mmpaymkttransfers/gethbinfo';
// // $wxHongBaoHelper4 = new WxPay();
// // $result = $wxHongBaoHelper4->pay($url, $obj4);

//企业付款查询
// $obj5 = array();
// $obj5['appid']         		= APPID;
// $obj5['mch_id']         	= MCHID;
// $obj5['partner_trade_no']	= "1253901501201508011624425667";

// var_dump($obj5);

// $url = 'https://api.mch.weixin.qq.com/mmpaymkttransfers/gettransferinfo';
// $wxHongBaoHelper5 = new WxPay();
// $result = $wxHongBaoHelper5->pay($url, $obj5);


class WxPay
{
	function __construct()
	{

	}
	
	function pay($url, $obj) 
	{
		$obj['nonce_str'] = $this->create_noncestr();
		$stringA = $this->formatQueryParaMap($obj, false);
		$stringSignTemp = $stringA . "&key=" . PARTNERKEY;
		$sign = strtoupper(md5($stringSignTemp));
		$obj['sign'] = $sign;
		
		$postXml = $this->arrayToXml($obj);
		$responseXml = $this->curl_post_ssl($url, $postXml);
		return $responseXml;
	}

	function create_noncestr($length = 32) 
	{
		$chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		$str = "";
		for ( $i = 0; $i < $length; $i++ )  {
			$str.= substr($chars, mt_rand(0, strlen($chars)-1), 1);
		}
		return $str;
	}

	function formatQueryParaMap($paraMap, $urlencode)
	{
		$buff = "";
		ksort($paraMap);
		foreach ($paraMap as $k => $v){
			if (null != $v && "null" != $v && "sign" != $k) {
			    if($urlencode){
				   $v = urlencode($v);
				}
				$buff .= $k . "=" . $v . "&";
			}
		}
		$reqPar;
		if (strlen($buff) > 0) {
			$reqPar = substr($buff, 0, strlen($buff)-1);
		}
		return $reqPar;
	}

	//数组转XML
	function arrayToXml($arr)
    {
        $xml = "<xml>";
        foreach ($arr as $key=>$val)
        {
			if (is_numeric($val)){
				$xml.="<".$key.">".$val."</".$key.">";
        	}else{
        	 	$xml.="<".$key."><![CDATA[".$val."]]></".$key.">";
			}
		}
        $xml.="</xml>";
        return $xml;
    }

	function curl_post_ssl($url, $vars, $second=30)
	{
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_TIMEOUT, $second);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,false);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,false);

		if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {	//Windows
			curl_setopt($ch, CURLOPT_SSLCERT, dirname(__FILE__).'cert'.DIRECTORY_SEPARATOR.'apiclient_cert.pem');
			curl_setopt($ch, CURLOPT_SSLKEY, dirname(__FILE__).'cert'.DIRECTORY_SEPARATOR.'apiclient_key.pem');
			curl_setopt($ch, CURLOPT_CAINFO, dirname(__FILE__).'cert'.DIRECTORY_SEPARATOR.'rootca.pem');
        }else{                        //LINUX
            curl_setopt($ch, CURLOPT_SSLCERT, 'cert'.DIRECTORY_SEPARATOR.'apiclient_cert.pem');
			curl_setopt($ch, CURLOPT_SSLKEY, 'cert'.DIRECTORY_SEPARATOR.'apiclient_key.pem');
			curl_setopt($ch, CURLOPT_CAINFO, 'cert'.DIRECTORY_SEPARATOR.'rootca.pem');
        }

		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $vars);
		$data = curl_exec($ch);
		if($data){
			curl_close($ch);
			return $data;
		}else {
			$error = curl_errno($ch);
			echo "call faild, errorCode:$error\n";
			curl_close($ch);
			return false;
		}
	}
}

?>