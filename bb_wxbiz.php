<?php if (!defined('BASEPATH')) exit('No direct script access allowed');
class Bb_wxbiz
{
	function __construct() {
		$this->obj =& get_instance();
		$this->initialize();
	}
	
	public function initialize() {
		include_once "lib/wxbiz/sha1.php";
		include_once "lib/wxbiz/xmlparse.php";
		include_once "lib/wxbiz/pkcs7Encoder.php";
		include_once "lib/wxbiz/errorCode.php";
	}
	





    /*
	*验证URL
    *@param sMsgSignature: 签名串，对应URL参数的msg_signature
    *@param sTimeStamp: 时间戳，对应URL参数的timestamp
    *@param sNonce: 随机串，对应URL参数的nonce
    *@param sEchoStr: 随机串，对应URL参数的echostr
    *@param sReplyEchoStr: 解密之后的echostr，当return返回0时有效
    *@return：成功0，失败返回对应的错误码
	*/
	public function VerifyURL($sMsgSignature, $sTimeStamp, $sNonce, $sEchoStr, &$sReplyEchoStr)
	{
		if (strlen(BIZ_AESKEY) != 43) {
			return ErrorCode::$IllegalAesKey;
		}

		$pc = new Prpcrypt(BIZ_AESKEY);

		// log_message('debug','==== IN WXBIZ LIbrary ====');
		// log_message('debug','GET sMsgSignature '.$sMsgSignature);
		// log_message('debug','GET sTimeStamp '.$sTimeStamp);
		// log_message('debug','GET sNonce '.$sNonce);
		// log_message('debug','GET sEchoStr '.$sEchoStr);
		// log_message('debug','GET sReplyEchoStr '.$sReplyEchoStr);

		// log_message('debug','GET TOKEN '.BIZ_TOKEN);
		// log_message('debug','GET AESKEY '.BIZ_AESKEY);
		
		//verify msg_signature
		$sha1 = new SHA1;
		$array = $sha1->getSHA1(BIZ_TOKEN, $sTimeStamp, $sNonce, $sEchoStr);
		$ret = $array[0];

		if ($ret != 0) {
			return $ret;
		}

		$signature = $array[1];
		// log_message('debug','SHA1 Signature '.$signature);

		if ($signature != $sMsgSignature) {
			return ErrorCode::$ValidateSignatureError;
		}

		$result = $pc->decrypt($sEchoStr, $this->cropid);



		// foreach($result as $k => $r)
		// {
		// 	log_message('debug','GET Decrypt '.$k.' => '.$r);
		// }


		if ($result[0] != 0) {
			return $result[0];
		}
		$sReplyEchoStr = $result[1];

		// log_message('debug','ErrorCode: '.ErrorCode::$OK);

		return ErrorCode::$OK;
	}







	/**
	 * 将公众平台回复用户的消息加密打包.
	 * <ol>
	 *    <li>对要发送的消息进行AES-CBC加密</li>
	 *    <li>生成安全签名</li>
	 *    <li>将消息密文和安全签名打包成xml格式</li>
	 * </ol>
	 *
	 * @param $replyMsg string 公众平台待回复用户的消息，xml格式的字符串
	 * @param $timeStamp string 时间戳，可以自己生成，也可以用URL参数的timestamp
	 * @param $nonce string 随机串，可以自己生成，也可以用URL参数的nonce
	 * @param &$encryptMsg string 加密后的可以直接回复用户的密文，包括msg_signature, timestamp, nonce, encrypt的xml格式的字符串,
	 *                      当return返回0时有效
	 *
	 * @return int 成功0，失败返回对应的错误码
	 */
	public function EncryptMsg($sReplyMsg, $sTimeStamp, $sNonce, &$sEncryptMsg)
	{
		$pc = new Prpcrypt(BIZ_AESKEY);

		//加密
		$array = $pc->encrypt($sReplyMsg, $this->cropid);
		$ret = $array[0];
		if ($ret != 0) {
			return $ret;
		}

		if ($sTimeStamp == null) {
			$sTimeStamp = time();
		}
		$encrypt = $array[1];

		//生成安全签名
		$sha1 = new SHA1;
		$array = $sha1->getSHA1(BIZ_TOKEN, $sTimeStamp, $sNonce, $encrypt);
		$ret = $array[0];
		if ($ret != 0) {
			return $ret;
		}
		$signature = $array[1];

		//生成发送的xml
		$xmlparse = new XMLParse;
		$sEncryptMsg = $xmlparse->generate($encrypt, $signature, $sTimeStamp, $sNonce);
		return ErrorCode::$OK;
	}




	public function getBizAccessToken()
	{
		$url = "https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=".BIZ_CROPID."&corpsecret=".BIZ_SECRET;
		$j = $this->obj->bb_util->curl_get($url);
		log_message('debug',$j);

		$r = json_decode($j, true);

		if(is_array($r))
		{
			// 准备文件
	        write_file(BIZ_ACCESSTOKEN_FILE,'','w');
	        @unlink(BIZ_ACCESSTOKEN_FILE);

	        // 保存access_token
	        write_file(BIZ_ACCESSTOKEN_FILE,$j,'w');

	        log_message('debug', '===> getBizAccessToken OK :'.$r['access_token']);

			return $r['access_token'];

		}else{
			log_message('debug', '===> getBizAccessToken ERROR :'.$r);

			return $r['errcode'];
		}
	}



    public function readBizAccessToken()
    {
        $token = read_file(BIZ_ACCESSTOKEN_FILE);
        $token = json_decode($token,true);

        log_message('debug', '===> READ TOKEN:'.$token["access_token"]);

        return $token["access_token"];
    }


	/**
	 * 检验消息的真实性，并且获取解密后的明文.
	 * <ol>
	 *    <li>利用收到的密文生成安全签名，进行签名验证</li>
	 *    <li>若验证通过，则提取xml中的加密消息</li>
	 *    <li>对消息进行解密</li>
	 * </ol>
	 *
	 * @param $msgSignature string 签名串，对应URL参数的msg_signature
	 * @param $timestamp string 时间戳 对应URL参数的timestamp
	 * @param $nonce string 随机串，对应URL参数的nonce
	 * @param $postData string 密文，对应POST请求的数据
	 * @param &$msg string 解密后的原文，当return返回0时有效
	 *
	 * @return int 成功0，失败返回对应的错误码
	 */
	public function DecryptMsg($sMsgSignature, $sTimeStamp = null, $sNonce, $sPostData, &$sMsg)
	{
		if (strlen(BIZ_AESKEY) != 43) {
			return ErrorCode::$IllegalAesKey;
		}

		$pc = new Prpcrypt(BIZ_AESKEY);

		//提取密文
		$xmlparse = new XMLParse;
		$array = $xmlparse->extract($sPostData);
		$ret = $array[0];

		if ($ret != 0) {
			return $ret;
		}

		if ($sTimeStamp == null) {
			$sTimeStamp = time();
		}

		$encrypt = $array[1];
		$touser_name = $array[2];

		//验证安全签名
		$sha1 = new SHA1;
		$array = $sha1->getSHA1(BIZ_TOKEN, $sTimeStamp, $sNonce, $encrypt);
		$ret = $array[0];

		if ($ret != 0) {
			return $ret;
		}

		$signature = $array[1];
		if ($signature != $sMsgSignature) {
			return ErrorCode::$ValidateSignatureError;
		}

		$result = $pc->decrypt($encrypt, $this->cropid);
		if ($result[0] != 0) {
			return $result[0];
		}
		$sMsg = $result[1];

		return ErrorCode::$OK;
	}




	/**
	 * 发送消息
	 * @param $sendType toUser|totag|toparty
	 * @param $to 接受对象
	 * @param $msgType string 消息类型，此时固定为：text
	 * @param $agentId string 企业应用的id，整型。可在应用的设置页面查看
	 * @param $isSafe string 表示是否是保密消息，0表示否，1表示是，默认0
	 * @param $msgContent string 消息内容
	 *
	 * @return int 成功0，失败返回对应的错误码
	 */
	public function sendMsg($sendType,$to,$msgType,$msgContent,$agentId,$isSafe)
	{
		$access_token = $this->readBizAccessToken();
		$url = "https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=".$access_token;

		$arr = array(
			'msgtype' => 'text',
			'agentid' => $agentId,
			'text'    => array('content' => $msgContent)
			);

		switch ($sendType) {
			case 'touser':
				$arr['touser'] = $to;
				break;
			
			case 'toparty':
				$arr['toparty'] = $to;
				break;

			case 'totag':
				$arr['totag'] = $to;
				break;
		}

		$rt = $this->obj->bb_util->curl_post($url,$arr);
		log_message('debug','==> sendMsg Result:'.$rt);

		return $rt;
	}
}

/* end of file */