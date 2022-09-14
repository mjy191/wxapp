<?php
namespace Mjy191\Wxapp;

use App\Exceptions\ApiException;
use Illuminate\Support\Facades\Redis;
use Mjy191\Enum\Enum;
use Mjy191\MyCurl\MyCurl;
use Mjy191\Tools\Tools;

class Wxapp {
    private $APPID;
    private $APPSECRET;
    private $tokeName;

    public function __construct()
    {
        // 小程序appId
        $this->APPID = config('wx.appAPPID');
        // 小程序secret
        $this->APPSECRET = config('wx.appSECRET');
        // 小程序access_token redis保存的key
        $this->tokeName = config('wx.appTokenName');
    }

    /**
     * 微信小程序code换取openid
     * @param $code
     * @return mixed
     * @throws ApiException
     */
    public function getOpenid($code)
    {
        $url = "https://api.weixin.qq.com/sns/jscode2session?appid={$this->APPID}&secret={$this->APPSECRET}&js_code={$code}&grant_type=authorization_code";
        $res = MyCurl::send($url);
        $res = json_decode($res, true);
        if (!isset($res['openid'])) {
            throw new ApiException('获取openid错误或code错误', Enum::erCodeSystem);
        }
        if (!isset($res['session_key'])) {
            throw new ApiException('获取openid错误session_key不存在', Enum::erCodeSystem);
        }
        return $res;
    }

    /**
     * 生产小程序码
     * @param $param
     * @return mixed
     * @throws ApiException
     */
    public function getwxacodeunlimit($param)
    {
        $url = "https://api.weixin.qq.com/wxa/getwxacodeunlimit?access_token=" . $this->getAccessToken();
        $data = Tools::issetNewData(['scene', 'page', 'width', 'autoColor', 'lineColor', 'isHyaline'], is_array($param) ? $param : $param->post());
        // 不记得返回日志，图片太大占用log日志
        $res = MyCurl::send($url, 'post', json_encode($data, JSON_UNESCAPED_UNICODE), ['Content-Type: application/json'], true, false, true);
        //{"errcode":40001,"errmsg":"invalid credential, access_token is invalid or not latest rid: 63021398-4f265650-6e8"} token过期
        $response = json_decode($res, true);
        if (isset($response['errcode'])) {
            if ($response['errcode'] == '40001') {
                $this->delAccessToken();
            }
            throw new ApiException('生产二维码错误,请刷新', Enum::erCodeSystem);
        }
        return $res;
    }

    /**
     * 获取微信小程序access_token
     * @return mixed
     * @throws ApiException
     */
    public function getAccessToken()
    {

        if ($token = Redis::get($this->tokeName)) {
            return $token;
        }
        $url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={$this->APPID}&secret={$this->APPSECRET}";
        $res = MyCurl::send($url);
        $res = json_decode($res, true);
        if (isset($res['access_token']) && isset($res['expires_in'])) {
            Redis::set($this->tokeName, $res['access_token']);
            Redis::expire($this->tokeName, 7000);
            return $res['access_token'];
        }
        throw new ApiException('获取access token错误', Enum::erCodeSystem);
    }

    public function delAccessToken()
    {
        Redis::del($this->tokeName);
    }

    /**
     * 检验数据的真实性，并且获取解密后的明文.
     * @param $encryptedData string 加密的用户数据
     * @param $iv string 与用户数据一同返回的初始向量
     * @param $data string 解密后的原文
     *
     * @return int 成功0，失败返回对应的错误码
     */
    public function decryptData($encryptedData, $iv, $sessionKey)
    {
        if (strlen($sessionKey) != 24) {
            throw new ApiException('sessionKey错误', Enum::decryptPhoneError);
        }
        $aesKey = base64_decode($sessionKey);

        if (strlen($iv) != 24) {
            throw new ApiException('iv错误', Enum::decryptPhoneError);
        }
        $aesIV = base64_decode($iv);

        $aesCipher = base64_decode($encryptedData);

        $result = openssl_decrypt($aesCipher, "AES-128-CBC", $aesKey, 1, $aesIV);

        $dataObj = json_decode($result, true);
        if ($dataObj == NULL) {
            throw new ApiException(Enum::msg[Enum::decryptPhoneError], Enum::decryptPhoneError);
        }
        if ($dataObj['watermark']['appid'] != $this->APPID) {
            throw new ApiException(Enum::msg[Enum::decryptPhoneError], Enum::decryptPhoneError);
        }
        return $dataObj;
    }
}
