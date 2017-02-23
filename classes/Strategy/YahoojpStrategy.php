<?php
/**
 * Yahoojp(YConnect) strategy for Opauth
 * based on http://developer.yahoo.co.jp/yconnect/
 *
 * More information on Opauth: http://opauth.org
 *
 * @copyright    Copyright © 2012 Ryo Ito (https://github.com/ritou)
 * @link         http://opauth.org
 * @package      Opauth.YahoojpStrategy
 * @license      MIT License
 */

/**
 * Yahoojp(YConnect) strategy for Opauth
 * based on http://developer.yahoo.co.jp/yconnect/
 *
 * @package			Opauth.Yahoojp
 */
namespace Opauth;

class YahoojpStrategy extends OpauthStrategy{

	/**
	 * \brief Authorization Endpoint
	 */
	const AUTHORIZATION_URL = "https://auth.login.yahoo.co.jp/yconnect/v1/authorization";

	/**
	 * \brief Token Endpoint
	 */
	const TOKEN_URL = "https://auth.login.yahoo.co.jp/yconnect/v1/token";

	/**
	 * \brief UserInfo Endpoint
	 */
	const USERINFO_URL = "https://userinfo.yahooapis.jp/yconnect/v1/attribute";

	/**
	 * Compulsory config keys, listed as unassociative arrays
	 */
	public $expects = array('client_id', 'client_secret');

	/**
	 * Optional config keys, without predefining any default values.
	 */
	public $optionals = array('redirect_uri', 'scope', 'state');

	/**
	 * Optional config keys with respective default values, listed as associative arrays
	 * eg. array('scope' => 'email');
	 */
	public $defaults = array(
		'redirect_uri' => '{complete_url_to_strategy}oauth2callback',
		'scope' => 'openid profile email address'
	);

	/**
	 * Auth request
	 */
	public function request(){
		$url = static::AUTHORIZATION_URL;
		$params = array(
			'client_id' => $this->strategy['client_id'],
			'redirect_uri' => $this->strategy['redirect_uri'],
			'response_type' => 'code',
			'scope' => $this->strategy['scope']
		);

		foreach ($this->optionals as $key){
			if (!empty($this->strategy[$key])) $params[$key] = $this->strategy[$key];
		}

		$this->clientGet($url, $params);
	}

	/**
	 * Internal callback, after OAuth
	 */
	public function oauth2callback(){
		if (array_key_exists('code', $_GET) && !empty($_GET['code'])){
			$code = $_GET['code'];
			$url = static::TOKEN_URL;

			$params = array(
				'grant_type' => 'authorization_code',
				'code' => $code,
				'redirect_uri' => $this->strategy['redirect_uri'],
			);

			$http_client = new HttpClient();
			$http_client->setHeader([
				'Content-Type: multipart/form-data; charset=utf-8',
				'Expect:', // POST HTTP 100-continue 無効
				'Authorization: Basic '.base64_encode($this->strategy['client_id'] . ':' . $this->strategy['client_secret'])
			]);

			$http_client->requestPost( $url, $params );

			$response = $http_client->getResponseBody();
			$results  = json_decode($response);

			if (!empty($results) && !empty($results->access_token)){
				$userinfo = $this->userinfo($results->access_token);
				$this->auth = array(
					'provider' => 'Yahoojp',
					'uid' => $userinfo->user_id,
					'info' => array(
						'name' => $userinfo->name,
						'email' => $userinfo->email,
						'email_verified' => $userinfo->email_verified
					),
					'credentials' => array(
						'token' => $results->access_token,
						'expires' => date('c', time() + $results->expires_in)
					),
					'raw' => $userinfo
				);

				$this->callback();
			}
			else{
				$error = array(
					'provider' => 'Yahoojp',
					'code' => 'access_token_error',
					'message' => 'Failed when attempting to obtain access token',
					'raw' => array(
						'response' => $response,
						'headers' => $headers
					)
				);

				$this->errorCallback($error);
			}
		}
		else{
			$error = array(
				'provider' => 'Yahoojp',
				'code' => 'oauth2callback_error',
				'raw' => $_GET
			);

			$this->errorCallback($error);
		}
	}

	/**
	 * Queries People API for user info
	 *
	 * @param string $access_token
	 * @return array Parsed JSON results
	 */
	private function userinfo($access_token){
		$userinfo = $this->serverGet(static::USERINFO_URL, array('schema' => 'openid', 'access_token' => $access_token), null, $headers);
		if (!empty($userinfo)){
			return json_decode($userinfo);
		}
		else{
			$error = array(
				'provider' => 'Yahoojp',
				'code' => 'userinfo_error',
				'message' => 'Failed when attempting to query for user information',
				'raw' => array(
					'response' => $userinfo,
					'headers' => $headers
				)
			);

			$this->errorCallback($error);
		}
	}
}

class HttpClient
{
	/**
	 * \private \brief curlインスタンス
	 */
	private $ch = null;

	/**
	 * \private \brief SSLチェックフラグ
	 */
	private static $sslCheckFlag = true;

	/**
	 * \private \brief 全レスポンスヘッダ情報
	 */
	private $headers = array();

	/**
	 * \private \brief レスポンスボディ
	 */
	private $body = null;

	/**
	 * \brief Curlインスタンス生成
	 */
	public function __construct()
	{
		$this->ch = curl_init();
		//curl_setopt( $this->ch, CURLOPT_VERBOSE, 1 ); // 詳細情報出力
		//curl_setopt( $this->ch, CURLOPT_FAILONERROR, 1 );	// 400以上でなにもしない
		curl_setopt( $this->ch, CURLOPT_RETURNTRANSFER, true );
		curl_setopt( $this->ch, CURLOPT_HEADER, true );
		\Log::debug( "curl_init(" . get_class() . "::" . __FUNCTION__ . ")" );
	}

	/**
	 * \brief Curlインスタンス削除
	 */
	public function __destruct()
	{
		if( $this->ch != null ) {
			curl_close( $this->ch );
			$this->ch = null;
			\Log::debug( "curl_closed(" . get_class() . "::" . __FUNCTION__ . ")" );
		}
	}

	/**
	 * \brief SSLチェック解除メソッド
	 */
	public static function disableSSLCheck()
	{
		self::$sslCheckFlag = false;

		\Log::debug( "disable SSL check(" . get_class() . "::" . __FUNCTION__ . ")" );
	}

	/**
	 * \brief ヘッダ設定メソッド
	 * @param	$headers	ヘッダの配列
	 */
	public function setHeader($headers = null)
	{
		if( $headers != null ) {
			curl_setopt( $this->ch, CURLOPT_HTTPHEADER, $headers );
		}

		\Log::debug( "added headers(" . get_class() . "::" . __FUNCTION__ . "): ".print_r($headers,true));
	}

	/**
	 * \brief POSTリクエストメソッド
	 * @param	$url	エンドポイントURL
	 * @param	$data	パラメータ配列
	 */
	public function requestPost($url, $data=null)
	{
		curl_setopt( $this->ch, CURLOPT_URL, $url );
		curl_setopt( $this->ch, CURLOPT_POST, 1 );
		curl_setopt( $this->ch, CURLOPT_POSTFIELDS, $data );
		\Log::info( "curl url(" . get_class() . "::" . __FUNCTION__ . "): ".$url );

		if( !self::$sslCheckFlag ) {
			curl_setopt( $this->ch, CURLOPT_SSL_VERIFYPEER, false );
			curl_setopt( $this->ch, CURLOPT_SSL_VERIFYHOST, false );
		}

		$result = curl_exec( $this->ch );
		$info   = curl_getinfo( $this->ch );

		if( !$result ) {
			\Log::error( "failed curl_exec(" . get_class() . "::" . __FUNCTION__ . ")" );
			\Log::error( "curl_errno: " . curl_errno( $this->ch ) );
			throw new \Exception( "failed curl_exec." );
		}

		$this->extractResponse( $result, $info );

		\Log::info( "curl_exec(" . get_class() . "::" . __FUNCTION__ . "): ".print_r($data, true));
		\Log::debug( "response body(" . get_class() . "::" . __FUNCTION__ . "): ".print_r($result, true));
	}

	/**
	 * \brief GETリクエストメソッド
	 * @param	$url	エンドポイントURL
	 * @param	$data	パラメータ配列
	 */
	public function requestGet($url, $data=null)
	{
		if( $data != null ) {
			$query = http_build_query( $data );
			$parse = parse_url( $url );
			if( !empty( $parse["query"] ) ) {
				$url .= '&' . $query;
			} else {
				$url .= '?' . $query;
			}
		}

		curl_setopt( $this->ch, CURLOPT_URL, $url );
		\Log::info( "curl url(" . get_class() . "::" . __FUNCTION__ . "): ".$url );

		if( !self::$sslCheckFlag ) {
			curl_setopt( $this->ch, CURLOPT_SSL_VERIFYPEER, false );
			curl_setopt( $this->ch, CURLOPT_SSL_VERIFYHOST, false );
		}

		$result = curl_exec( $this->ch );
		$info   = curl_getinfo( $this->ch );

		if( !$result ) {
			\Log::error( "failed curl_exec(" . get_class() . "::" . __FUNCTION__ . ")" );
			\Log::error( "curl_errno: " . curl_errno( $this->ch ) );
			throw new \Exception( "failed curl_exec." );
		}

		$this->extractResponse( $result, $info );

		\Log::info( "curl_exec(" . get_class() . "::" . __FUNCTION__ . "): ".print_r($data, true));
		\Log::debug( "response body(" . get_class() . "::" . __FUNCTION__ . "): ".print_r($result, true));
	}

	/**
	 * \brief PUTリクエストメソッド
	 * @param	$url	エンドポイントURL
	 * @param	$data	パラメータ配列
	 */
	public function requestPut($url, $data=null)
	{
		curl_setopt( $this->ch, CURLOPT_URL, $url );
		curl_setopt( $this->ch, CURLOPT_CUSTOMREQUEST, "PUT" );
		curl_setopt( $this->ch, CURLOPT_POSTFIELDS, $data );

		\Log::info( "curl url(" . get_class() . "::" . __FUNCTION__ . "): ".$url );

		if( !self::$sslCheckFlag ) {
			curl_setopt( $this->ch, CURLOPT_SSL_VERIFYPEER, false );
			curl_setopt( $this->ch, CURLOPT_SSL_VERIFYHOST, false );
		}

		$result = curl_exec( $this->ch );
		$info   = curl_getinfo( $this->ch );

		if( !$result ) {
			\Log::error( "failed curl_exec(" . get_class() . "::" . __FUNCTION__ . ")" );
			\Log::error( "curl_errno: " . curl_errno( $this->ch ) );
			throw new \Exception( "failed curl_exec." );
		}

		$this->extractResponse( $result, $info );

		\Log::info( "curl_exec(" . get_class() . "::" . __FUNCTION__ . "): ".print_r($data, true));
		\Log::debug( "response body(" . get_class() . "::" . __FUNCTION__ . "): ".print_r($result, true));
	}

	/**
	 * \brief DELETEリクエストメソッド
	 * @param	$url	エンドポイントURL
	 * @param	$data	パラメータ配列
	 */
	public function requestDelete($url, $data=null)
	{
		curl_setopt( $this->ch, CURLOPT_URL, $url );
		curl_setopt( $this->ch, CURLOPT_CUSTOMREQUEST, "DELETE" );
		curl_setopt( $this->ch, CURLOPT_POSTFIELDS, $data );
		\Log::info( "curl url(" . get_class() . "::" . __FUNCTION__ . "): ".$url );

		if( !self::$sslCheckFlag ) {
			curl_setopt( $this->ch, CURLOPT_SSL_VERIFYPEER, false );
			curl_setopt( $this->ch, CURLOPT_SSL_VERIFYHOST, false );
		}

		$result = curl_exec( $this->ch );
		$info   = curl_getinfo( $this->ch );

		if( !$result ) {
			\Log::error( "failed curl_exec(" . get_class() . "::" . __FUNCTION__ . ")" );
			\Log::error( "curl_errno: " . curl_errno( $this->ch ) );
			throw new \Exception( "failed curl_exec." );
		}

		$this->extractResponse( $result, $info );

		\Log::info( "curl_exec(" . get_class() . "::" . __FUNCTION__ . "): ".print_r($data, true));
		\Log::debug( "response body(" . get_class() . "::" . __FUNCTION__ . "): ".print_r($result, true));
	}

	/**
	 * \brief 全レスポンスヘッダ取得メソッド
	 */
	public function getResponseHeaders()
	{
		if( $this->headers != null ) {
			return $this->headers;
		} else {
			return false;
		}
	}

	/**
	 * \brief レスポンスヘッダ取得メソッド
	 * @param	$header_name	ヘッダフィールド
	 */
	public function getResponseHeader($header_name)
	{
		if( array_key_exists( $header_name, $this->headers ) ) {
			return $this->headers[$header_name];
		} else {
			return null;
		}
	}

	/**
	 * \brief レスポンスボディ取得メソッド
	 */
	public function getResponseBody()
	{
		if( $this->body != null ) {
			return $this->body;
		} else {
			return null;
		}
	}

	/**
	 * \brief レスポンス抽出メソッド
	 *
	 * レスポンスをヘッダとボディ別に抽出
	 *
	 * @param	$raw_response	レスポンス文字列
	 */
	private function extractResponse($raw_response, $info)
	{
		// ヘッダとボディを分割
		$headers_raw = substr( $raw_response, 0, $info['header_size'] );
		$headers_raw = preg_replace( "/(\r\n\r\n)$/", "", $headers_raw );
		$body_raw    = substr( $raw_response, $info['header_size'] );

		// ヘッダを連想配列形式に変換
		$headers_raw_array = preg_split( "/\r\n/", $headers_raw );
		$headers_raw_array = array_map( "trim", $headers_raw_array );

		foreach( $headers_raw_array as $header_raw ) {

			if( preg_match( "/HTTP/", $header_raw ) ) {
				$headers_asoc_array[0] = $header_raw;
			} elseif( !empty( $header_raw ) ) {
				$tmp = preg_split( "/: /", $header_raw );
				$field = $tmp[0];
				$value = $tmp[1];
				$headers_asoc_array[$field] = $value;
			}

		}

		$this->headers = $headers_asoc_array;
		$this->body    = $body_raw;

		\Log::debug( "extracted headers(" . get_class() . "::" . __FUNCTION__ . "): ".print_r($this->headers, true));
		\Log::debug( "extracted body(" . get_class() . "::" . __FUNCTION__ . "): ".print_r($this->body, true));
	}
}
