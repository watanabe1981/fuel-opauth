<?php
// 仕様
// APIエンドポイント
// https://api.freee.co.jp/ (httpsのみ)

// 認証
// OAuth2に対応
/**
 * Freee strategy for Opauth
 * based on https://secure.freee.co.jp/developers/api/doc?_ga=1.17149881.1424921122.1487874207
 *
 * More information on Opauth: http://opauth.org
 *
 * @copyright    Copyright © 2017 Isamu Watanabe (http://www.developpers.info)
 * @link         http://www.developpers.info
 * @package      Opauth.FreeStrategy
 * @license      MIT License
 */
 namespace Opauth;

class FreeeStrategy extends OpauthStrategy
{
  const VERSION       = '1.0';

  const API_ENDPOINT  = 'https://api.freee.co.jp';

  const AUTHORIZE_URL = 'https://secure.freee.co.jp/oauth/authorize';
  const TOKEN_URL     = '/oauth/token';
  const USER_INFO_URL = '/api/1/users/me';

  // 勘定科目
  const ACCOUNT_ITEMS_URL = '/api/1/account_items.json';

  // 連携サービス
  const BANKS_URL = '/api/1/banks.json';

  // 事業所
  const COMPANIES_URL = '/api/1/companies.json';



  /**
   * Compulsory config keys, listed as unassociative arrays
   * eg. ['app_id', 'app_secret');
   */
  public $expects = ['app_id', 'app_secret'];

  /**
   * Optional config keys with respective default values, listed as associative arrays
   * eg. ['scope' => 'email');
   */
  public $defaults = [
	'redirect_uri' => '{complete_url_to_strategy}int_callback'
  ];

  /**
   * Auth request
   */
  public function request()
  {
	$url = static::AUTHORIZE_URL;

	$params = [
	  'client_id'     => $this->strategy['app_id'],
	  'redirect_uri'  => $this->strategy['redirect_uri'],
	  'response_type' => 'code'
	];

	if (!empty($this->strategy['scope']))
    {
	  $params['scope'] = $this->strategy['scope'];
    }
	if (!empty($this->strategy['response_type']))
    {
	  $params['response_type'] = $this->strategy['response_type'];
    }

	// redirect to generated url
	$this->clientGet($url, $params);
  }

  /**
   * Internal callback, after Free's OAuth
   */
  public function int_callback()
  {
	if (array_key_exists('code', $_GET) && !empty($_GET['code']))
	{
	  $url = static::API_ENDPOINT.static::TOKEN_URL;

	  $params = [
		'client_id'     => $this->strategy['app_id'],
		'client_secret' => $this->strategy['app_secret'],
		'redirect_uri'  => $this->strategy['redirect_uri'],
		'grant_type'    => 'authorization_code',
		'code'          => trim($_GET['code'])
	  ];
	  $response = $this->serverPost($url, $params, null, $headers);

	  $results = json_decode($response);
	  if (!empty($results) && !empty($results->access_token))
	  {
		$userinfo = $this->userinfo($results->access_token);

		$this->auth = [
		  'provider' => 'Freee',
            'uid'  => $userinfo->email,
            'info' => [
                'name'            => $userinfo->display_name,
                'email'           => $userinfo->email,
                'first_name'      => $userinfo->first_name,
                'last_name'       => $userinfo->last_name,
                'first_name_kana' => $userinfo->first_name_kana,
                'last_name_kana'  => $userinfo->last_name_kana,
                'companies'       => $userinfo->companies,
		      ],
		  'credentials' => [
			'token'     => $results->access_token,
			'expires'   => date('c', time() + 60 * 10)
		  ],
		  'raw'         => $userinfo
		];

		/**
		 * NOTE:
		 * Freee's access_token have no explicit expiry, however, please do not assume your
		 * access_token is valid forever.
		 *
		 * Missing optional info values
		 * - email
		 */

		$this->callback();
	  }
	  else
      {
		$error = [
            'provider' => 'Freee',
            'code'     => 'access_token_error',
            'message'  => 'Failed when attempting to obtain access token',
            'raw'      => [
	            'response' => $userinfo,
	            'headers'  => $headers
			]
		];

		$this->errorCallback($error);
	  }
	}
	else{
	  $error = [
        'provider' => 'Freee',
        'code'     => $_GET['error'],
        'reason'   => $_GET['error_reason'],
        'message'  => $_GET['error_description'],
        'raw'      => $_GET
	  ];

	  $this->errorCallback($error);
	}
  }

  /**
   * Queries Free API for user info
   *
   * @param integer $uid
   * @param string  $access_token
   * @return  array Parsed JSON results
   */
  private function userinfo($access_token)
  {
    $params = [
        'access_token' => $access_token,
        'companies'    => true,
    ];

	$userinfo = $this->serverGet(static::API_ENDPOINT.static::USER_INFO_URL, $params, null, $headers);

	if (!empty($userinfo))
	{
	  $results = json_decode($userinfo);
	  return $results->user;
	}
	else
	{
	  $error = [
        'provider'     => 'Freee',
        'code'         => 'userinfo_error',
        'message'      => 'Failed when attempting to query for user information',
        'raw'          => [
            'response' => $userinfo,
            'headers'  => $headers
		]
	  ];

		$this->errorCallback($error);
	}
  }
}
?>