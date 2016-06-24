<?php

namespace App\Helpers\Bnet;

class Client
{
    const AUTH_TYPE_URI                 = 0;
    const AUTH_TYPE_AUTHORIZATION_BASIC = 1;
    const AUTH_TYPE_FORM                = 2;
    const ACCESS_TOKEN_URI      = 0;
    const ACCESS_TOKEN_BEARER   = 1;
    const ACCESS_TOKEN_OAUTH    = 2;
    const ACCESS_TOKEN_MAC      = 3;
    const GRANT_TYPE_AUTH_CODE          = 'authorization_code';
    const GRANT_TYPE_PASSWORD           = 'password';
    const GRANT_TYPE_CLIENT_CREDENTIALS = 'client_id';
    const GRANT_TYPE_REFRESH_TOKEN      = 'refresh_token';
    const HTTP_METHOD_GET    = 'GET';
    const HTTP_METHOD_POST   = 'POST';
    const HTTP_METHOD_PUT    = 'PUT';
    const HTTP_METHOD_DELETE = 'DELETE';
    const HTTP_METHOD_HEAD   = 'HEAD';
    const HTTP_METHOD_PATCH  = 'PATCH';
    const HTTP_FORM_CONTENT_TYPE_APPLICATION = 0;
    const HTTP_FORM_CONTENT_TYPE_MULTIPART = 1;

    protected $client_id = null;
    protected $client_secret = null;
    protected $client_auth = self::AUTH_TYPE_URI;
    protected $access_token = null;
    protected $access_token_type = self::ACCESS_TOKEN_URI;
    protected $access_token_secret = null;
    protected $access_token_algorithm = null;
    protected $access_token_param_name = 'access_token';
    protected $certificate_file = null;
    protected $curl_options = array();
	public $redirect_uri = '';
	public $region = '';
	public $locale = '';
	public $ext;
	public $baseurl = array(

			'US' => array(
				'urlbase'					=> 'https://us.api.battle.net/',
				'AUTHORIZATION_ENDPOINT'	=> 'https://us.battle.net/oauth/authorize',
				'TOKEN_ENDPOINT'			=> 'https://us.battle.net/oauth/token',
			),
			'EU' => array(
				'urlbase'					=> 'https://eu.api.battle.net/',
				'AUTHORIZATION_ENDPOINT'	=> 'https://eu.battle.net/oauth/authorize',
				'TOKEN_ENDPOINT'			=> 'https://eu.battle.net/oauth/token',
			),
			'KR' => array(
				'urlbase'					=> 'https://kr.api.battle.net/',
				'AUTHORIZATION_ENDPOINT'	=> 'https://kr.battle.net/oauth/authorize',
				'TOKEN_ENDPOINT'			=> 'https://kr.battle.net/oauth/token',
			),
			'TW' => array(
				'urlbase'					=> 'https://tw.api.battle.net/',
				'AUTHORIZATION_ENDPOINT'	=> 'https://tw.battle.net/oauth/authorize',
				'TOKEN_ENDPOINT'			=> 'https://tw.battle.net/oauth/token',
			),
			'SEA' => array(
				'urlbase'					=> 'https://sea.api.battle.net/',
				'AUTHORIZATION_ENDPOINT'	=> 'https://sea.battle.net/oauth/authorize',
				'TOKEN_ENDPOINT'			=> 'https://sea.battle.net/oauth/token',
			),
	);

    public function __construct($client_id, $client_secret, $region, $locale, $redirect_uri)
    {
        if (!extension_loaded('curl')) {
            throw new Exception('The PHP exention curl must be installed to use this library.', Exception::CURL_NOT_FOUND);
        }
		
		$client_auth			= self::AUTH_TYPE_URI;
        $this->client_id		= $client_id;
        $this->client_secret	= $client_secret;
		$this->region			= $region;
		$this->locale			= $locale;
        $this->client_auth		= $client_auth;
		$this->redirect_uri		= $redirect_uri;
    }

    public function getClientId()
    {
        return $this->client_id;
    }

    public function getClientSecret()
    {
        return $this->client_secret;
    }

    public function getAuthenticationUrl($auth_endpoint, $redirect_uri, array $extra_parameters = array())
    {
        $parameters = array_merge(array(
            'response_type' => 'code',
            'client_id'     => $this->client_id,
//			'scope'			=> 'wow.profile+sc2.profile',
			'scope'			=> 'wow.profile',
			'auth_flow'		=> 'auth_code',
            'redirect_uri'  => $redirect_uri
        ), $extra_parameters);
        return $auth_endpoint . '?' . http_build_query($parameters, null, '&');
    }

    public function getAccessToken($token_endpoint, $grant_type, array $parameters)
    {
        if (!$grant_type) {
            throw new InvalidArgumentException('The grant_type is mandatory.', InvalidArgumentException::INVALID_GRANT_TYPE);
        }
        $grantTypeClassName = $this->convertToCamelCase($grant_type);
        $grantTypeClass =  __NAMESPACE__ . '\\GrantType\\' . $grantTypeClassName;
        if (!class_exists($grantTypeClass)) {
            throw new InvalidArgumentException('Unknown grant type \'' . $grant_type . '\'', InvalidArgumentException::INVALID_GRANT_TYPE);
        }
        $grantTypeObject = new $grantTypeClass();
        $grantTypeObject->validateParameters($parameters);
        if (!defined($grantTypeClass . '::GRANT_TYPE')) {
            throw new Exception('Unknown constant GRANT_TYPE for class ' . $grantTypeClassName, Exception::GRANT_TYPE_ERROR);
        }
        $parameters['grant_type'] = $grantTypeClass::GRANT_TYPE;
        $http_headers = array();
        switch ($this->client_auth) {
            case self::AUTH_TYPE_URI:
            case self::AUTH_TYPE_FORM:
                $parameters['client_id'] = $this->client_id;
                $parameters['client_secret'] = $this->client_secret;
                break;
            case self::AUTH_TYPE_AUTHORIZATION_BASIC:
                $parameters['client_id'] = $this->client_id;
                $http_headers['Authorization'] = 'Basic ' . base64_encode($this->client_id .  ':' . $this->client_secret);
                break;
            default:
                throw new Exception('Unknown client auth type.', Exception::INVALID_CLIENT_AUTHENTICATION_TYPE);
                break;
        }

        return $this->executeRequest($token_endpoint, $parameters, self::HTTP_METHOD_POST, $http_headers, self::HTTP_FORM_CONTENT_TYPE_APPLICATION);
    }

    public function setAccessToken($token)
    {
        $this->access_token = $token;
    }

    public function setClientAuthType($client_auth)
    {
        $this->client_auth = $client_auth;
    }

    public function setCurlOption($option, $value)
    {
        $this->curl_options[$option] = $value;
    }

    public function setCurlOptions($options) 
    {
        $this->curl_options = array_merge($this->curl_options, $options);
    }

    public function setAccessTokenType($type, $secret = null, $algorithm = null)
    {
        $this->access_token_type = $type;
        $this->access_token_secret = $secret;
        $this->access_token_algorithm = $algorithm;
    }
	
	protected function _buildUrl($path, $params = array())
    {
		$params['apikey'] = $this->client_id;
		if (isset($this->access_token))
		{
			$params['access_token']	= $this->access_token;
		}
		$params['locale'] = $this->locale;

		$url = $this->baseurl[$this->region]['urlbase'];
		$url .= self::_buildtype($path,$params);
		$url .= (count($params)) ? '?' . http_build_query($params) : '';
		return $url;
    }

	public function _buildtype($class,$fields)
	{
		switch ($class)
		{
			case 'achievement':
						$q = 'wow/achievement/'.$fields['id'];
					break;
			case 'auction':
						$q = 'wow/auction/data/'.$fields['server'];
					break;
			case 'abilities':
						$q = 'wow/pet/ability/'.$fields['id'];
					break;
			case 'species':
						$q = 'wow/pet/species/'.$fields['id'];
					break;
			case 'stats':
						$q = 'wow/pet/stats/'.$fields['id'];
					break;
			case 'realm_leaderboard':
						$q = 'wow/challenge/'.$fields['server'];
					break;
			case 'region_leaderboard':
						$q = 'wow/challenge/region';
					break;
			case 'team':
						$q = 'wow/arena/'.$fields['server'].'/'.$fields['size'].'/'.$fields['name'];
					break;
			case 'character':
						$q = 'wow/character/'.$fields['server'].'/'.$fields['name'];
					break;
			case 'item':
						$q = 'wow/item/'.$fields['id'];
					break;
			case 'item_set':
						$q = 'wow/item/set/'.$fields['id'];
					break;
			case 'guild':
						$q = 'wow/guild/'.$fields['server'].'/'.$fields['name'];
					break;
			case 'leaderboards':
						$q = 'wow/leaderboard/'.$fields['size'];
					break;
			case 'quest':
						$q = 'wow/quest/'.$fields['id'];
					break;
			case 'realmstatus':
						$q = 'wow/realm/status';
					break;
			case 'recipe':
						$q = 'wow/recipe/'.$fields['id'];
					break;
			case 'spell':
						$q = 'wow/spell/'.$fields['id'];
					break;
			case 'battlegroups':
						$q = 'wow/data/battlegroups/';
					break;
			case 'races':
						$q = 'wow/data/character/races';
					break;
			case 'classes':
						$q = 'wow/data/character/classes';
					break;
			case 'achievements':
						$q = 'wow/data/character/achievements';
					break;
			case 'guild_rewards':
						$q = 'wow/data/guild/rewards';
					break;
			case 'guild_perks':
						$q = 'wow/data/guild/perks';
					break;
			case 'guild_achievements':
						$q = 'wow/data/guild/achievements';
					break;
			case 'item_classes':
						$q = 'wow/data/item/classes';
					break;
			case 'talents':
						$q = 'wow/data/talents';
					break;
			case 'pet_types':
						$q = 'wow/data/pet/types';
					break;
			case 'pet':
						$q = 'wow/pet/';
					break;
			case 'mount':
						$q = 'wow/mount/';
					break;
			case 'sc2profile':
					if ($this->access_token)
					{
						$q = 'sc2/profile/user';
					}else{
						throw new Exception('Access Token Required for this call.', Exception::MISSING_PARAMETER);
					}
					break;
			case 'wowprofile':
					if ($this->access_token)
					{
						$q = 'wow/user/characters';
					}else{
						throw new Exception('Access Token Required for this call.', Exception::MISSING_PARAMETER);
					}
					break;
			case 'accountid':
					if ($this->access_token)
					{
						$q = 'account/user/id';
					}else{
						throw new Exception('Access Token Required for this call.', Exception::MISSING_PARAMETER);
					}
					break;
			case 'battletag':
					if ($this->access_token)
					{
						$q = 'account/user/battletag';
					}else{
						throw new Exception('Access Token Required for this call.', Exception::MISSING_PARAMETER);
					}
					break;

			default:
			break;
		}
		return $q;
	}
	
    public function fetch($protected_resource_url, $parameters = array(), $http_method = self::HTTP_METHOD_GET, array $http_headers = array(), $form_content_type = self::HTTP_FORM_CONTENT_TYPE_MULTIPART)
    {
		$protected_resource_url = self::_buildUrl($protected_resource_url, $parameters);
	
        if ($this->access_token) {
            switch ($this->access_token_type) {
                case self::ACCESS_TOKEN_URI:
                    if (is_array($parameters)) {
                        $parameters[$this->access_token_param_name] = $this->access_token;
                    } else {
                        throw new InvalidArgumentException(
                            'You need to give parameters as array if you want to give the token within the URI.',
                            InvalidArgumentException::REQUIRE_PARAMS_AS_ARRAY
                        );
                    }
                    break;
                case self::ACCESS_TOKEN_BEARER:
                    $http_headers['Authorization'] = 'Bearer ' . $this->access_token;
                    break;
                case self::ACCESS_TOKEN_OAUTH:
                    $http_headers['Authorization'] = 'OAuth ' . $this->access_token;
                    break;
                case self::ACCESS_TOKEN_MAC:
                    $http_headers['Authorization'] = 'MAC ' . $this->generateMACSignature($protected_resource_url, $parameters, $http_method);
                    break;
                default:
                    throw new Exception('Unknown access token type.', Exception::INVALID_ACCESS_TOKEN_TYPE);
                    break;
            }
        }
        return $this->executeRequest($protected_resource_url, $parameters, $http_method, $http_headers, $form_content_type);
    }

    private function generateMACSignature($url, $parameters, $http_method)
    {
        $timestamp = time();
        $nonce = uniqid();
        $parsed_url = parse_url($url);
        if (!isset($parsed_url['port']))
        {
            $parsed_url['port'] = ($parsed_url['scheme'] == 'https') ? 443 : 80;
        }
        if ($http_method == self::HTTP_METHOD_GET) {
            if (is_array($parameters)) {
                $parsed_url['path'] .= '?' . http_build_query($parameters, null, '&');
            } elseif ($parameters) {
                $parsed_url['path'] .= '?' . $parameters;
            }
        }

        $signature = base64_encode(hash_hmac($this->access_token_algorithm,
                    $timestamp . "\n"
                    . $nonce . "\n"
                    . $http_method . "\n"
                    . $parsed_url['path'] . "\n"
                    . $parsed_url['host'] . "\n"
                    . $parsed_url['port'] . "\n\n"
                    , $this->access_token_secret, true));

        return 'id="' . $this->access_token . '", ts="' . $timestamp . '", nonce="' . $nonce . '", mac="' . $signature . '"';
    }

    private function executeRequest($url, $parameters = array(), $http_method = self::HTTP_METHOD_GET, array $http_headers = null, $form_content_type = self::HTTP_FORM_CONTENT_TYPE_MULTIPART)
    {
        $curl_options = array(
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_CUSTOMREQUEST  => $http_method
        );

        switch($http_method) {
            case self::HTTP_METHOD_POST:
                $curl_options[CURLOPT_POST] = true;
            case self::HTTP_METHOD_PUT:
			case self::HTTP_METHOD_PATCH:
                if(is_array($parameters) && self::HTTP_FORM_CONTENT_TYPE_APPLICATION === $form_content_type) {
                    $parameters = http_build_query($parameters, null, '&');
                }
                $curl_options[CURLOPT_POSTFIELDS] = $parameters;
                break;
            case self::HTTP_METHOD_HEAD:
                $curl_options[CURLOPT_NOBODY] = true;
            case self::HTTP_METHOD_DELETE:
            case self::HTTP_METHOD_GET:
                if (is_array($parameters)) {
                } elseif ($parameters) {
                }
                break;
            default:
                break;
        }

        $curl_options[CURLOPT_URL] = $url;

        if (is_array($http_headers)) {
            $header = array();
            foreach($http_headers as $key => $parsed_urlvalue) {
                $header[] = "$key: $parsed_urlvalue";
            }
            $curl_options[CURLOPT_HTTPHEADER] = $header;
        }

        $ch = curl_init();
        curl_setopt_array($ch, $curl_options);
        if (!empty($this->certificate_file)) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
            curl_setopt($ch, CURLOPT_CAINFO, $this->certificate_file);
        } else {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        }
        if (!empty($this->curl_options)) {
            curl_setopt_array($ch, $this->curl_options);
        }
        $result = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $content_type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        if ($curl_error = curl_error($ch)) {
            throw new Exception($curl_error, Exception::CURL_ERROR);
        } else {
            $json_decode = json_decode($result, true);
        }
        curl_close($ch);

        return array(
            'result' => (null === $json_decode) ? $result : $json_decode,
            'code' => $http_code,
            'content_type' => $content_type
        );
    }

    public function setAccessTokenParamName($name)
    {
        $this->access_token_param_name = $name;
    }

    private function convertToCamelCase($grant_type)
    {
        $parts = explode('_', $grant_type);
        array_walk($parts, function(&$item) { $item = ucfirst($item);});
        return implode('', $parts);
    }
}

class Exception extends \Exception
{
    const CURL_NOT_FOUND                     = 0x01;
    const CURL_ERROR                         = 0x02;
    const GRANT_TYPE_ERROR                   = 0x03;
    const INVALID_CLIENT_AUTHENTICATION_TYPE = 0x04;
    const INVALID_ACCESS_TOKEN_TYPE          = 0x05;
}

class InvalidArgumentException extends \InvalidArgumentException
{
    const INVALID_GRANT_TYPE      = 0x01;
    const CERTIFICATE_NOT_FOUND   = 0x02;
    const REQUIRE_PARAMS_AS_ARRAY = 0x03;
    const MISSING_PARAMETER       = 0x04;
}