<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Esiabridge extends CI_Controller {
	/* Многие пожелания добра [Many best wishes to]:
	*  https://github.com/fr05t1k/esia/blob/master/src/OpenId.php
	*  https://habrahabr.ru/post/276313/
	*
	*  DO: correct a signature check... 08.06.2020 Still yet to do :(
	*/

	function __construct() {
		parent::__construct();
		$this->load->model("logmodel");
		$this->load->model("verifymodel");
		$this->load->model("userdatamodel");
	}

	public $oid          = null;
	public $tlog         = null;
	public $portalUrl    = 'https://esia.gosuslugi.ru/';
	public $logMode      = 'logfile'; //both, none, logfile, screen
	private $accessToken = null;
	private $state       = null;


	/* Cryptografic & hash function wrappers */

	/**
	* Generate state as UUID-formed string
	* 
	* @return string
	*/
	private function getState() {
		return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
			mt_rand(0, 0xffff),
			mt_rand(0, 0xffff),
			mt_rand(0, 0xffff),
			mt_rand(0, 0x0fff) | 0x4000,
			mt_rand(0, 0x3fff) | 0x8000,
			mt_rand(0, 0xffff),
			mt_rand(0, 0xffff),
			mt_rand(0, 0xffff)
		);
	}

	/**
	* Signing a message which
	* will be send in client_secret param
	* 
	* @param string $src
	* @return string
	*/

	private function getSecret($src) {
		$sign				= null;
		$certfile			= $this->config->item("cert_path")."auth.key";
		$path				= $this->config->item("base_server_path").'tickets/';
		$signedFileName		= $path.uniqid(true).'.auth-c7_signature';
		$messageFileName	= $path.uniqid(true).'.auth-c7_message';

		file_put_contents($messageFileName, $src);

		/* uses special bundle openssl 1.1.0e + gost-engine. system calls */

		$signResult = shell_exec("openssl cms -sign -signer ".$certfile." -inkey ".$certfile." -binary -in ".$messageFileName." -outform pem -out ".$signedFileName);

		if ( strlen($signResult) ) {
			$this->logmodel->addToLog("OpenSSL was unable to success with signing\n");
		}
		if ( !file_exists($messageFileName) ) {
			$this->logmodel->addToLog("Crypto Module Error: it was unable to write message file\n");
		}
		if ( !file_exists($signedFileName) ) {
			$this->logmodel->addToLog("Crypto Module Error: it was unable to write signed file\n");
		}

		if ( file_exists($signedFileName) ) {
			/* read PEM, slice the first an the last lines, concatenate and encode to Base64URLSafe */
			$signed = implode( array_slice( explode( "\n", file_get_contents($signedFileName) ), 1, -2 ), ""); 
			$sign   = $this->urlSafe($signed);
			unlink($signedFileName);
		}
		if ( file_exists($messageFileName) ) {
			unlink($messageFileName);
		}
		return $sign;
	}

	/* Parsers */

	/**
	* Prepares string for base64urlSafe-encoding
	* 
	* @param $string string
	* @return string
	*/
	private function urlSafe($string) {
		return rtrim(strtr(trim($string), '+/', '-_'), '=');
	}

	/**
	* Prepares a base64UrlSafe-encoded string and decodes it
	* 
	* @param $string string
	* @return string|false
	*/
	private function base64UrlSafeDecode($string) {
		$base64 = strtr($string, '-_', '+/');
		return base64_decode($base64);
	}

	/*
	* Parses a token for data contained in it
	* 
	* @param $accessToken string
	* @return array
	*/
	private function parseToken($accessToken) {
		$chunks			= explode('.', $accessToken);
		if (sizeof($chunks) == 3) {
			$output = array(
				'header'    => json_decode($this->base64UrlSafeDecode($chunks[0])),
				'payload'   => json_decode($this->base64UrlSafeDecode($chunks[1])),
				'signature' => $chunks[2],
				'hashpart'  => $chunks[0].".".$chunks[1],
			);
			if (file_put_contents($this->config->item("base_server_path").'tickets/signature', $output['signature'])) {
				$this->logmodel->addToLog("Signature has been written to file\n");
			}

			if (file_put_contents($this->config->item("base_server_path").'tickets/hashpart',  $output['hashpart'])) {
				$this->logmodel->addToLog("Hashpart has been written to file\n");
			}

			$this->oid = $output['oid'] = ( isset($output['payload']->{"urn:esia:sbj_id"}) ) ? $output['payload']->{"urn:esia:sbj_id"} : 0;
			return $output;
		}
		return false;
	}

	/*
	* Send a request for 
	* 
	* @param $accessToken string
	* @return array
	*/
	private function sendTokenRequest($request) {
		$options = array(
			'http' => array(
				'content' => http_build_query($request),
				'header'  => 'Content-type: application/x-www-form-urlencoded',
				'method'  => 'POST'
			)
		);
		$context  = stream_context_create($options);
		$result   = file_get_contents($this->userdatamodel->getURL('token'), false, $context);
		$result   = json_decode($result);
		if (!$result) {
			$this->logmodel->addToLog("Request failed. Server returned nothing useful.\n\n\n");
			return false;
		}
		return $result;
	}

	/**
	* Return an URL we redirect user to.
	* OR
	* Return a Codeigniter View with a link
	* 
	* @param $cSystemID int
	* @param $objectID int
	* @return string|false
	*/
	private function requestAuthCode($cSystemID = 0, $objectID = "c15aa69b-b10e-46de-b124-85dbd0a9f4c9") {
		// Извлечение конфигурации запроса к ЕСИА и критериев фильтрации
		$connectedSystems   = $this->config->item('CS');
		$this->logmodel->addToLog( "AuthCode request by ".$cSystemID.".\n" );
		if (!isset($connectedSystems[$cSystemID])) {
			$this->logmodel->addToLog( "No return URL found by specified index while initializing AuthCodeRequest. Check config.\n" );
			$this->logmodel->writeLog("esia_authcode.log");
			return false;
		}
		$this->scope        = implode($connectedSystems[$cSystemID]['scopes'], " ");
		$this->logmodel->addToLog( "AuthCode request by ".$cSystemID." scopes: ".$this->scope." ".print_r($connectedSystems[$cSystemID]['scopes'], true).".\n" );
		// (Методические рекомендации по использованию ЕСИА v 2.23, В.6.2.1 Стандартный режим запроса авторизационного кода)
		$timestamp          = date('Y.m.d H:i:s O');
		$this->state        = $this->getState();
		$requestParams      = array(
			'client_id'		=> $this->config->item("IS_MNEMONICS"),
			'cid'			=> $this->config->item("IS_MNEMONICS"),
			'rurl'			=> "http://auth.arhcity.ru/redirect",
			'client_secret'	=> $this->getSecret($this->scope.$timestamp.$this->config->item("IS_MNEMONICS").$this->state),
			'redirect_uri'	=> $this->config->item("base_url").'esiabridge/token/'.$this->state."/".$cSystemID.'/'.$objectID,
			'scope'			=> $this->scope,
			'response_type'	=> 'code',
			'state'			=> $this->state,
			'timestamp'		=> $timestamp,
			'access_type'	=> 'online'
		);
		$options = array(
			'url'           => $this->userdatamodel->getURL('code'),
			'get_params'    => http_build_query($requestParams)
		);
		$this->logmodel->addToLog("Параметры запроса:\n".print_r($requestParams, true)."\n");
		$this->logmodel->addToLog("Содержимое ссылки на получение кода от ".$timestamp.":\n\"".$options['get_params']."\n");
		$this->logmodel->writeLog("esia_authcode.log");
		
		// return http_build_query($requestParams);
		// OR
		// in case we use Codeigniter
		// return to Codeigniter View
		//return $this->load->view('esia/auth', $options, true);
		return $options['url'].$options['get_params'];
	}

	/**
	* Return an object containing an access token
	* 
	* @return object|false
	*/
	private function getESIAToken($scope) {
		$timestamp   = date('Y.m.d H:i:s O');
		$this->state = $this->getState();
		$returnURL   = $this->config->item("base_url").'esiabridge/token';
		$secret      = $this->getSecret($scope.$timestamp.$this->config->item("IS_MNEMONICS").$this->state);
		
		$request   = array(
			'client_id'		=> $this->config->item("IS_MNEMONICS"),
			'code'			=> $this->input->get('code'),
			'grant_type'	=> 'authorization_code',
			'client_secret' => $secret,
			'state'			=> $this->state,
			'redirect_uri'	=> $returnURL,
			'scope'			=> $scope,
			'timestamp'		=> $timestamp,
			'token_type'	=> 'Bearer'
		);
		$this->logmodel->addToLog("REQUESTING TOKEN for scope ".$scope."\nToken request @".$timestamp.":\n".print_r($request, true)."------------------\n");
		return $this->sendTokenRequest($request);
	}
	/**
	* Sets an access token depending on profile
	* 
	* @return true|false
	*/
	private function setToken($scopes) {
		/* retrieving access token */
		// досточно получить 1 токен. В нём уже прописаны все scopes взятые из авторизационного кода.
		$result = $this->getESIAToken( $scopes[0] );
		$this->logmodel->addToLog("Request was sent successfully. Server returned:\n".print_r($result, true));
		$this->accessToken = $result->access_token;
		$this->logmodel->addToLog('$this->accessToken set:'."\n------------------\n".print_r($this->accessToken, true)."\n------------------\n");
		/* for checks */
		$parsedToken = $this->parseToken($this->accessToken);
		$this->logmodel->addToLog("------------------ Parsed Access Token ------------------\n".print_r($parsedToken, true)."\n------------------\n\n\n\n");

		if ($this->accessToken) {
			return true;
		}
		return false;
	}

	/**
	* Send a callback to a client system with authentication result
	* 
	* @return string|false
	*/

	private function preSendCheck ($cSystemID) {
		$connectedSystems = $this->config->item('CS');
		if ( !$this->config->item('system_online') ){
			$this->logmodel->addToLog( "System is now offline! Check config.\n" );
			return false;
		}

		if ( !isset($connectedSystems[$cSystemID]) ) {
			$this->logmodel->addToLog( "No return URL found by specified index while sending callback. Check config.\n" );
			return false;
		}
		return true;
	}

	private function sendCallbackToClient($cSystemID, $backRequest) {
		if ( !$this->preSendCheck($cSystemID) ) {
			$this->logmodel->writeLog();
			return false;
		}

		$connectedSystems = $this->config->item('CS');
		$url              = $connectedSystems[$cSystemID]['returnURL'];

		$options = array(
			'http' => array(
				'content' => http_build_query($backRequest),
				'header'  => 'Content-type: application/x-www-form-urlencoded',
				'method'  => 'POST'
			)
		);
		$context  = stream_context_create($options);
		$result   = file_get_contents($url, false, $context);
		$location = false;
		foreach ( $http_response_header as $header ) {
			if ( preg_match("/Location:(.*)/i", $header, $matches) ) {
				$location = trim($matches[1]);
			}
		}
		if ($result === FALSE) {
			$this->logmodel->addToLog( "Callback request to ".$url." failed! Check config.\n" );
			$this->logmodel->writeLog();
			return false;
		}
		return $location;
	}

	/* MAIN SECTION GETTER*/

	public function index () {
		header("Location: https://www.arhcity.ru");
		return false;
	}

	private function checkClientSystem() {
		$connectedSystems = $this->config->item('CS');
		if ( isset($connectedSystems[$this->input->post("systemID")]) ) {
			return true;
		}
		$this->logmodel->addToLog("System ID: ".$this->input->post("systemID")." not found\n");
		$this->logmodel->writeLog("esia_ticket.log");
		return false;
	}

	private function writeTicket($data) {
		$ticketPath = $this->config->item("base_server_path")."tickets/".$this->input->post("ticket");
		if ( file_put_contents($ticketPath, json_encode($data)) === FALSE ) {
			$this->logmodel->addToLog("A ticket file could not be written. Possibly, bad data or directiry is RO\n");
			$this->logmodel->writeLog("esia_ticket.log");
			return false;
		}
		return true;
	}

	private function parseTicketData() {
		$data = json_decode($this->input->post("data"));
		if ( !$data ) {
			$this->logmodel->addToLog("Search pattern could not be parsed as valid JSON\n");
			$this->logmodel->writeLog("esia_ticket.log");
			return false;
		}
		return $data;
	}

	public function processticket() {
		if (   !$this->input->post("ticket")         || !$this->input->post("data")         || !$this->input->post("systemID")
			|| !strlen($this->input->post("ticket")) || !strlen($this->input->post("data")) || !strlen($this->input->post("systemID"))
		) {
			$this->logmodel->addToLog("At least one of an essential fields: POST['data'] or POST['ticket'] or POST['systemID'] is missing or empty\n");
			$this->logmodel->writeLog("esia_ticket.log");
			return false;
		}
		$this->logmodel->addToLog("Fields OK. Processing...\n");

		if ( !$this->checkClientSystem() ) {
			return false;
		}
		$ticketData = $this->parseTicketData();
		if ( !$ticketData || !$this->writeTicket($ticketData) ) {
			return false;
		}
		$this->logmodel->addToLog("A ticket was processed succesfully\n");
		print $this->requestAuthCode( $this->input->post("systemID"), $this->input->post("ticket"));
		$this->logmodel->addToLog("Request Auth Code has passed\n");
		$this->logmodel->writeLog("esia_ticket.log");
		return true;
	}

	private function newUserDataObject() {
		return array(
			'oid'			=> $this->oid,
			'trusted'		=> $this->userdatamodel->trusted,
			'fullname'		=> $this->userdatamodel->fullname,
			'birthplace'	=> $this->userdatamodel->birthplace,
			'cellphone'		=> $this->userdatamodel->cellPhone,
			'email'			=> $this->userdatamodel->email,
			'inn'			=> $this->userdatamodel->inn,
			'prg'			=> array(
				'region'	=> $this->userdatamodel->regRegion,
				'city'		=> $this->userdatamodel->regCity,
				'street'	=> $this->userdatamodel->regStreet,
				'house'		=> $this->userdatamodel->regHouse,
				'frame'		=> $this->userdatamodel->regFrame,
				'flat'		=> $this->userdatamodel->regFlat,
				'fias'		=> $this->userdatamodel->regFias
			),
			'plv'			=> array(
				'region'	=> $this->userdatamodel->plvRegion,
				'city'		=> $this->userdatamodel->plvCity,
				'street'	=> $this->userdatamodel->plvStreet,
				'house'		=> $this->userdatamodel->plvHouse,
				'frame'		=> $this->userdatamodel->plvFrame,
				'flat'		=> $this->userdatamodel->plvFlat,
				'fias'		=> $this->userdatamodel->plvFias
			)
		);
	}

	private function userDeniedAccess($cSystemID, $objectID) {
		if ( $this->input->get('error') ) {
			$errorRequest = array(
				'ticket'      => $objectID,
				'error'       => $this->input->get('error'),
				'description' => $this->input->get('error_description')
			);
			$this->logmodel->addToLog( "USER DENIED ACCESS" );
			$this->sendCallbackToClient($cSystemID, $errorRequest);
			$this->logmodel->writeLog();
			return false;
		}
	}

	/**
	* Calls a function requesting User Data
	*
	* @param $state string
	* @param $cSystemID string
	* @param $objectID int
	* @return true|false
	*/
	
	private function tokenCheckResult() {
		$connectedSystems = $this->config->item("CS");
		if ( !$this->verifymodel->verifyState($state) || $this->userDeniedAccess($cSystemID, $objectID) ) {
			$this->load->helper("url");
			redirect(strstr($connectedSystems[$cSystemID]['returnURL'],"&",TRUE));
			return false;
		}
		return true
	}

	private function processUserdata($config, $objectID) {
		/* performing all requests */
		foreach ($config["requests"] as $request) {
			$this->userdatamodel->requestUserData($this->accessToken, $request);
		}
		$userdata     = $this->newUserDataObject();
		$this->logmodel->addToLog( "\n------------------\nUSER DATA SET:\n".print_r($userdata, true)."\n" );
		$sendData     = array();
		if ($config['profile'] === "fullname") {
			$sendData = $userdata['fullname'];
		}
		if ($config['profile'] === "fulldata") {
			$sendData = $userdata;
		}
		$backRequest  = array(
			'oid'     => $userdata['oid'],
			'ticket'  => $objectID,
			'data'    => json_encode($sendData),
			'valid'   => $this->userdatamodel->processUserMatching($userdata, $objectID, $config['profile']),
			'trusted' => $userdata['trusted']
		);
		$this->sendCallbackToClient($cSystemID, $backRequest);
		return true;
	}

	public function token($state = "", $cSystemID = 0, $objectID = 0 ) {
		if ( !$this->tokenCheckResult() ) {
			return false;
		}

		if ( strlen($this->input->get('code')) ) {
			$connectedSystems = $this->config->item('CS');
			if (!isset($connectedSystems[$cSystemID])) {
				$this->logmodel->addToLog( "\nClient System not found in config!\n" );
				return false;
			}

			$config = $connectedSystems[$cSystemID];
			$this->load->helper('url');

			if ( $this->setToken($config['scopes']) ) {
				$this->processUserdata($config, $objectID);
				$this->logmodel->addToLog( "\nCOMPLETED SUCCESSFULLY!\n" );
				$this->logmodel->writeLog();

				if ($config['profile'] === "cisco") {
					redirect($connectedSystems[$cSystemID]['returnURL']."/".$userdata['oid']."/".$objectID);
					return true;
				}
				redirect($connectedSystems[$cSystemID]['returnURL']);
				return true;
			}

			$this->logmodel->addToLog( "\nIT WAS UNABLE TO GET EVEN A SINGLE TOKEN!\n" );
			$this->logmodel->writeLog();
		}
		$this->logmodel->addToLog( "Authorization Code was not provided" );
		$this->logmodel->writeLog();
		return false;
	}
}
?>