<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Verifymodel extends CI_Model {
	function __construct() {
		parent::__construct();
	}

	
	/* VERIFICATION */

	/**
	* Verifies an access token
	* 
	* @param $accessToken array
	* @return true|false
	*/
	public function verifyToken($accessToken) {
		// проверка токена ( Методические рекомендации по использованию ЕСИА v 2.23, Приложение В.6.4)
		$this->logmodel->addToLog("\nTOKEN VERIFICATION\n");
		if ( !$this->verifySignature($accessToken) ) {// ................. check signature !!
			return false;
		}
		if ( !$this->verifyMnemonics($accessToken['payload']) ) {
			return false;
		};
		if ( !$this->verifyExpiration($accessToken['payload']) ) {
			return false;
		};
		if ( !$this->verifyIssuer($accessToken['payload']) ) {
			return false;
		};
		return true;
	}

	/**
	* Verifies a token issuer
	* 
	* @param $accessToken array
	* @return true|false
	*/
	private function verifyIssuer($accessToken) {
		if ($accessToken->iss === "http://esia.gosuslugi.ru/") {
			$this->logmodel->addToLog("TOKEN ISSUER: ".$accessToken->iss." CORRECT!\n");
			return true;
		}
		$this->logmodel->addToLog("\nTOKEN ISSUER FORGED!\n");
		return false;
	}

	/**
	* Verifies a mnemonics sent by ESIA to be a system of ours
	* 
	* @param $accessToken array
	* @return true|false
	*/
	private function verifyMnemonics($accessToken) {
		if ( !isset($accessToken->client_id) || $accessToken->client_id !== $this->config->item("IS_MNEMONICS") ) {
			$this->logmodel->addToLog("Expected mnemonics: ".$this->config->item("IS_MNEMONICS")." - does not match one in access token!\n");
			return false;
		}
		$this->logmodel->addToLog("MNEMONICS: CORRECT\n");
		return true;
	}

	/**
	* Verifies a token sent by ESIA whether it is applicable
	* 
	* @param $accessToken array
	* @return true|false
	*/
	private function verifyExpiration($accessToken) {
		$timeTolerance = 10; // 1 sec can cause failure.
		if ( (int) date("U") < (int) ($accessToken->nbf - $timeTolerance) || (int) date("U") > (int) $accessToken->exp ) {
			$this->logmodel->addToLog("ACTUAL: NO!\nNBF: ".$accessToken->nbf - $timeTolerance."( -".$timeTolerance." sec.),\nNOW: ".date("U").",\nEXP: ".$accessToken->exp."\n");
			return false;
		}
		$this->logmodel->addToLog("ACTUAL: YES, BIAS: ".(date("U") - (int) $accessToken->nbf)." sec. (-".$timeTolerance." sec. tolerance)\n");
		return true;
	}

	/**
	* Verifies a signature sent by ESIA
	* disabled
	* 
	* @param $accessToken array
	* @return true|false
	*/
	private function verifySignature($accessToken) { // correct this later
		/*
		$algs = array(
			'RS256' => 'sha256'
		);
		//$path =$this->config->item("base_server_path").'tickets';
		//$certpath = $this->config->item("cert_path");
		//file_put_contents($path.'signature', $accessToken['signature']);
		//file_put_contents($path.'hashpart',  $accessToken['hashpart']);

		//$command = "openssl dgst -sha256 -verify ".$path."esia2.pem -signature ".$path."signature ".$path."hashpart";
		//$result  = exec($command);
		//$this->logmodel->addToLog( "SIGNATURE CHECK COMMAND:\n ".$command."\nRESULT: ".$result."\n------------------\n" );

		/*
		* sorry, but we stop here for now...
		*/
		return true;
	}

	/**
	* Verifies state previously given in return URL with the one provided by us
	* 
	* @param $state string
	* @return string|false
	*/
	public function verifyState($state="") {
		// проверка возвращённого кода состояния ( Методические рекомендации по использованию ЕСИА v 2.23, Приложение В.2.2)
		if ( !strlen($state) ) {
			$this->logmodel->addToLog("\nSTATE PARAMETER '".$this->input->get('state')."' WAS NOT SUPPLIED! Aborting!\n------------------");
			$this->logmodel->writeLog();
			return false;
		}
		if ( $this->input->get('state') === $state ) {
			return true;
		}
		$this->logmodel->addToLog("\nSERVER RETURNED STATE PARAMETER '".$this->input->get('state')."' WHICH DOES NOT MATCH THE ONE SUPPLIED! Aborting!\n------------------");
		$this->logmodel->writeLog();
		return false;
	}

}