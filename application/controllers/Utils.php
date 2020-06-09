<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Utils extends CI_Controller {

	function __construct() {
		parent::__construct();
	}

	public function makepostrequest() {
		$ticket = array(
			"profile"     => "address",
			"matchParams" => array(
				"region"  => "Архангельская обл",
				"city"    => array(
					"г Архангельск"   => array(
						"ул Гагарина" => array("4","3","7","32","9","10"),
						"ул Ленина"   => array("4","3","7","5","9","10")
					),
					"г Северодвинск" => array()
				)
			)
		);
		print http_build_query($ticket);
	}

	public function writeTokenFile() {
		$objectID = "c15aa69b-b10e-46de-b124-85dbd0a9f4c9";
		
		$ticket = array(
			"profile"     => "openid",
			
			"matchParams" => array(
				"region"  => "Архангельская обл",
				"city"    => array(
					"г Архангельск"   => array(
						"ул Гагарина" => array("4","3","7","32","9","10"),
						"ул Ленина"   => array("4","3","7","5","9","10")
					),
					"г Северодвинск" => array()
				)
			)
			
		);
		$json = json_encode($ticket);
		print $json;
		$file   = file_put_contents($this->config->item("base_server_path")."tickets/".$objectID, $json);
	}

	public function verifyx() {
		$path   = $this->config->item("base_server_path").'application/views/esia/';
		$command = "openssl dgst -verify ".$path."cert/prom/esia.cer -signature ".$path."signature ".$path."hashpart";
		$result = exec($command);
		print $result;
	}

	public function index() {
		header("Location: https://www.arhcity.ru");
	}
	
}