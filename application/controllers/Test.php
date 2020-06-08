<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Test extends CI_Controller {

	function __construct() {
		parent::__construct();
	}

	public function index() {
		//phpinfo();
		//exit;
		
		$path				= $this->config->item("base_server_path").'application/views/esia/';
		$signFile			= $path.'signed'.uniqid(true).'.msg';
		$messageFile		= $path.'message'.uniqid(true).'.msg';

		file_put_contents($messageFile, "1111111");

		shell_exec("openssl cms -sign -signer ".$this->config->item("cert_path")."auth.key -inkey ".$this->config->item("cert_path")."auth.key -binary -in ".$path."msg -outform pem -out ".$path."signature3");
	}

}