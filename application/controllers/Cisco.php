<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Cisco extends CI_Controller {

	function __construct() {
		parent::__construct();
	}

	public function getUUID() {
		return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
		mt_rand(0, 0xffff),
		mt_rand(0, 0xffff),
		mt_rand(0, 0xffff),
		mt_rand(0, 0x0fff) | 0x4000,
		mt_rand(0, 0x3fff) | 0x8000,
		mt_rand(0, 0xffff),
		mt_rand(0, 0xffff),
		mt_rand(0, 0xffff));
	}

	public function trap() {
		$ticket = $this->getUUID();
		$data = $_GET;
		$data['profile'] = "cisco";
		$options = array(
			'http' => array(
				'content' => http_build_query(
					array(
						'data'     => json_encode($data),
						'systemID' => "bbfb534e-b325-4e18-9e40-a67897474d40",
						'ticket'   => $ticket
					)
				),
			'header'  => 'Content-type: application/x-www-form-urlencoded',
			'method'  => 'POST'
		));
		//print json_encode($data);
		//return false;
		$context = stream_context_create($options);
		$this->load->view("cisco/cisco", array("link" => file_get_contents("http://esia.arhcity.ru/esiabridge/processticket", false, $context)));
	}

	public function finalize($EsiaID, $objectID) {
		$ticketFile = $this->config->item("base_server_path")."tickets/".$objectID;
		$logdata    = json_decode(file_get_contents($ticketFile));
		if ( file_exists($ticketFile) ) {
			unlink($ticketFile);
		}
		$this->load->library('user_agent');
		$mobile     = ($this->agent->is_mobile()) ? " mobile device " : " PC ";
		$browser    = " - ".$this->agent->browser()." - ".$this->agent->version();
		$userString = date("d.m.Y H:i:s")." - ".$EsiaID.' - '.$logdata->client_mac." - ".$logdata->wlan." - ".$mobile.$browser."\n";
		if (strlen($EsiaID)) {
			file_put_contents($this->config->item('base_server_path')."/cisco_log.log", $userString, FILE_APPEND);
		}
		$options = array(
			'http' => array(
				'content' => http_build_query(array(
					"username"		=> "esiayes",
					"password"		=> "Uslugi170817",
					"redirect_url"	=> "http://www.arhcity.ru",
					//"buttonClicked"	=> 4,
					//"err_flag"		=> 0
				)),
				'header'  => "Content-type: application/x-www-form-urlencoded",
				'method'  => 'POST'
			),
			"ssl" => array(
				"verify_peer"      => false,
				"verify_peer_name" => false
			)
		);
		$context = stream_context_create($options);
		$file    = file_get_contents("https://192.168.152.2/login.html", false, $context);
		$file    = str_replace('src="/', 'src="https://1.1.1.1/', $file);
		$file    = str_replace('ACTION="/', 'ACTION="https://1.1.1.1/', $file);
		$file    = str_replace('<INPUT type="TEXT" name="username" size="25" maxlength="63" value="">', '<INPUT type="hidden" name="username" maxlength="63" value="">', $file );
		$file    = str_replace('<INPUT type="Password" name="password" emweb_type=PASSWORD size="25" maxlength="63" value="" EMWEB_TYPE=PASSWORD>', '<INPUT type="hidden" name="password" maxlength="63" value="">', $file);
		$insurgent = '<script type="text/javascript">
		document.forms[0].username.value      = "esiayes";
		document.forms[0].password.value      = "Uslugi170817";
		document.forms[0].redirect_url.value  = "http://www.arhcity.ru";
		document.forms[0].buttonClicked.value = 4;
		document.forms[0].submit();
		</script></body>';
		$file = str_replace('</body>', $insurgent, $file);
		print $file;
	}

	public function index() {
		header("Location: http://www.arhcity.ru");
	}
}