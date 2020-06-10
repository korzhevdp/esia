<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Test extends CI_Controller {

	function __construct() {
		parent::__construct();
	}

	public function index() {
		print 'test routine<br><br><br>';

		$path = $this->config->item("base_server_path").'tickets/';

		//exec("openssl dgst -verify ".$path."gost.pem -signature ".$path."signature ".$path."hashpart", $err);

		print "openssl dgst -md_gost12_256 -sign   ".$path."auth.key -out ".$path."in.txt.2012 ".$path."in.txt<br>";
		print "openssl dgst -md_gost12_256 -verify ".$path."auth.key -signature ".$path."in.txt.2012 ".$path."in.txt";

		//exec("openssl dgst -md_gost12_256 -sign   ".$path."auth.key -out ".$path."in.txt.2012 ".$path."in.txt");
		//exec("openssl dgst -md_gost12_256 -verify ".$path."auth.key -signature ".$path."in.txt.2012 ".$path."in.txt");

		//print str_replace(" ", "&nbsp;", str_replace("\n", "<br>", print_r($err, true)));
	}

}