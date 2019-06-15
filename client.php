#!/usr/bin/php
<?php
/* =====================================================================
This file is part of "PHP Key Vault Server"
https://github.com/AnanasPfirsichSaft/pkvs

MIT License

Copyright (c) 2019 AnanasPfirsichSaft

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */
error_reporting(-1);
function fmtreply($a){return "\t".str_replace("\n","\t\n",$a);}
function pecho($a){global $pkvs_verbose;if($pkvs_verbose)echo $a;}
$pkvs_host = array('localhost',2019);
$pkvs_file_default = ( strtolower(PHP_OS) == 'linux' ) ? '/tmp/pkvs_data.xml' : 'z:/pkvs_data.xml';
$pkvs_key = 0;
$pkvs_file = '';
$pkvs_auth = '';
$pkvs_lock = true;
$pkvs_verbose = false;
	if ( is_array($argv) && sizeof($argv) > 1 && !array_search('--help',$argv) ){
		foreach ( $argv as $key=>$value ){
		$key = substr($value,2,strpos($value,'=')-2);
		$value = substr($value,strpos($value,'=')+1);
			switch ( strtolower($key) ){
			case 'host':
			$pkvs_host = explode(':',$value);
				if ( !isset($pkvs_host[1]) || !is_scalar($pkvs_host[0]) )
				$pkvs_host[1] = 2019;
			$pkvs_host[0] = preg_replace('/[^a-z0-9\.\-]+/','',$pkvs_host[0]);
			$pkvs_host[1] = intval(preg_replace('/[^0-9]+/','',$pkvs_host[1]));
			break;
			case 'file':
				if ( !file_exists($value) || !is_readable($value) )
				trigger_error('xml file is not found or readable',E_USER_ERROR);
			$pkvs_file = $value;
			break;
			case 'key':
			$pkvs_key = intval($value);
			break;
			case 'auth':
			$pkvs_auth = preg_replace('/[\x00-\x1f]+/','',$value);
			break;
			}
		}
		if ( in_array('--no-lock',$argv,true) )
		$pkvs_lock = false;
		if ( in_array('--verbose',$argv,true) )
		$pkvs_verbose = true;
	}
	else{
	echo "PHP VAULT KEY SERVER CLIENT\n";
	echo "================================\n\n";
	echo "--host=[hostname:port]\tSet hostname and port of PKVS. Can be a direct connection or\n";
	echo "\t\t\tfor example a forwarded port through an encrypted ssh tunnel.\n";
	echo "\t\t\tDefault is localhost and port 2019.\n";
	echo "--auth=[string|-]\tAuthentication credential, if needed. Use '-' to ask interactively.\n";
	echo "--key=[id]\t\tGet the key from vault. If missing, keys will be put.\n";
	echo "--file=[filename]\tPath to xml file to send with keys and optional configuration.\n";
	echo "\t\t\tDefault is '".$pkvs_file_default."'.\n";
	echo "--no-lock\t\tDo not lock the vault at the end\n";
	echo "--verbose\t\tBe verbose about my doing\n";
	die();
	}
unset($key,$value);
	if ( $pkvs_auth === '-' ){
	echo 'WARNING: Will be seen!'.chr(10);
	echo 'PKVS password: ';
		if ( $fp = fopen('php://stdin','r')){
		$pkvs_auth = '';
			while ( !feof($fp) ){
			$pkvs_auth .= fgets($fp,128);
			break;
			}
		fclose($fp);
		unset($fp);
		}
	}
	if ( strlen($pkvs_file) < 8 )
	$pkvs_file = $pkvs_file_default;
$pkvs_auth = preg_replace('/[\x00-\x1f]+/','',$pkvs_auth);

	if ( strlen($pkvs_file) > 8 && file_exists($pkvs_file) && is_readable($pkvs_file) ){
	$xml = file_get_contents($pkvs_file);
	preg_match('/<configuration>(.+?)<\/configuration>/su',$xml,$config);
	preg_match('/<storage>(.+?)<\/storage>/su',$xml,$keys);
		if ( is_array($config) && sizeof($config) === 2 )
		$config = '<?xml version=\'1.0\' encoding=\'utf-8\' standalone=\'yes\'?> '.$config[1];
		else
		trigger_error('no configuration block found in xml file',E_USER_ERROR);
		if ( is_array($keys) && sizeof($keys) === 2 )
		$keys = '<?xml version=\'1.0\' encoding=\'utf-8\' standalone=\'yes\'?> '.$keys[1];
		else
		trigger_error('no key block found in xml file',E_USER_ERROR);
	//print_r('config{{'.$config.'}}'.chr(10));
	//print_r('storage{{'.$keys.'}}'.chr(10));
	pecho('READ XML LEN='.strlen($xml).chr(10));
	}
	else{
	$config = '';
	$keys = '';
	}

pecho('CONNECT '.$pkvs_host[0].':'.$pkvs_host[1].chr(10));
$sock = fsockopen($pkvs_host[0],$pkvs_host[1]);
	if ( $sock ){
	$reply = fread($sock,1024);
	pecho(fmtreply($reply));
		if ( strlen($pkvs_auth) > 0 ){
		pecho('AUTHENTICATE'.chr(10));
		fputs($sock,'auth '.$pkvs_auth);
		$reply = fread($sock,1024);
		pecho(fmtreply($reply));
		}
		if ( in_array(substr($reply,0,3),array('100','200')) ){
			if ( $pkvs_key > 0 ){
			pecho('GET KEY '.chr(10));
			fputs($sock,'get '.$pkvs_key);
			$reply = fread($sock,1024);
				if ( intval(substr($reply,0,3)) === 200 )
				echo substr($reply,4).chr(10);
				else
				echo fmtreply($reply);
			}
			elseif ( strlen($config) > 0 && strlen($keys) > 0 ){
			pecho('PUT CONFIGURATION DATA'.chr(10));
			fputs($sock,'config '.str_replace(array(chr(9),chr(10),chr(13)),array('','',''),$config));
			$reply = fread($sock,1024);
			pecho(fmtreply($reply));
				if ( intval(substr($reply,0,3)) === 200 ){
				pecho('PUT KEY DATA'.chr(10));
				fputs($sock,'put xml '.str_replace(array(chr(9),chr(10),chr(13)),array('','',''),$keys));
				$reply = fread($sock,1024);
				pecho(fmtreply($reply));
					if ( $pkvs_lock && intval(substr($reply,0,3)) === 200 ){
					pecho('LOCKING VAULT'.chr(10));
					fputs($sock,'lock');
					$reply = fread($sock,1024);
					}
					else
					$reply = '';
				echo fmtreply($reply);
				}
			}
		}
	pecho('QUIT'.chr(10));
	fputs($sock,'quit');
	$reply = fread($sock,1024);
	pecho(fmtreply($reply));
	fclose($sock);
	}
?>