<?php
/* =====================================================================
This file is part of "PHP Key Vault Server"
https://github.com/AnanasPfirsichSaft/pkvs

MIT License

Copyright (c) 2022 AnanasPfirsichSaft

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
register_shutdown_function('pkvs_cleaner');
define('PKVS_VERSION',3);
define('PKVS_CIPHER','aes-256-ctr');

class pkvs_data {
var $lock = false;
var $iv = '';
var $tag = '';
var $km1 = '';
var $km2 = '';
var $psk = [];
var $cmd = ['shutdown'=>0];
var $key = [];
function __serialize(){
return ['lock'=>$this->lock,'iv'=>$this->iv,'tag'=>$this->tag,'km1'=>$this->km1,'km2'=>$this->km2,'psk'=>$this->psk,'cmd'=>$this->cmd,'key'=>$this->key];
}
function __unserialize($a){
$this->lock = $a['lock'];
$this->iv = $a['iv'];
$this->tag = $a['tag'];
$this->km1 = $a['km1'];
$this->km2 = $a['km2'];
$this->psk = $a['psk'];
$this->cmd = $a['cmd'];
$this->key = $a['key'];
}
}

function pkvs_cleaner(){
global $zz,$kd,$kv,$output,$error;
if ( isset($zz) ){
pkvs_sanitize($zz->iv);
pkvs_sanitize($zz->tag);
pkvs_sanitize($zz->km1);
pkvs_sanitize($zz->km2);
	foreach ( $zz->psk as $k=>$v )
	pkvs_sanitize($zz->psk[$k]);
	for ( $a = 1 ; $a <= sizeof($zz->key) ; $a++ )
	pkvs_sanitize($zz->key[$a]['data']);
}
if ( isset($kd) ){
pkvs_sanitize($kd[0]);
pkvs_sanitize($kd[3]);
}
if ( isset($kv) ){
	for ( $a = 0 ; $a < sizeof($kv) ; $a++ ){
	pkvs_sanitize($kv[$a][0]);
	pkvs_sanitize($kv[$a][3]);
	}
}
if ( isset($_POST['<?xml_version']) )
pkvs_sanitize($_POST['<?xml_version']);
if ( isset($_REQUEST['<?xml_version']) )
pkvs_sanitize($_REQUEST['<?xml_version']);
pkvs_sanitize($k);
pkvs_sanitize($v);
pkvs_sanitize($output);
pkvs_sanitize($error);
}

// not timing safe, but has it to be?
function pkvs_auth($a){global $zz;if(!isset($zz)||!is_string($a))return false;foreach($zz->psk as $k=>$v){if(crypt($a,$v) === $v)return $k;}return false;}
function pkvs_sanitize(&$a){$a = str_repeat('.',strlen($a));}
function pkvs_var2arr(&$a){preg_match_all('/([a-z0-9]+)=["\']{1}(.+?)["\']{1}/u',$a,$b,PREG_SET_ORDER);if ( is_array($b) && sizeof($b) > 0 ){$a = [];
  foreach ( $b as $k ){ if(is_numeric($k[2]))$k[2]=intval($k[2]);$a[$k[1]]=$k[2];}}return true;}
function pkvs_str2iarr($a){if(!is_bool($a)){$a=explode(',',$a);foreach($a as $k=>$v)$a[$k]=intval($v);}return $a;}
function pkvs_compat_keys($a){if(substr($a[0],1,1)==='/')return '</key'; else return "<key id='".$a[1]."'";}

$command = $_REQUEST['cmd'] ?? '';
$iamtrue = true;
$output = '';
$error = '';

	switch ( strtolower($command) ){
	case 'init':
	$d = trim(file_get_contents('php://input'));
		if ( strlen($d) < 100 ){
		$error = "you must provide the xml data as plain string in POST\n";
		break;
		}
		if ( stripos($d,"<?xml version='1.0' encoding='utf-8' standalone='yes'?>") === false ){
		$error = "cannot find xml header in data string\n";
		break;
		}
	$c = $_GET['compat'] ?? 0;
	$s = @shmop_open(ftok(__FILE__,'A'),'a',0600,10000);
	$zz = new pkvs_data;
		if ( $s !== false ){
		$e = trim(shmop_read($s,0,10000));
		$zz = unserialize($e);
			if ( $zz->lock ){
			pkvs_sanitize($d);
			$error = "vault has been locked\n";
			break;
			}
			else
			$zz = new pkvs_data;
		pkvs_sanitize($e);
		}
		if ( intval($c) > 0 )
		$d = preg_replace_callback('/<\/*key_(\d+)/','pkvs_compat_keys',$d);
	preg_match_all('/<([a-z0-9]+)([a-z0-9_ =",\*\'\-]*)>(.+?)<\/\1>/u',$d,$kv,PREG_SET_ORDER);
	$zz->iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(PKVS_CIPHER),$iamtrue);
	$zz->km1 = openssl_random_pseudo_bytes(16,$iamtrue);
	$h = hash_init('sha3-512');
	pkvs_sanitize($d);
		if ( is_array($kv) && sizeof($kv) > 0 ){
			foreach ( $kv as $kd ){
			$kd[1] = strtolower(trim($kd[1]));
				switch ( $kd[1] ){
				case 'version':
					if ( $c === 0 && intval($kd[3]) !== 3 ){
					$error = "wrong version number\n";
					break 2;
					}
				break;
				case 'integrity':
					if ( strlen($kd[3]) > 32 )
					$j = $kd[3];
				break;
				case 'pool':
					if ( file_exists($kd[3]) && is_readable($kd[3]) ){
					$b = mt_rand(0,filesize($kd[3])-16);
					$km2 = file_get_contents($kd[3],false,null,$b,16);
					$zz->km2 = $kd[3].':'.$b;
					}
					else{
					$error = "pool file is not readable\n";
					break 2;
					}
				pkvs_sanitize($b);
				pkvs_sanitize($kd[3]);
				break;
				case 'psk':
				pkvs_var2arr($kd[2]);
					if ( !isset($kd[2]['id']) ){
					$error = "key must have a numeric identifier larger than zero\n";
					break 2;
					}
				$kd[2]['id'] = intval($kd[2]['id']);
					if ( $kd[2]['id'] <= 0 ){
					$error = "key must have a numeric identifier larger than zero\n";
					break 2;
					}
				$zz->psk[$kd[2]['id']] = $kd[3];
				hash_update($h,$kd[3]);
				pkvs_sanitize($kd[3]);
				break;
				case 'cmd':
				pkvs_var2arr($kd[2]);
					if ( isset($zz->cmd[$kd[2]['name']]) ){
					$zz->cmd[$kd[2]['name']] = pkvs_str2iarr($kd[3]);
					hash_update($h,$kd[3]);
					}
				break;
				case 'key':
					if ( !isset($km2) ){
					$error = "pool must be defined before any key\n";
					break 2;
					}
				pkvs_var2arr($kd[2]);
					if ( !isset($kd[2]['id']) ){
					$error = "key must have a numeric identifier larger than zero\n";
					break 2;
					}
				$kd[2]['id'] = intval($kd[2]['id']);
					if ( $kd[2]['id'] <= 0 ){
					$error = "key must have a numeric identifier larger than zero\n";
					break 2;
					}
				$kd[2]['allow'] = $kd[2]['allow'] ?? false;
				$kd[2]['encode'] = $kd[2]['encode'] ?? 'raw';
					if ( isset($kd[2]['deny']) && $kd[2]['deny'] === '*' )
					$kd[2]['allow'] = false;
					if ( $kd[2]['encode'] === 'base64' )
					$kd[3] = base64_decode($kd[3]);
				$b = openssl_encrypt($kd[3],PKVS_CIPHER,$zz->km1.$km2,OPENSSL_RAW_DATA,$zz->iv,$zz->tag);
				$zz->key[$kd[2]['id']] = ['allow'=>pkvs_str2iarr($kd[2]['allow']),'encode'=>$kd[2]['encode'],'data'=>$b];
				hash_update($h,$kd[3]);
				pkvs_sanitize($b);
				pkvs_sanitize($kd[3]);
				break;
				}
			}
		}
	pkvs_sanitize($km2);
	$h = base64_encode(hash_final($h,true));
		if ( sizeof($zz->psk) === 0 || sizeof($zz->key) === 0 ){
		$error = "neither you have set any psk nor any keys\n";
		break;
		}
		if ( isset($j) )
		$output .= ( strcmp($h,$j) === 0 ) ? "OK $h\n" : "ERR $h\n";
		else
		$output .= "UNK $h\n";
	$s = shmop_open(ftok(__FILE__,'A'),'c',0600,10000);
	$s = shmop_write($s,serialize($zz),0);
		if ( !$s )
		$error = "could not write shared memory data\n";
	/*echo "<pre>";
	var_dump($zz);
	echo "</pre>";*/
	break;

	case 'get':
	$i = $_GET['key'] ?? 0;
	$i = intval($i);
	$a = $_GET['auth'] ?? '';
	$s = @shmop_open(ftok(__FILE__,'A'),'a',0600,10000);
	$d = ( $s !== false ) ? trim(shmop_read($s,0,10000)) : false;
		if ( !$d || strlen($d) < 100 ){
		$error = "could not read shared memory data\n";
		break;
		}
	$zz = unserialize($d);
	pkvs_sanitize($d);
	$b = pkvs_auth($a);
	$a = explode(':',$zz->km2);
		if ( !$b ){
		$error = "authorization credential incorrect\n";
		break;
		}
		if ( !file_exists($a[0]) || !is_readable($a[0]) ){
		$error = "pool file is not readable\n";
		break;
		}
		if ( !isset($zz->key[$i]) ){
		$error = "key cannot be found\n";
		break;
		}
		if ( !$zz->key[$i]['allow'] || !in_array($b,$zz->key[$i]['allow'],true) ){
		$error = "you are not allowed to fetch this key\n";
		break;
		}
	$output .= openssl_decrypt($zz->key[$i]['data'],PKVS_CIPHER,$zz->km1.file_get_contents($a[0],false,null,intval($a[1]),16),OPENSSL_RAW_DATA,$zz->iv,$zz->tag)."\n";
	pkvs_sanitize($a[0]);
	pkvs_sanitize($a[1]);
	break;

	case 'lock':
	$s = @shmop_open(ftok(__FILE__,'A'),'a',0600,10000);
	$d = ( $s !== false ) ? trim(shmop_read($s,0,10000)) : false;
		if ( !$d || strlen($d) < 100 ){
		$error = "could not read shared memory data\n";
		break;
		}
	$zz = unserialize($d);
	pkvs_sanitize($d);
		if ( $zz->lock )
		$error = "already locked\n";
		else{
		$zz->lock = true;
		$s = shmop_open(ftok(__FILE__,'A'),'w',0600,10000);
		$s = shmop_write($s,serialize($zz),0);
			if ( !$s )
			$error = "could not write shared memory data\n";
		$output .= "OK\n";
		}
	break;

	case 'shutdown':
	$a = $_GET['auth'] ?? '';
	$s = @shmop_open(ftok(__FILE__,'A'),'a',0600,10000);
	$d = ( $s !== false ) ? trim(shmop_read($s,0,10000)) : false;
		if ( !$d || strlen($d) < 100 ){
		$error = "could not read shared memory data\n";
		break;
		}
	$zz = unserialize($d);
	pkvs_sanitize($d);
	$b = pkvs_auth($a);
		if ( !$b ){
		$error = "authorization credential incorrect\n";
		break;
		}
		if ( !in_array($b,$zz->cmd['shutdown'],true) ){
		$error = "you are not allowed to shutdown\n";
		break;
		}
	$s = shmop_open(ftok(__FILE__,'A'),'w',0600,10000);
	shmop_write($s,str_repeat('.',10000),10000);
		if ( shmop_delete($s) )
		$output .= "OK\n";
		else
		$error = "could not remove shared memory data\n";
	break;

	case 'status':
	$s = @shmop_open(ftok(__FILE__,'A'),'a',0600,10000);
	$d = ( $s !== false ) ? trim(shmop_read($s,0,10000)) : false;
		if ( !$d || strlen($d) < 100 ){
		$error = "could not read shared memory data\n";
		break;
		}
	$zz = unserialize($d);
	$a = strlen($d);
	pkvs_sanitize($d);
	$output .= "OK\n";
	$output .= "- The size of shared memory segment is ".$a." bytes\n";
	$output .= "- I have ".sizeof($zz->key)." keys in my vault\n";
	$output .= "- ".sizeof($zz->psk)." groups are defined for authorization\n";
	$output .= ( $zz->lock ) ? "- The vault is locked" : "- The vault is unlocked";
	break;

	default:
	$output .= "OK\n";
	$output .= "- PKVS Lite – Version ".PKVS_VERSION."\n";
	$output .= "- \n";
	$output .= "- Usage:\n";
	$output .= "- cmd=init, as POST with xml string in 'data'\n";
	$output .= "- cmd=get, as GET with key id 'key' and 'auth' credential\n";
	$output .= "- cmd=lock, as GET with no parameters\n";
	$output .= "- cmd=shutdown, as GET with 'auth' credential\n";
	$output .= "- cmd=status, as GET with no parameters";
	break;
	}

	if ( strlen($error) === 0 )
	header($_SERVER['SERVER_PROTOCOL'].' 200 OK',200,true);
	else{
	header($_SERVER['SERVER_PROTOCOL'].' 404 Not Found',404,true);
	$output = 'ERR '.$error;
	}
header('Content-Type: text/plain; charset=utf-8');
echo $output;
?>