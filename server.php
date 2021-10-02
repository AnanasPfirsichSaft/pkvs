#!/usr/bin/php
<?php
/* =====================================================================
This file is part of "PHP Key Vault Server"
https://github.com/AnanasPfirsichSaft/pkvs

MIT License

Copyright (c) 2019-2021 AnanasPfirsichSaft

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
define('PKVS_VERSION',2);
define('PKVS_BIND_HOST','::1');
define('PKVS_BIND_PORT',2019);
define('PKVS_MAX_CLIENTS',16);
define('PKVS_MAXIMUM_ALERT_LEVEL',5);
define('PKVS_MAXIMUM_CLIENT_COMMANDS_PER_CONNECTION',10);
define('PKVS_HASH_ITERATIONS',50000);
define('PKVS_SANITIZE_STRING','.');
define('PKVS_ALLOW_LOCAL_INFILE',false);
// ============================================================================
error_reporting(-1);
	if ( !extension_loaded('sockets') )
	trigger_error('socket extension is not available',E_USER_ERROR);
	if ( !extension_loaded('openssl') )
	trigger_error('openssl extension is not available',E_USER_ERROR);
	if ( !extension_loaded('pcre') )
	trigger_error('pcre extension is not available',E_USER_ERROR);
	if ( strtolower(PHP_OS) !== 'linux' )
	trigger_error('at the moment only linux is supported',E_USER_ERROR);
	if ( !ini_get('safe_mode') )
	set_time_limit(0);
declare(ticks = 1);
$__key = '';
$__key_left = '';
$__key_right = '';
$__lock = false;
$__vault = array();
$__clients = array();
$__active = array();
$__stats = array('.'=>0,'rx'=>0,'tx'=>0);
$__auth_psk = array();
$__auth_config_group = 0;
$__auth_shutdown_group = 0;
$__auth_status_group = 0;
$__auth_file_in_fs = '';
$__alert_level = 0;
$__last_reply = 0;
$__greets = array(
'Good day, how may I serve you?',
'What ails you my friend?',
'Wow, what can I do for ya?',
'I sense a soul in search of answers.',
'Psst, over here.',
'Hello, my friend. Stay a while and listen.',
'The sanctity of this place has been fouled.',
'Aaah! Fresh meat!'
);
function pkvs_echo($a,$b=true,$c=''){echo $a;if($b)echo chr(10);
	if ( $b && $c !== 'NOLOG' && defined('PKVS_LOGFILE') && is_writeable(PKVS_LOGFILE) ){
	file_put_contents(PKVS_LOGFILE,'['.date('d.m H:i:s').'] '.$a.chr(10),FILE_APPEND);
	chmod(PKVS_LOGFILE,0600);
	}
}
function pkvs_socket_error($a){$e=socket_last_error();$e=socket_strerror($e);
trigger_error('socket error in "'.$a.'" says "'.$e.'"',E_USER_ERROR);}
function pkvs_client_slot(){return array('sock'=>null,'ip'=>null,'port'=>null,'rx_cmds'=>0,'auth'=>false,'key_group'=>0);}
function pkvs_close_socket($a){global $__clients;
socket_close($__clients[$a]['sock']);$__clients[$a] = pkvs_client_slot();return;}
function pkvs_encrypt($a,$b=''){global $__key,$__iv,$__tag;
$k = ( strlen($b) === 0 ) ? $__key : $b;
pkvs_sanitize($k,__LINE__);pkvs_sanitize($b,__LINE__); // unsure, if we should use zero padding as openssl option?
$b = openssl_encrypt($a,PKVS_CRYPT_ALGO,$k,OPENSSL_RAW_DATA,$__iv,$__tag);return $b;}
function pkvs_decrypt($a,$b=''){global $__key,$__iv,$__tag;
$k = ( strlen($b) === 0 ) ? $__key : $b;
pkvs_sanitize($k,__LINE__);pkvs_sanitize($b,__LINE__);
$b = openssl_decrypt($a,PKVS_CRYPT_ALGO,$k,OPENSSL_RAW_DATA,$__iv,$__tag);return $b;}
function pkvs_sanitize(&$a,$b){if(in_array(gettype($a),array('string','integer','double'),true))$a = str_repeat(PKVS_SANITIZE_STRING,strlen($a));/*else trigger_error('tried to sanitize non-string ('.gettype($a).') on line '.intval($b),E_USER_NOTICE);*/}
function pkvs_hash($a,$b=1){
if ( $b === 1 ){$c=sha1($a);for($i=0;$i<=PKVS_HASH_ITERATIONS;$i++)$c=sha1($c);return $c;}
elseif ( $b === 2 ){return crypt($a);}
}
function pkvs_var2arr(&$a){preg_match_all('/([a-z0-9]+)=["\']{1}(.+?)["\']{1}/u',$a,$b,PREG_SET_ORDER);if ( is_array($b) && sizeof($b) > 0 ){$a = array();
foreach ( $b as $k )$a[$k[1]] = $k[2];}return true;}
function pkvs_keymgr($a){
global $__key,$__key_left,$__key_right;
	if ( $a === '+' ){
		if ( defined('PKVS_KEY_POOL') ){
		$b = explode(';',PKVS_KEY_POOL);
			switch ( $b[0] ){
			case 'FILE':
			$__key_right = ( is_file($b[1]) && is_readable($b[1]) ) ? file_get_contents($b[1],false,null,0,floor(PKVS_KEY_LENGTH/2)) : '';
			break;
			}
			if ( strlen($__key_right) > 0 && strlen($__key_left.$__key_right) < PKVS_KEY_LENGTH )
			trigger_error('encryption key is too short',E_USER_ERROR);
			if ( strlen($__key_left.$__key_right) > PKVS_KEY_LENGTH ){
			$__key_right = substr($__key_right,0,floor(PKVS_KEY_LENGTH/2));
			trigger_error('encryption key is too long, truncating from '.strlen($__key_right).' to '.PKVS_KEY_LENGTH,E_USER_ERROR);
			}
		$__key = $__key_left.$__key_right;
		pkvs_sanitize($__key_right,__LINE__);
		}
		else
		$__key = $__key_left.$__key_right;
	}
	elseif ( $a === '-' )
	pkvs_sanitize($__key,__LINE__);
return true;
}
function pkvs_reply($a,$b){
global $__last_reply;
	if ( !is_array($b) ) $b = array($b);
$o = array();
	foreach ( $b as $k=>$v ){
	$s = ( $k === 0 ) ? ' ' : '-';
	$o[] = $a.$s.preg_replace('/[\t\r\n\0]+/','',$v);
	}
$__last_reply = (int)$a;
return implode(chr(10),$o).chr(10);
}
function pkvs_signal_handler($signo){
global $sock,$__clients,$__lock,$__vault,$__key,$__key_left,$__key_right,$__iv;
	switch ( $signo ){
	case SIGTERM: case SIGHUP:
	pkvs_echo('signal: caught SIGTERM/SIGHUP...');
	pkvs_echo('Initiating shutdown');
	pkvs_echo('Wiping contents to cleanup memory pages');
	pkvs_sanitize($__key,__LINE__);
	pkvs_sanitize($__key_left,__LINE__);
	pkvs_sanitize($__key_right,__LINE__);
	pkvs_sanitize($__iv,__LINE__);
		foreach ( $__vault as $k=>$v )
		pkvs_sanitize($__vault[$k]['hash'],__LINE__);
	pkvs_echo('Closing hard any open connections');
		for ( $i = 0 ; $i < PKVS_MAX_CLIENTS ; $i++ )
		socket_close($__clients[$i]['sock']);
	socket_close($sock);
	pkvs_echo('Good-Bye and take care of yourself!');
	exit;
	break;
	case SIGUSR1:
	pkvs_echo('signal: caught SIGUSR1...');
	pkvs_echo('Unlocking the vault');
	$__lock = false;
	pkvs_echo('Resuming normal operations');
	break;
	default: break;
	}
}
function pkvs_cipher_helper(&$a){
$a = strtolower($a);
}
function pkvs_help(){
echo "PHP KEY VAULT SERVER - VERSION ".PKVS_VERSION."\n";
echo "===========================================\n";
echo "Supported cryptographic ciphers:\n";
$ciphers = openssl_get_cipher_methods();
array_walk($ciphers,'pkvs_cipher_helper');
$ciphers = array_unique($ciphers);
sort($ciphers);
	foreach ( $ciphers as $key=>$value ){ // remove meaningless or unsafe modes [ecb!] and not correctly working ciphers [ccm,gcm,ocb]
		if ( preg_match('/(hmac|wrap|pad|ecb|ocb|[gc]+cm|idea|cast|des|seed|rc[0-9]+)/',$value) )
		unset($ciphers[$key]);
	}
echo wordwrap(implode(', ',$ciphers),72)."\n\n";
echo "Supported psk hash methods:\n";
$all_constants = get_defined_constants();
	foreach ( $all_constants as $key=>$value ){
		if ( substr($key,0,6) == "CRYPT_" )
		echo "$key => $value\n";
	}
echo "\n";
echo "PKVS will bind to address '".PKVS_BIND_HOST."' on port ".PKVS_BIND_PORT."\n\n";
echo "--cipher=[name]\t\tUse cipher for encrypting the keys in vault\n";
echo "\t\t\tSet 'auto', if unsure.\n";
echo "--auth-file=[filename]\tExistence of this file is required to supply keys\n";
echo "--pool=[fd]\t\tGet second half of the session key from external source\n";
echo "--log=[filename]\tAlso forward outputs to logfile\n";
echo "--no-auth\t\tNo authentication required for clients\n";
echo "--no-socket\t\tNo network connection, dryrun only\n\n";
echo "--hash-psk\t\tAsk for psk from stdin to hash\n";
echo "--gen-key=[ashex,bits]\tCreate a key for the vault\n";
echo "\t\t\tIf ashex is '1', 'y', 'true' or 'ashex' the key will be\n";
echo "\t\t\tprinted in hexadecimal. Otherwise base64 encoding is\n";
echo "\t\t\tapplied. Usual bit lengths are 128 or 256.\n";
echo "--help\t\t\tThis wonderful screen :)\n";
echo "\n";
}
$iamtrue = true;
$cli_args = array();
	if ( sizeof($argv) > 0 ){
		foreach ( $argv as $k=>$v ){
			if ( $k !== 0 )
			$cli_args[] = $v;
		}
	}
	if ( isset($cli_args[0]) && ( $cli_args[0] === 'help' || $cli_args[0] === '-h' || $cli_args[0] === '--help' ) ){
	pkvs_help();
	die();
	}
	foreach ( $cli_args as $v ){
		if ( $v === '--hash-psk' ){ // sha256 should be safe for now (2019), but you may patch it
			if ( !defined('CRYPT_SHA256') ) // see: https://www.php.net/manual/en/function.crypt.php
			trigger_error('your php does not support sha256 for hashing',E_USER_ERROR);
		echo 'WARNING: Will be visible!'.chr(10);
		echo 'Pre-Shared-Key Password: ';
			if ( $fp = fopen('php://stdin','r') ){
			$buffer = '';
				while ( !feof($fp) ){
				$buffer .= fgets($fp,128);
				break;
				}
			$buffer = preg_replace('/[\x00-\x1f]+/','',trim($buffer));
			fclose($fp);
			}
		die('Please include this psk into your configuration xml file:'.chr(10).chr(10).'<psk id=\'[ANYNUMBER]\' scheme=\'2\'>'.crypt($buffer,'$5$rounds='.PKVS_HASH_ITERATIONS.'$'.bin2hex(openssl_random_pseudo_bytes(8,$iamtrue)).'$').'</psk>'.chr(10).chr(10));
		}
		if ( substr($v,0,10) === '--gen-key=' ){
		$v = explode(',',substr($v,10));
		$v[1] = intval($v[1]);
			if ( $v[1] < 64 || $v[1] > 256 )
			trigger_error('your key length should be between 64 and 256 bits',E_USER_WARNING);
			switch ( strtolower($v[0]) ){
			case 'yes': case 'y': case 'true': case '1': case 'ashex':
			$v = bin2hex(openssl_random_pseudo_bytes(floor($v[1]/8),$iamtrue));
			break;
			default:
			$v = base64_encode(openssl_random_pseudo_bytes(floor($v[1]/8),$iamtrue));
			$e = ' encode=\'base64\'';
			break;
			}
		die('Please include this key into your configuration xml file:'.chr(10).chr(10).'<key id=\'[ANYNUMBER]\' allow=\'*\''.$e.'>'.$v.'</key>'.chr(10).chr(10));
		}
		if ( substr($v,0,6) === '--log=' ){
		define('PKVS_LOGFILE',substr($v,6));
			if ( !file_exists(PKVS_LOGFILE) && is_writeable(dirname(PKVS_LOGFILE)) ){
			touch(PKVS_LOGFILE);
			chmod(PKVS_LOGFILE,0600);
			}
		}
		if ( substr($v,0,9) === '--cipher=' ){
		$v = substr($v,9);
			if ( $v === 'auto' ){
			$ci = openssl_get_cipher_methods();
			$pr = array( // i removed 'ofb' as i am unsure if this is a safe mode?
			'aes-256-ctr',
			'camellia-256-ctr',
			'aes-128-ctr',
			'camellia-128-ctr',
			'aes-256-cbc',
			'camellia-256-cbc',
			'camellia-128-cbc',
			'bf-cbc'
			);
				foreach ( $pr as $v ){
					if ( in_array($v,$ci,true) )
					break;
				}
			}
		define('PKVS_CRYPT_ALGO',$v);
		}
		if ( substr($v,0,7) === '--pool=' ){
		$v = substr($v,7);
			if ( is_file($v) && is_readable($v) )
			define('PKVS_KEY_POOL','FILE;'.$v);
			else
			trigger_error('additional key material could not be read from pool. falling back to random key.',E_USER_WARNING);
		}
		if ( substr($v,0,12) === '--auth-file=' ){
		$v = substr($v,12);
		$__auth_file_in_fs = $v;
		}
		if ( $v === '--no-socket' )
		define('PKVS_DRYRUN',true);
		if ( $v === '--no-auth' )
		define('PKVS_NOAUTH',true);
	}

	for ( $i = 0 ; $i < PKVS_MAX_CLIENTS ; $i++ )
	$__clients[$i] = pkvs_client_slot();
unset($cli_args,$k,$v,$pr,$ci);

pkvs_echo('PHP Key Vault Server - Version '.PKVS_VERSION);
pkvs_echo('PHP Version is '.PHP_VERSION.' on '.PHP_OS);
	if ( !defined('PKVS_CRYPT_ALGO') ){
	pkvs_help();
	die();
	}
	if ( defined('PKVS_LOGFILE') )
	pkvs_echo('Enabling log file "'.PKVS_LOGFILE.'"');
	if ( defined('PKVS_NOAUTH') )
	pkvs_echo('Disabling client authentication');
	if ( strlen($__auth_file_in_fs) > 0 )
	pkvs_echo('Authentication file is required - '.$__auth_file_in_fs);
	if ( extension_loaded('pcntl') ){
	pkvs_echo('Setup new signal handler for TERM, HUP and USR1');
	pcntl_signal(SIGTERM,'pkvs_signal_handler');
	pcntl_signal(SIGHUP,'pkvs_signal_handler');
	pcntl_signal(SIGUSR1,'pkvs_signal_handler');
	}
pkvs_echo('Initializing encryption subsystem using '.PKVS_CRYPT_ALGO.' cipher');
	if ( !in_array(strtolower(PKVS_CRYPT_ALGO),openssl_get_cipher_methods(),true) )
	trigger_error('your selected cipher is not supported by openssl',E_USER_ERROR);
preg_match('/\d+/',PKVS_CRYPT_ALGO,$fp);
	if ( is_array($fp) && sizeof($fp) === 1 && strlen($fp[0]) > 0 )
	$kl = intval($fp[0]/8);
	else // todo: some keylength presets for other ciphers
	$kl = 16;
define('PKVS_KEY_LENGTH',$kl);
pkvs_echo('Guessed key length based on cipher as '.PKVS_KEY_LENGTH.' bytes');
pkvs_echo('Getting first half of the key from random source');
$__key_left = openssl_random_pseudo_bytes(floor(PKVS_KEY_LENGTH/2),$iamtrue);
	if ( defined('PKVS_KEY_POOL') )
	pkvs_echo('Getting second half of the key from external source ('.PKVS_KEY_POOL.')');
	else{
	pkvs_echo('Getting second half of the key from random source');
	$__key_right = openssl_random_pseudo_bytes(floor(PKVS_KEY_LENGTH/2),$iamtrue);
	}
pkvs_echo('Grabbing initialization vector');
$__iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(PKVS_CRYPT_ALGO),$iamtrue);
$__tag = '';
	if ( !defined('PKVS_DRYRUN') ){
	pkvs_echo('Getting a socket to establish network connections');
		if ( strpos(PKVS_BIND_HOST,':') !== false )
		$sock = AF_INET6;
		else
		$sock = AF_INET;
	$sock = socket_create($sock,SOCK_STREAM,SOL_TCP);
		if ( !$sock )
		pkvs_socket_error('socket_create');
		if ( !socket_bind($sock,PKVS_BIND_HOST,PKVS_BIND_PORT) )
		pkvs_socket_error('socket_bind');
		if ( !socket_listen($sock,3) )
		pkvs_socket_error('socket_listen');
	pkvs_echo('Listening on address '.PKVS_BIND_HOST.' and port '.PKVS_BIND_PORT.' for incoming connections');
	pkvs_echo('Used transport protocol is TCP. I read the sockets binary-safe.');
	pkvs_echo('Maximum number of simulatenous connections is '.PKVS_MAX_CLIENTS);
	pkvs_echo('Clients are allowed to issue '.PKVS_MAXIMUM_CLIENT_COMMANDS_PER_CONNECTION.' commands per connection');
//  socket_set_nonblock($sock); # needs more testing with simultaneous connections
	}
pkvs_echo('Startup completed :)');
pkvs_echo(str_repeat('=',72));
unset($fp,$eb,$kl);

	if ( defined('PKVS_DRYRUN') ){
	pkvs_echo('Entering dryrun endless loop...');
	sleep(86400*365);
	die();
	}

	while ( true ){
	// which clients are active and should be processed?
	$__stats['.']++;
	$__active[0] = $sock;
		for ( $i = 0 ; $i < PKVS_MAX_CLIENTS ; $i++ ){
			if ( !is_null($__clients[$i]['sock']) )
			$__active[$i+1] = $__clients[$i]['sock'];
		}
		if ( $__alert_level > PKVS_MAXIMUM_ALERT_LEVEL ){
		pkvs_echo('eek - alert level is above threshold. i will now call the crack suicide commando ;(');
		break;
		}
	pkvs_echo('*** #'.str_pad($__stats['.'],6,0,STR_PAD_LEFT).' AL['.$__alert_level.'] currently we have '.intval(sizeof($__active)-1).' connections, received '.$__stats['rx'].' bytes and sent '.$__stats['tx'].' bytes',true,'NOLOG');

	// set up a blocking call to socket_select()
	$write = null;
	$except = null;
	$ready = @socket_select($__active,$write,$except,$tv_sec=null);

		// if a new connection is being made add it to the client array
		if ( in_array($sock,$__active) ){
			for ( $i = 0 ; $i < PKVS_MAX_CLIENTS ; $i++ ){
				if ( is_null($__clients[$i]['sock']) ){
				$__clients[$i]['sock'] = socket_accept($sock);
				socket_getpeername($__clients[$i]['sock'],$ph,$pp);
				pkvs_echo(chr(9).'accepting connection for client '.$i.' ['.$ph.':'.$pp.']');
				$__clients[$i]['ip'] = $ph;
				$__clients[$i]['port'] = (int)$pp;
					if ( defined('PKVS_NOAUTH') || sizeof($__auth_psk) === 0 )
					$__clients[$i]['auth'] = true;
				$ph = array_rand($__greets);
				$ra = ( $__clients[$i]['auth'] ) ? ' ' : ' [AUTH] ';
				socket_write($__clients[$i]['sock'],'100 [PKVS] [V1]'.$ra.$__greets[$ph].chr(10));
				unset($ph,$pp,$ra);
				break;
				}
				elseif ( $i === PKVS_MAX_CLIENTS-1 )
				pkvs_echo(chr(9).'maximum client number reached, rejecting new connections');
			}
			if ( --$ready <= 0 )
			continue;
		}

/* response codes used (borrowed from http)
2=success,3=redirect,4=client err,5=server err
100 Continue
200 Ok
204 No Content
304 Not Modified
400 Bad Request
401 Auth Required
403 Forbidden
404 Not Found
*/

		// If a client is trying to write - handle it now
		for ( $i = 0 ; $i < PKVS_MAX_CLIENTS ; $i++ ){
			if ( in_array($__clients[$i]['sock'],$__active) ){
			clearstatcache();
			$input = trim(socket_read($__clients[$i]['sock'],8192));
				if ( substr($input,0,1) === '_' ){ // clients cannot use "system command"...
				$input = substr($input,1);
				pkvs_echo(chr(9).'client tried to send system command - trimming input',true,'NOLOG');
				}
/*			$bs = substr_count($input,' ');
				if ( $bs > 16 ){ // abort on too many blank spaces
				$input = '_ too_many_blank_spaces';
				pkvs_echo(chr(9).'client sent too much blank spaces {'.$bs.'} - blanking input',true,'NOLOG');
				}*/
			$__stats['rx'] += strlen($input);
			$__clients[$i]['rx_cmds']++;
			$close = false;
			$shutdown = false;
			$output = '';
			unset($bs);
				/*if ( is_null($input) || $input === '' ){
				pkvs_echo(chr(9).'closing connection to client '.$i.' due to zero response');
				pkvs_close_socket($i);
				continue;
				}*/
			$stack = explode(' ',$input);
			pkvs_echo(chr(9).'fetching '.strlen($input).' bytes from client '.$i.' having command [#'
			.$__clients[$i]['rx_cmds'].'/'.PKVS_MAXIMUM_CLIENT_COMMANDS_PER_CONNECTION.'] "'.substr($stack[0],0,16).'"');
				if ( !$__clients[$i]['auth'] && !in_array(strtolower($stack[0]),array('help','auth','quit'),true) ){
				$stack[0] = '_';
				$stack[1] = 'auth_required';
				}
				if ( $__clients[$i]['rx_cmds'] > PKVS_MAXIMUM_CLIENT_COMMANDS_PER_CONNECTION ){
				$stack[0] = '_';
				$stack[1] = 'too_many_commands';
				}
				switch ( strtolower($stack[0]) ){
				case 'auth':
					if ( $__clients[$i]['auth'] ){
					$output = pkvs_reply(200,'you are already authenticated');
					break;
					}
					if ( strlen($__auth_file_in_fs) > 0 ){
					clearstatcache(true,$__auth_file_in_fs);
						if ( !file_exists($__auth_file_in_fs) ){
						$output = pkvs_reply(403,'authentication file is missing');
						break;
						}
					}
				$ok = -1;
				$pf = ( isset($stack[1]) ) ? $stack[1] : '';
					foreach ( $__auth_psk as $id=>$hash ){
						if ( crypt($pf,$hash) == $hash )
						$ok = $id;
					}
					if ( $ok > 0 ){
					$output = pkvs_reply(200,'credentials confirmed, group-id is '.$ok);
					$__clients[$i]['auth'] = true;
					$__clients[$i]['key_group'] = intval($ok);
					pkvs_sanitize($pf,__LINE__);
					unset($pf);
					break;
					}
				$output = pkvs_reply(401,'credentials not correct');
				$__alert_level++;
				pkvs_sanitize($pf,__LINE__);
				pkvs_sanitize($hash,__LINE__);
				unset($pf,$ok,$id,$hash);
				break;
				case 'config':
					if ( $__auth_config_group > 0 && $__clients[$i]['key_group'] !== $auth_config_group ){
					$output = pkvs_reply(403,'you are not allowed to change the configuration');
					break;
					}
				$ok = false;
				$kv = $stack;
				unset($kv[0]); // input is xml formatted <key [args(key=value),...]>value</key>
				preg_match_all('/<([a-z0-9]+)([a-z0-9 =",\*\']*)>(.+?)<\/\1>/u',implode(' ',$kv),$kv,PREG_SET_ORDER);
				//var_dump($kv);
					if ( is_array($kv) && sizeof($kv) > 0 ){
						foreach ( $kv as $kd ){
							switch ( strtolower(trim($kd[1])) ){
							case 'psk':
							pkvs_var2arr($kd[2]);
							$kd[2]['id'] = abs($kd[2]['id']); // no negative values!
							$__auth_psk[$kd[2]['id']] = $kd[3];
							pkvs_echo(chr(9).chr(9).'configuring psk id '.$kd[2]['id']);
							$ok = true;
							break;
							case 'cmd':
							pkvs_var2arr($kd[2]);
								if ( $kd[2]['name'] === 'config' )
								$__auth_config_group = abs($kd[3]);
								if ( $kd[2]['name'] === 'shutdown' )
								$__auth_shutdown_group = abs($kd[3]);
								if ( $kd[2]['name'] === 'status' )
								$__auth_status_group = abs($kd[3]);
							pkvs_echo(chr(9).chr(9).'configuring '.$kd[2]['name'].' to '.abs($kd[3]));
							$ok = true;
							break;
							}
						pkvs_sanitize($kd[0],__LINE__);
						pkvs_sanitize($kd[1],__LINE__);
							if ( is_array($kd[2]) ){
								foreach ( $kd[2] as $k1=>$k2 )
								pkvs_sanitize($kd[2][$k1],__LINE__);
							}
						pkvs_sanitize($kd[3],__LINE__);
						}
					}
					foreach ( $kv as $k1=>$k2 )
					pkvs_sanitize($kv[$k1],__LINE__);
					if ( $ok )
					$output = pkvs_reply(200,'ok');
					else
					$output = pkvs_reply(304,'no configuration changes');
				unset($ok,$kv,$kd,$k1,$k2);
				break;
				case 'list':
				$kl = array();
					foreach ( $__vault as $k1=>$k2 ){
						if ( sizeof($k2['group']) === 0 || in_array($__clients[$i]['key_group'],$k2['group']) )
						$kl[] = $k1;
					pkvs_sanitize($k2['hash'],__LINE__);
					}
				sort($kl);
				$output = pkvs_reply(200,array('keys in vault',implode(',',$kl)));
				unset($kl,$k1,$k2);
				break;
				case 'lock':
					if ( sizeof($__vault) === 0 ){
					$output = pkvs_reply(304,'why should i lock an empty vault?');
					break;
					}
					if ( $__lock ){
					$output = pkvs_reply(304,'sorry, the vault is already locked');
					break;
					}
				$__lock = true;
				$output = pkvs_reply(200,'ok');
				break;
				case 'get':
				$safe = false;
				$id = ( isset($stack[1]) ) ? $stack[1] : -1;
					if ( substr($id,0,1) === '+' ){
					$id = intval(substr($id,1));
					$close = true;
					}
					elseif ( substr($id,0,1) === '?' ){
					$id = intval(substr($id,1));
					$safe = true;
					}
					else
					$id = intval($id);
				$kv = ( isset($__vault[$id]) ) ? $__vault[$id] : false;
					if ( $kv === false )
					$output = pkvs_reply(404,'key '.$id.' not found');
					elseif ( sizeof($kv['group']) > 0 && !in_array($__clients[$i]['key_group'],$kv['group']) )
					$output = pkvs_reply(403,'not allowed to get key '.$id);
					elseif ( $kv === '_ token_missing' )
					$output = pkvs_reply(403,'key '.$id.' has been cleared');
					else{
					$id = pkvs_keymgr('+');
						if ( $id === true || $id === '' ){
						$kv['hash'] = pkvs_decrypt($kv['hash']);
							if ( $safe )
							$kv['hash'] = preg_replace_callback('/[\x00-\x1f\x80-\xff]{1}/',function($safe){return sprintf('\x%X',ord($safe[0]));},$kv['hash']);
						$output = pkvs_reply(200,$kv['hash']);
						}
						else
						$output = pkvs_reply(404,'key '.$id.' is corrupt');
					}
				pkvs_sanitize($safe,__LINE__);
				pkvs_sanitize($safe[0],__LINE__);
				pkvs_sanitize($kv['hash'],__LINE__);
				pkvs_keymgr('-');
				unset($id);
				break;
				case 'put':
					if ( $__lock ){
					$output = pkvs_reply(403,'the vault is locked against changes');
					break;
					}
				$id = ( isset($stack[1]) ) ? $stack[1] : false;
					if ( is_numeric($id) ) $id = intval($id);
					if ( substr($id,0,3) !== 'xml' && $id < 1 || $id > 1024 ){
					$output = pkvs_reply(400,'the id must be between 1 and 1024');
					break;
					}
					elseif ( !$id ){
					$output = pkvs_reply(400,'the id must be numeric, xml or xmlfile');
					break;
					}
				$kv = ( isset($stack[2]) ) ? $stack[2] : false;
					if ( sizeof($stack) > 3 && $id === 'xml' ){
					$ka = $stack; // if 'xml' is supplied, compile input as string except first two from stack...
					unset($ka[0],$ka[1]);
					$kv = implode(' ',$ka);
						foreach ( $ka as $ski=>$skv )
						pkvs_sanitize($ka[$ski],__LINE__);
					pkvs_sanitize($skv,__LINE__);
					}
					if ( substr($id,0,3) === 'xml' ){
					$ks = array('ok');
						if ( PKVS_ALLOW_LOCAL_INFILE && $id === 'xmlfile' && is_file($kv) && is_readable($kv) )
						$kv = file_get_contents($kv);
					$kv = preg_replace('/[\x00-\x08\x0b\x0c\x0e-\x1f]+/','?',$kv);
						if ( substr($kv,0,5) !== '<?xml' ){
						$output = pkvs_reply(400,'you gave me malformed xml input');
						pkvs_sanitize($kv,__LINE__);
						break;
						}
					preg_match_all('/<key_(\d+)([a-z0-9 =",\*\']*)>(.+?)<\/key_\1>/u',$kv,$kf,PREG_SET_ORDER);
					pkvs_sanitize($kv,__LINE__);
						if ( sizeof($kf) > 0 ){
						$id = pkvs_keymgr('+');
							foreach ( $kf as $kv ){
								if ( $id === false )
								break;
							pkvs_var2arr($kv[2]);
								if ( !isset($kv[2]['encode']) )
								$kv[2]['encode'] = 'plain';
								if ( !isset($kv[2]['allow']) || $kv[2]['allow'] === '*' )
								$kv[2]['allow'] = implode(',',array_keys($__auth_psk));
								if ( isset($kv[2]['deny']) && $kv[2]['deny'] === '*' ){
								pkvs_echo(chr(9).chr(9).'skip key '.(int)$kv[1].' due to deny all rule',true,'NOLOG');
								continue;
								}
								if ( $kv[2]['encode'] === 'base64' )
								$kv[3] = base64_decode($kv[3]);
							$__vault[(int)$kv[1]] = array('group'=>array_unique(explode(',',$kv[2]['allow'])),'hash'=>pkvs_encrypt($kv[3]));
							$ks[] = 'key '.(int)$kv[1].' stored, length is '.strlen($kv[3]);
							pkvs_echo(chr(9).chr(9).'set key '.(int)$kv[1].', allow to group-id '.implode(',',$__vault[(int)$kv[1]]['group']),true,'NOLOG');
							pkvs_sanitize($kv[0],__LINE__);
								if ( is_array($kv[2]) ){
									foreach ( $kv[2] as $k1=>$k2 )
									pkvs_sanitize($kv[2][$k1],__LINE__);
								}
							pkvs_sanitize($kv[3],__LINE__);
							}
						}
					$output = ( sizeof($ks) > 1 ) ? pkvs_reply(200,$ks) : pkvs_reply(304,'no keys changed');
					} // end if xml
					else{
						if ( strlen($kv) < 8 ){
						$output = pkvs_reply(400,'the key must be at least eight characters in length');
						break;
						}
					$ks = pkvs_keymgr('+');
					$ka = ( sizeof($__auth_psk) > 0 ) ? array_keys($__auth_psk) : array();
						if ( $ks === true || $ks === '' ){
							if ( $kv === '-' ){
							unset($__vault[$id]);
							pkvs_echo(chr(9).chr(9).'unset key '.(int)$id);
							}
							else{
							$__vault[$id] = array('group'=>$ka,'hash'=>pkvs_encrypt($kv));
							pkvs_echo(chr(9).chr(9).'set key '.(int)$id.', allow to all');
							}
						$output = pkvs_reply(200,array('key '.$id.' stored, length is '.strlen($kv)));
						pkvs_sanitize($kv,__LINE__);
						}
						else
						pkvs_reply(403,'key not changed');
					}
				pkvs_keymgr('-');
				unset($id,$ka,$kv,$kf,$ks,$k1,$k2);
				break;
				case 'exit': case 'quit':
				pkvs_echo(chr(9).'connection abort requested by client '.$i);
				$close = true;
				break;
				case 'help':
				$as = ( defined('PKVS_NOAUTH') ) ? '' : '*';
				$al = ( PKVS_ALLOW_LOCAL_INFILE )
				? '                       id can be "xmlfile" to read local files and value is the path'
				: '                       importing from local file has been disabled';
				$hs = array(
				'This is PKVS (PHP Key Vault Server). Its purpose is to safely store',
				'and provide keys for en-/decryption over networks.',
				'Here is what I can do for you:',
				'',
				'auth [passphrase]    send authentication credential',
				'config [value]     '.$as.' set configuration value',
				'                       value is xml data w/o linefeed',
				'                         <psk id=\'ANYNUMBER\' scheme=\'2\'>HASHED_PRE_SHARED_KEY</psk>',
				'                         <cmd name=\'STRING\'>GROUP_ID</cmd>',
				'                         STRING can be',
				'                           config - Change configuration',
				'                           status - Show pkvs status',
				'                           shutdown - Shutdown the server',
				'                         GROUP_ID sets which psk is allowed to perform action',
				'',
				'list               '.$as.' list all available key identifiers',
				'get [id]           '.$as.' get the requested key from vault',
				'get ?[id]          '.$as.' the same but output is safely encoded',
				'get +[id]          '.$as.' the same but close the connection afterwards',
				'put [id] [value]   '.$as.' put a new key to vault, where value is the key',
				'                       id can be "xml" and value is xml data w/o linefeed',
				$al,
				'',
				'lock               '.$as.' lock the vault to forbid any key changes',
				'status             '.$as.' see status page',
				'shutdown           '.$as.' shutdown the pkvs server',
				'quit                 close the connection',
				'',
				);
					if ( $as === '*' )
					$hs[] = 'Commands marked with an asterisk require authentication!';
				$output = pkvs_reply(100,$hs);
				unset($as,$al,$hs);
				break;
				case 'shutdown':
				pkvs_echo('shutdown of server requested by client');
					if ( $__clients[$i]['key_group'] !== $__auth_shutdown_group ){
					$output = pkvs_reply(403,'no permission to shutdown pkvs');
					$__alert_level++;
					}
					else{
					$output = pkvs_reply(200,'what a pity! don´t you like me, anymore?');
					$close = true;
					$shutdown = true;
					}
				break;
				case 'status':
				pkvs_echo('status of server requested by client');
					if ( $__clients[$i]['key_group'] !== $__auth_status_group ){
					$output = pkvs_reply(403,'no permission to see status of pkvs');
					$__alert_level++;
					}
					else{
					$output = pkvs_reply(200,array(
					'#Version: '.PKVS_VERSION,
					'#Environment: PHP '.PHP_VERSION.' ('.memory_get_usage().' bytes allocated)',
					'#Keys: '.sizeof($__vault).' in '.sizeof($__auth_psk).' groups',
					'#Encryption: '.PKVS_CRYPT_ALGO.' (key length is '.PKVS_KEY_LENGTH.')',
					'#Connections: '.intval(sizeof($__active)).'/'.PKVS_MAX_CLIENTS.' ('.$__stats['.'].' total)',
					'#Alert Level: '.$__alert_level.'/'.PKVS_MAXIMUM_ALERT_LEVEL,
					'#Transferred: received '.$__stats['rx'].' bytes and sent '.$__stats['tx'].' bytes',
					));
					}
				break;
				case '_': // _ means "system messages"; clients cannot poll it ;)
					if ( $stack[1] === 'too_many_blank_spaces' )
					$output = pkvs_reply(400,'do not send so much blank spaces');
					elseif ( $stack[1] === 'auth_required' )
					$output = pkvs_reply(401,'you have to authenticate yourself first');
					elseif ( $stack[1] === 'too_many_commands' ){
					$output = pkvs_reply(400,'i am not supposed to talk to you anymore');
					$close = true;
					}
					else
					$output = pkvs_reply(403,'nah, i do not like your face!');
				break;
				default: $output = pkvs_reply(204,'pardon, me?'); break;
				}
				if ( strlen($output) > 0 ){
				$__stats['tx'] += strlen($output);
				$d = socket_write($__clients[$i]['sock'],$output);
					if ( !$d ){
					pkvs_echo(chr(9).'socket to client '.$i.' appears to be broken');
					$close = true;
					}
					else{
					pkvs_echo(chr(9).'sending '.strlen($output).' bytes to client '.$i.' with code '.$__last_reply);
//					pkvs_echo(chr(9).chr(9).'client '.$i.' => input('.wordwrap($input,72,"\n\t\t",true).') output('.wordwrap(preg_replace('/[\t\r\n\0]+/',' ',rtrim($output)),72,"\n\t\t",true).')'.chr(10),true,'NOLOG');
						if ( $__last_reply === 200 )
						$__alert_level = 0;
					}
				}
				if ( $close ){
				pkvs_echo(chr(9).'closing connection to client '.$i);
				pkvs_close_socket($i);
				}
				foreach ( $stack as $ski=>$skv )
				pkvs_sanitize($stack[$ski],__LINE__);
			pkvs_sanitize($skv,__LINE__);
			pkvs_sanitize($input,__LINE__);
			pkvs_sanitize($output,__LINE__);
				if ( $shutdown )
				break 2;
			}
			else{ // end if: in_array($__clients[$i]['sock'],$__active)
				// close any lonely socket, that´s still in list but not marked active
				if ( !is_null($__clients[$i]['sock']) ){
				pkvs_echo(chr(9).'closing left behind (inactive) connection to client '.$i);
				pkvs_close_socket($i);
				}
			}
		}

	} // end while

pkvs_echo('hmm, leaving main loop to prepare shutdown. now cleaning up...');
pkvs_sanitize($__key,__LINE__);
pkvs_sanitize($__key_left,__LINE__);
pkvs_sanitize($__key_right,__LINE__);
pkvs_sanitize($__iv,__LINE__);
pkvs_sanitize($__tag,__LINE__);
	foreach ( $__vault as $k=>$v )
	pkvs_sanitize($__vault[$k]['hash'],__LINE__);
	for ( $i = 0 ; $i < PKVS_MAX_CLIENTS ; $i++ ){
		if ( !is_null($__clients[$i]['sock']) ){
		pkvs_echo('closing remaining connection to client '.$i);
		socket_close($__clients[$i]['sock']);
		}
	}
socket_close($sock);
	foreach ( $GLOBALS as $value ){
		if ( !is_array($value) )
		pkvs_sanitize($value,__LINE__);
	}
pkvs_echo('sensitive data purged from memory');
pkvs_echo('good bye and take care of yourself!');
exit;
?>