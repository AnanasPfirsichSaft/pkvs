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
ob_start();
$key = ( isset($_GET['key']) ) ? (int)$_GET['key'] : 0;
$auth = ( isset($_GET['auth']) ) ? substr(preg_replace('/[\x00-\x1f]+/','',$_GET['auth']),0,64) : '';
$addlog = ( isset($_GET['addlog']) ) ? substr(preg_replace('/[^a-zA-Z0-9_ ]+/','',$_GET['addlog']),0,64) : '';
	if ( strlen($addlog) > 4 ){
	openlog('pkvs_proxy',LOG_NDELAY,LOG_DAEMON);
	syslog(LOG_NOTICE,'src='.$_SERVER['REMOTE_ADDR'].' '.$addlog);
	closelog();
	}
$host = explode(':','localhost:2019');
$sock = fsockopen($host[0],$host[1]);
	if ( is_resource($sock) && $key !== 0 ){
	$a = fread($sock,1024);
		if ( (int)substr($a,0,3) === 100 ){
			if ( strlen($auth) > 0 ){
			fputs($sock,'auth '.$auth);
			$a = fread($sock,1024);
			}
			else
			$a = '200 Ok';
			if ( (int)substr($a,0,3) === 200 ){
			fputs($sock,'get '.$key);
			$a = fread($sock,1024);
				if ( (int)substr($a,0,3) === 200 )
				echo substr($a,4);
				else{
				header('HTTP/1.0 404 Not Found',404,true);
				echo 'key not found';
				}
			}
			else{
			header('HTTP/1.0 403 Forbidden',403,true);
			echo 'authentication failure';
			}
		fputs($sock,'quit');
		fread($sock,1024);
		}
		else{
		header('HTTP/1.0 500 Internal Error',500,true);
		echo 'bad greeting from pkvs';
		}
	fclose($sock);
	}
	else{
	header('HTTP/1.0 502 Bad Gateway',502,true);
	echo 'connection to pkvs failed';
	}

header('Content-Type: text/plain; charset=utf-8');
header('Content-Length: '.strlen(ob_get_contents()));
header('Cache-Control: no-cache,no-store,max-age=0,s-maxage=0');
header('Connection: close');
header('Expires: 0');
ob_end_flush();
?>