#!/usr/bin/php
<?php
/* =====================================================================
This file is part of "PHP Key Vault Server"
https://github.com/AnanasPfirsichSaft/pkvs

MIT License

Copyright (c) 2023 AnanasPfirsichSaft

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
	if ( !defined('PASSWORD_ARGON2I') && !defined('PASSWORD_ARGON2ID') )
	die("Your PHP installation does not support argon2.\n");
	if ( defined('PASSWORD_ARGON2ID') ){
	$algo = PASSWORD_ARGON2ID;
	echo "we will use ARGON2ID\n";
	}
	else{
	$algo = PASSWORD_ARGON2I;
	echo "we will use ARGON2I\n";
	}
$opts = array(
'algo'=>$algo,
'time'=>PASSWORD_ARGON2_DEFAULT_TIME_COST,
'mem'=>PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
'thr'=>PASSWORD_ARGON2_DEFAULT_THREADS
);

echo "argon2 default time cost: ".PASSWORD_ARGON2_DEFAULT_TIME_COST." (use --time=X to override)\n";
echo "argon2 default memory cost (KiB): ".PASSWORD_ARGON2_DEFAULT_MEMORY_COST." (use --memory=X to override)\n";
echo "argon2 default threads: ".PASSWORD_ARGON2_DEFAULT_THREADS." (use --threads=X to override)\n";

	foreach ( $argv as $value ){
	preg_match('/^\-\-(time|memory|threads)=(\d+)$/iD',$value,$match);
		if ( is_array($match) && sizeof($match) === 3 ){
			switch ( $match[1] ){
			case 'time': $opts['time'] = intval($match[2]); echo "setting time to ".$opts['time']."\n"; break;
			case 'memory': $opts['mem'] = intval($match[2]); echo "setting memory to ".$opts['mem']."\n"; break;
			case 'threads': $opts['thr'] = intval($match[2]); echo "setting threads to ".$opts['thr']."\n"; break;
			}
		}
	}

echo "WARNING: Will be visible!\n";
echo "Pre-Shared-Key Password: ";
	if ( $fp = fopen('php://stdin','r') ){
	$buffer = '';
		while ( !feof($fp) ){
		$buffer .= fgets($fp,128);
		break;
		}
	$buffer = preg_replace('/[\x00-\x1f]+/','',trim($buffer));
	fclose($fp);
	}

	if ( strlen($buffer) > 4 ){
	$output = password_hash($buffer,$opts['algo'],array('memory_cost'=>$opts['mem'],'time_cost'=>$opts['time'],'threads'=>$opts['thr']));
	echo "Please include this psk into your configuration xml file:
	<psk id='[ANYNUMBER]' scheme='2'>".$output."</psk>\n";
	}
	else
	echo "password too short, use at least four characters\n";

?>