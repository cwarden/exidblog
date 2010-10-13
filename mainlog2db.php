#!/usr/bin/php4
<?php
require_once('EximDatabaseLogger.php');

$configFile = isset($_ENV['EXIDBLOG_CONF']) ? $_ENV['EXIDBLOG_CONF'] : '/etc/exidblog.conf';
include($configFile);

$mainlogPath = isset($mainlogPath) ? $mainlogPath : '/var/log/exim4/mainlog';

$tailCommand = "/bin/cat $mainlogPath; /usr/bin/tail --follow=name --retry $mainlogPath";
$tailHandle = popen("$tailCommand", 'r');
if (! is_resource($tailHandle)) {
	trigger_error('failed to start tail process');
}

$conn = mysql_connect($dbHost, $dbUser, $dbPass) or die('Failed to connect to database');
mysql_select_db($dbName) or die('Failed to select database: ' . $dbName);

$logger =& new EximDatabaseLogger($conn);
$logger->ignoreOldEntries = true;
$logger->parse($tailHandle);

pclose($tailHandle);

