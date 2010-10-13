<?php
require_once('EximDatabaseLogger.php');

$configFile = isset($_ENV['EXIDBLOG_CONF']) ? $_ENV['EXIDBLOG_CONF'] : '/etc/exidblog.conf';
include($configFile);

$handle = fopen('php://stdin', 'r');
if (! is_resource($handle)) {
	trigger_error('failed to open stdin');
}

$conn = mysql_connect($dbHost, $dbUser, $dbPass) or die('Failed to connect to database');
mysql_select_db($dbName) or die('Failed to select database: ' . $dbName);

$logger =& new EximDatabaseLogger($conn);
$logger->ignoreOldEntries = true;
$logger->parse($handle);

pclose($handle);

