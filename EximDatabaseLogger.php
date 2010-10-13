<?php // $Header$
// based on eximstats
error_reporting(E_ALL);
define('EMAIL_REGEX', '[_[:alnum:]-]+(\.[_[:alnum:]-]+)*@[[:alnum:]-]+(\.[[:alnum:]-]+)*(\.([[:alpha:]]){2,4})');
define('LOG_TYPE_RECEIVED', 'RECEIVED');
define('LOG_TYPE_DELIVERED', 'DELIVERED');
define('LOG_TYPE_BOUNCED', 'BOUNCED');
define('LOG_TYPE_BLACKLISTED', 'BLACKLISTED');
define('LOG_TYPE_SPAM', 'SPAM');
define('LOG_TYPE_MALWARE', 'MALWARE');
define('LOG_TYPE_MIME_ERROR', 'MIME_ERROR');
define('LOG_TYPE_BAD_ATTACHMENT', 'BAD_ATTACHMENT');
define('LOG_TYPE_SENDER_VERIFY_FAIL', 'REJECT_INVALID_SENDER');
define('LOG_TYPE_SENDER_VERIFY_TEMP_FAIL', 'TEMP_REJECT_INVALID_SENDER');
define('LOG_TYPE_OTHER_TEMP_REJECT', 'OTHER_TEMP_REJECT');

define('HOSTNAME_FUNCTION', '/bin/hostname --fqdn');

/**
 *
 * Logs entries from Exim's mainlog to a database
 *
 * @author		Christian G. Warden <cwarden@postica.com>
 * @copyright	(c) 2004 by The Postica Corporation
 * @version		$Id$
 */
class EximDatabaseLogger {

	var $conn;
	var $mtaId;

	/**
	 * Ignore records whose timestamp is before this time.
	 * @var		integer
	 * @access	public
	 */
	var $startTime;

	/**
	 * Ignore records whose timestamp is less than the maximum timestamp for this mta.
	 * @var		integer
	 * @access	public
	 */
	var $ignoreOldEntries;

	/**
	*
	* Set timestamp, before which, records should be ignored.
	*
	* @access	public
	*/
	function setStartTime($timestamp) {
		$this->startTime = $timestamp;
	}

	/**
	*
	* Takes a database resource an optionally the id of the mta this log is from
	*
	* @return	EximDatabaseLogger
	* @access	public
	*/
	function EximDatabaseLogger(&$conn, $mtaId = null) {
		define_syslog_variables();
		openlog('exidblog', LOG_PERROR | LOG_PID, LOG_MAIL);
		$this->conn =& $conn;
		if (! is_null($mtaId)) {
			$this->mtaId = $mtaId;
		} else {
			$hostname = chop(exec(HOSTNAME_FUNCTION));
			$res = mysql_query(sprintf(
				"SELECT id FROM mta WHERE name = '%s'",
				mysql_real_escape_string($hostname)));
			if ($res === false) {	
				syslog(LOG_ERR, 'failed to get mta id: ' . mysql_error());
				die();
			}

			if (mysql_num_rows($res) != 1) {
				syslog(LOG_ERR, 'Failed to find record for mta: ' . $hostname);
				die();
			}
			list($this->mtaId) = mysql_fetch_array($res);
			if ($this->mtaId === false) {
				syslog(LOG_ERR, 'failed to get mta field: ' . mysql_error());
				die();
			}
			mysql_free_result($res) || die('failed to free result');
		}
	}

	/**
	*
	* Takes a file handle and read until
	*
	* @return	void
	* @access	public
	*/
	function parse($handle) {
		if ($this->ignoreOldEntries) {
			$res = mysql_query(sprintf('
				SELECT
					UNIX_TIMESTAMP(MAX(timestamp))
				FROM
					log
				WHERE
					mta = %d',
				$this->mtaId));
			if ($res === false) {
				syslog(LOG_ERR, 'query failed: ' . mysql_error());
				die();
			}
			list($this->startTime) = mysql_fetch_array($res) or die('failed to get start time: ' . mysql_error());
			mysql_free_result($res) || die('failed to free result');
		}
		$fakeRejects = array();
		do {
			$line = fgets($handle);
			if (strlen($line) == 0) {
				break;
			}
			if (strlen($line) < 38 ||
					!preg_match('/^(\d{4})\-(\d\d)-(\d\d)\s(\d\d):(\d\d):(\d\d)( [-+]\d\d\d\d)?/', $line, $matches)) {
				continue;
			}
			$timestamp = mktime($matches[4], $matches[5], $matches[6], $matches[2], $matches[3], $matches[1]);
			if ($timestamp <= $this->startTime) {
				echo 'skipping line.  timestamp ' . date('Y-m-d G:i:s', $timestamp) . ' before ' . date('Y-m-d G:i:s', $this->startTime) . "\n";
				continue;
			}
			$extra = !empty($matches[7]) ? 6 : 0;
			$id   = substr($line, 20 + $extra, 16);
			$flag = substr($line, 37 + $extra, 2);

			$remoteHost          = '';
			$remoteHostDomain    = '';
			$ip                  = '';
			$senderEmail         = '';
			$senderEmailDomain   = '';
			$recipient           = '';
			$recipientDomain     = '';
			$recipients          = array();
			$headerSubject       = '';
			$headerMessageID     = '';
			$logType             = '';
			$additionalData      = '';
			if (preg_match('/\sH=(\S+)/', $line, $matches)) {
				$remoteHost = $matches[1];
				if (preg_match('/\sH=.*?(\s\[([^]]+)\])/', $line, $matches)) {
					$ip = $matches[2];
				} else {
					$ip = '';
				}
				if ($remoteHost[0] != '[' && preg_match('/^(\(?)[^\.]+\.([^\.]+\..*)/', $remoteHost, $matches)) {
					$remoteHostDomain = $matches[1] . $matches[2];
				}
			}
			if ($flag == '<=') {
				if (isset($fakeRejects[$id])) {
					unset($fakeRejects[$id]);
					continue;
				}
				$line = substr($line, 40 + $extra);
				# sender email
				$senderEmail = preg_match('/^(\S+)/', $line, $matches) ? $matches[1] : '';
				$senderEmailDomain = preg_match('/^\S*?\@(\S+)/', $line, $matches) ? $matches[1] : '';
				$pattern = '/from <[^>]*?> for(( ((' . EMAIL_REGEX . ')|([-\w]+)))+)$/';
				preg_match($pattern, $line, $matches);
				$recipient = ltrim($matches[1]);
				$recipients = explode(' ', $recipient);
				$headerMessageID = preg_match('/\sid=(\S+)/', $line, $matches) ? $matches[1] : '';
				$headerSubject = preg_match('/\sT="(.*)" from </', $line, $matches) ? $matches[1] : '';
				// additionalData is authenticated sender
				$additionalData = preg_match('/ A=(cram_md5|spa|login|plain):(\S+) S=/', $line, $matches) ? $matches[2] : '';
				$logType = LOG_TYPE_RECEIVED;
			} elseif ($flag == '=>' || $flag == '->') {
				$router = preg_match('/\sR=(\S+)/', $line, $matches) ? $matches[1] : '';
				switch ($router) {
					case 'discard_spam':
					case 'cache':
						continue 2;
						break;
				}
				$line = substr($line, 40 + $extra);
				$senderEmail = preg_match('/\sF=<(\S+)>/', $line, $matches) ? $matches[1] : '<>';
				$senderEmailDomain = ltrim(strstr($senderEmail, '@'), '@');
				$recipients[] = preg_match('/^(\S+)/', $line, $matches) ? $matches[1] : '';
				$additionalData = preg_match('/\sC="(.*)"$/', $line, $matches) ? $matches[1] : '';
				$logType = LOG_TYPE_DELIVERED;
			} elseif ($flag == '**') {
				$line = substr($line, 40 + $extra);
				$senderEmail = preg_match('/\sF=<(\S+)>/', $line, $matches) ? $matches[1] : '<>';
				$senderEmailDomain = ltrim(strstr($senderEmail, '@'), '@');
				$recipients[] = preg_match('/^(\S+)/', $line, $matches) ? $matches[1] : '';
				$router = preg_match('/\sR=(\S+)/', $line, $matches) ? $matches[1] : '';
				$logType = LOG_TYPE_BOUNCED;
				// what caused the bounce?
				switch ($router) {
				}
			} elseif (($flag == 'FR' && preg_match('/^(\S+) \(([^)]*)\)/', substr($line, 40 + $extra), $matches)) ||
				($flag == 'H=' && preg_match('/rejected after DATA: (\S+) \(([^)]*)\)/', $line, $matches))) {
				// rejected in data acl
				switch ($matches[1]) {
					case 'SPAM':
						$logType = LOG_TYPE_SPAM;
						break;
					case 'MALWARE':
						$logType = LOG_TYPE_MALWARE;
						break;
					case 'MIME_ERROR':
						$logType = LOG_TYPE_MIME_ERROR;
						break;
					case 'BAD_ATTACHMENT':
						$logType = LOG_TYPE_BAD_ATTACHMENT;
						break;
				}
				$additionalData = $matches[2];
				$senderEmail = preg_match('/\sF=<(\S+)>/', $line, $matches) ? $matches[1] : '<>';
				$senderEmailDomain = ltrim(strstr($senderEmail, '@'), '@');
				$headerMessageID = preg_match('/\sMSGID=(\S+)/', $line, $matches) ? $matches[1] : '';
				$headerSubject = preg_match('/\sSUB="(.*)" MSGID/', $line, $matches) ? $matches[1] : '';
				$recipient = preg_match('/\sRCPT=((\S+ ))+SUB/', $line, $matches) ? trim($matches[1]) : '';
				$recipients = explode(':', $recipient);
				if ($flag == 'FR') {
					$fakeRejects[$id] = '';
				}
			} elseif (substr($id, 0, 2) == 'H=' && preg_match('/F=<(.*?)> (temporarily )?rejected RCPT/', $line, $matches)) {
				$id = '';
				$senderEmail = $matches[1] != '' ? $matches[1] : '<>';
				$senderEmailDomain = ltrim(strstr($senderEmail, '@'), '@');
				$temporary = isset($matches[2]);
				preg_match('/\srejected RCPT <?([^>]+)>?:(.*)/', $line, $matches);
				$recipients[] = $matches[1];
				if (strpos($matches[2], 'Sender verify failed') !== false) {
					$logType = LOG_TYPE_SENDER_VERIFY_FAIL;
				} elseif (strpos($matches[2], 'Could not complete sender verify') !== false) {
					$logType = LOG_TYPE_SENDER_VERIFY_TEMP_FAIL;
				} elseif (strpos($matches[2], 'blacklisted') !== false) {
					$logType = LOG_TYPE_BLACKLISTED;
				} elseif ($temporary) {
					$logType = LOG_TYPE_OTHER_TEMP_REJECT;
					$additionalData = ltrim($matches[2]);
				} else {
					// user unknown, relay not permitted
					// echo 'Perm reject RCPT: ' . $matches[1] . " : " . $matches[2] . "\n";
					continue;
				}
			} else {
				continue;
			}

			$logEntry =& new LogEntry($this->conn);
			$logEntry->mta                = $this->mtaId;
			$logEntry->timestamp          = $timestamp;
			$logEntry->logType            = $logType;
			$logEntry->senderEmail        = strtolower($senderEmail);
			$logEntry->senderEmailDomain  = strtolower($senderEmailDomain);
			$logEntry->remoteHost         = strtolower($remoteHost);
			$logEntry->remoteHostDomain   = strtolower($remoteHostDomain);
			$logEntry->remoteIp           = $ip;
			$logEntry->eximMessageId      = $id;
			$logEntry->headerSubject      = str_replace('\"', '"', $headerSubject);
			$logEntry->headerMessageID    = $headerMessageID;
			$logEntry->additionalData     = $additionalData;

			foreach ($recipients as $recipientEmail) {
				$recipientEmailDomain = '';
				if (preg_match('/^' . EMAIL_REGEX . '$/', $recipientEmail)) {
					$recipientEmailDomain = ltrim(strstr($recipientEmail, '@'), '@');
				}	
				$logEntry->recipientEmail       = strtolower($recipientEmail);
				$logEntry->recipientEmailDomain = strtolower($recipientEmailDomain);
				$logEntry->store();
			}
			unset($logEntry);
		} while (true);
	}
}

class LogEntry {
	var $conn;
	var $mta;
	var $timestamp;
	var $logType;
	var $senderEmail;
	var $senderEmailDomain;
	var $remoteHost;
	var $remoteHostDomain;
	var $remoteIp;
	var $eximMessageId;
	var $headerSubject;
	var $headerMessageID;
	var $recipientEmail;
	var $recipientEmailDomain;
	var $additionalData;

	function LogEntry(&$conn) {
		$this->conn =& $conn;
	}

	function store() {
		while (mysql_ping($this->conn) === false) {
			syslog(LOG_WARNING, 'Lost connection to database.  Will retry in 60 seconds.');
			sleep(60);
		}
		$sql = sprintf("
			INSERT INTO
				log
			(
				mta,
				timestamp,
				log_type,
				sender_email,
				sender_email_domain,
				remote_hostname,
				remote_hostname_domain,
				remote_ip,
				exim_message_id,
				recipient_email,
				recipient_email_domain,
				header_subject,
				header_message_id,
				additional_data
			) VALUES (
				%d,
				FROM_UNIXTIME(%d),
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
				'%s'
			)",
			$this->mta,
			$this->timestamp,
			$this->logType,
			mysql_real_escape_string($this->senderEmail, $this->conn),
			mysql_real_escape_string($this->senderEmailDomain, $this->conn),
			mysql_real_escape_string($this->remoteHost, $this->conn),
			mysql_real_escape_string($this->remoteHostDomain, $this->conn),
			mysql_real_escape_string($this->remoteIp, $this->conn),
			mysql_real_escape_string($this->eximMessageId, $this->conn),
			mysql_real_escape_string($this->recipientEmail, $this->conn),
			mysql_real_escape_string($this->recipientEmailDomain, $this->conn),
			mysql_real_escape_string($this->headerSubject, $this->conn),
			mysql_real_escape_string($this->headerMessageID, $this->conn),
			mysql_real_escape_string($this->additionalData, $this->conn));
		if (! mysql_query($sql, $this->conn)) {
			syslog(LOG_ERR, 'Failed to insert record: ' . mysql_error());
			die();
		}
	}
}

?>
