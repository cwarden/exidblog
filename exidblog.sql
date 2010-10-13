CREATE TABLE mta (
  id int(11) NOT NULL auto_increment,
  name varchar(50) NOT NULL default '',
  PRIMARY KEY  (id)
) TYPE=InnoDB;

CREATE TABLE log (
  id bigint(20) NOT NULL auto_increment,
  mta int(11) NOT NULL default '0',
  timestamp datetime NOT NULL default '0000-00-00 00:00:00',
  log_type enum('RECEIVED','DELIVERED','BOUNCED','REJECT_INVALID_SENDER','TEMP_REJECT_INVALID_SENDER','BLACKLISTED','MALWARE','SPAM','MIME_ERROR','BAD_ATTACHMENT','OTHER_TEMP_REJECT') default NULL,
  sender_email varchar(255) NOT NULL default '',
  sender_email_domain varchar(100) NOT NULL default '',
  remote_hostname varchar(255) default NULL,
  remote_hostname_domain varchar(100) default NULL,
  remote_ip varchar(15) default NULL,
  exim_message_id varchar(16) default NULL,
  recipient_email varchar(255) NOT NULL default '',
  recipient_email_domain varchar(100) NOT NULL default '',
  header_subject varchar(255) default NULL,
  header_message_id varchar(100) default NULL,
  additional_data varchar(100) default NULL,
  PRIMARY KEY  (id),
  KEY mta (mta),
  KEY exim_message_id (exim_message_id),
  KEY header_message_id (header_message_id),
  KEY idx_timestamp_type_rdomain_sdomain (timestamp,log_type,recipient_email_domain,sender_email_domain),
  KEY idx_timestamp_type_additional (timestamp,log_type,additional_data),
  KEY idx_timestamp_subject (timestamp,header_subject(25)),
  CONSTRAINT `0_151` FOREIGN KEY (`mta`) REFERENCES `mta` (`id`)
) TYPE=InnoDB;
