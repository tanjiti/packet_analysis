CREATE TABLE IF NOT EXISTS `ip_statistic_tuple` (
	`direct`	INTEGER DEFAULT -1,
	`ts`	INTEGER,
	`ip_protocol_type`	INTEGER DEFAULT -1,
	`src_ip`	TEXT,
	`dst_ip`	TEXT,
	`src_port`	INTEGER DEFAULT 0,
	`dst_port`	INTEGER DEFAULT 0,
	`packet_length`	INTEGER DEFAULT 0,
	`src_ip_geo`	TEXT,
	`dst_ip_geo`	TEXT,
	`src_port_service`	TEXT DEFAULT 'NONE',
	`dst_port_service`	TEXT DEFAULT 'NONE'
);