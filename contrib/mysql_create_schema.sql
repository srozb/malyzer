CREATE TABLE `sessions` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `machine_id` varchar(36) COLLATE utf8_polish_ci NOT NULL,
  `analysis_id` varchar(36) COLLATE utf8_polish_ci NOT NULL,
  `tag` varchar(128) COLLATE utf8_polish_ci DEFAULT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `version` varchar(32) COLLATE utf8_polish_ci DEFAULT NULL,
  `target` varchar(128) COLLATE utf8_polish_ci DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `analysis_id` (`analysis_id`)
) ENGINE=InnoDB AUTO_INCREMENT=36 DEFAULT CHARSET=utf8 COLLATE=utf8_polish_ci

CREATE TABLE `hooks` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `pid` int(10) unsigned NOT NULL,
  `tid` int(10) unsigned NOT NULL,
  `function` varchar(32) COLLATE utf8_polish_ci DEFAULT NULL,
  `payload` blob,
  `exact_param` varchar(128) COLLATE utf8_polish_ci DEFAULT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `session_id` int(11) NOT NULL,
  `category` varchar(25) COLLATE utf8_polish_ci DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `session_id` (`session_id`),
  CONSTRAINT `hooks_ibfk_1` FOREIGN KEY (`session_id`) REFERENCES `sessions` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=2752 DEFAULT CHARSET=utf8 COLLATE=utf8_polish_ci
