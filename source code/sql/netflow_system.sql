-- MySQL dump 10.11
--
-- Host: localhost    Database: netflow_system
-- ------------------------------------------------------
-- Server version	5.0.95

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `DRDoS_log`
--

DROP TABLE IF EXISTS `DRDoS_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `DRDoS_log` (
  `id` int(11) NOT NULL auto_increment,
  `datetime` datetime NOT NULL,
  `IP` varchar(50) character set utf8 NOT NULL,
  `port` int(11) NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=14 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `Dconn_log`
--

DROP TABLE IF EXISTS `Dconn_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `Dconn_log` (
  `IP` varchar(50) character set utf8 NOT NULL,
  `port` int(11) NOT NULL,
  `flows` int(11) NOT NULL,
  `last_updated` timestamp NOT NULL default CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `aflow_log`
--

DROP TABLE IF EXISTS `aflow_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `aflow_log` (
  `id` int(11) NOT NULL auto_increment,
  `datetime` datetime NOT NULL,
  `src_ip` varchar(50) character set latin1 NOT NULL,
  `dst_ip` varchar(50) character set latin1 NOT NULL,
  `dst_port` int(11) NOT NULL,
  `bytes` bigint(20) NOT NULL,
  `flows` int(11) NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=4 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `anomaly_log`
--

DROP TABLE IF EXISTS `anomaly_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `anomaly_log` (
  `id` int(11) NOT NULL auto_increment,
  `start_time` datetime default NULL,
  `stop_time` datetime default NULL,
  `event_type` varchar(50) default NULL,
  `src_ip` varchar(50) default NULL,
  `src_port` varchar(10) default NULL,
  `dst_ip` varchar(50) default NULL,
  `dst_port` varchar(10) default NULL,
  `attack_count` int(11) default NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `blacklist`
--

DROP TABLE IF EXISTS `blacklist`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `blacklist` (
  `IP` varchar(50) NOT NULL,
  `reason` varchar(50) NOT NULL,
  `last_updated` timestamp NOT NULL default CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP,
  UNIQUE KEY `IP` (`IP`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `blacklist_log`
--

DROP TABLE IF EXISTS `blacklist_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `blacklist_log` (
  `id` int(11) NOT NULL auto_increment,
  `src_ip` varchar(50) NOT NULL,
  `src_port` varchar(10) NOT NULL,
  `dst_ip` varchar(50) NOT NULL,
  `dst_port` varchar(10) NOT NULL,
  `date` datetime NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `event_statistics`
--

DROP TABLE IF EXISTS `event_statistics`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `event_statistics` (
  `id` int(11) NOT NULL auto_increment,
  `IP` varchar(50) NOT NULL,
  `source` varchar(50) NOT NULL,
  `warning` tinyint(1) NOT NULL,
  `last_attack` datetime NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `monIP_log`
--

DROP TABLE IF EXISTS `monIP_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `monIP_log` (
  `id` int(11) NOT NULL auto_increment,
  `source` varchar(50) NOT NULL,
  `srcport` varchar(10) NOT NULL,
  `target` varchar(50) NOT NULL,
  `dstport` varchar(10) NOT NULL,
  `date` datetime NOT NULL,
  PRIMARY KEY  (`source`,`target`,`dstport`),
  UNIQUE KEY `id` (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=14427 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `plots`
--

DROP TABLE IF EXISTS `plots`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `plots` (
  `id` int(11) NOT NULL auto_increment,
  `date` datetime NOT NULL,
  `flows` int(11) NOT NULL,
  `bytes` bigint(20) NOT NULL,
  `packets` int(11) NOT NULL,
  `identity` varchar(3) NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=65491 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `rules`
--

DROP TABLE IF EXISTS `rules`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `rules` (
  `id` int(11) NOT NULL,
  `event` varchar(20) NOT NULL,
  `threshold` int(11) NOT NULL,
  `suprathreshold` int(11) NOT NULL,
  `src_ip` varchar(5) NOT NULL,
  `src_port` varchar(5) NOT NULL,
  `dst_ip` varchar(5) NOT NULL,
  `dst_port` varchar(5) NOT NULL,
  UNIQUE KEY `event` (`event`),
  UNIQUE KEY `id` (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scan_log`
--

DROP TABLE IF EXISTS `scan_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `scan_log` (
  `id` int(11) NOT NULL auto_increment,
  `datetime` datetime NOT NULL,
  `src_ip` varchar(50) character set utf8 NOT NULL,
  `dst_port` varchar(10) character set utf8 NOT NULL,
  `count` int(11) NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=269 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `spam_log`
--

DROP TABLE IF EXISTS `spam_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `spam_log` (
  `id` int(11) NOT NULL auto_increment,
  `datetime` datetime NOT NULL,
  `IP` varchar(50) character set utf8 NOT NULL,
  `flows` int(11) NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=12 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tracklist`
--

DROP TABLE IF EXISTS `tracklist`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tracklist` (
  `start_time` datetime NOT NULL,
  `stop_time` datetime NOT NULL,
  `event_type` varchar(50) NOT NULL,
  `src_ip` varchar(50) NOT NULL,
  `src_port` varchar(10) NOT NULL,
  `dst_ip` varchar(50) NOT NULL,
  `dst_port` varchar(10) NOT NULL,
  `count` int(11) NOT NULL,
  `num` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `traffic`
--

DROP TABLE IF EXISTS `traffic`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `traffic` (
  `id` int(11) NOT NULL auto_increment,
  `srcip` varchar(50) NOT NULL,
  `srcport` varchar(10) NOT NULL,
  `dstip` varchar(50) NOT NULL,
  `dstport` varchar(10) NOT NULL,
  `proto` varchar(10) NOT NULL,
  `bytes` int(11) NOT NULL,
  `start_time` datetime NOT NULL,
  `stop_time` datetime NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=121474 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `unusedIP`
--

DROP TABLE IF EXISTS `unusedIP`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `unusedIP` (
  `IP` varchar(50) NOT NULL,
  `last_updated` timestamp NOT NULL default CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP,
  UNIQUE KEY `IP` (`IP`),
  UNIQUE KEY `IP_2` (`IP`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `whitelist`
--

DROP TABLE IF EXISTS `whitelist`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `whitelist` (
  `IP` varchar(50) NOT NULL,
  `DN` varchar(100) NOT NULL,
  `owner` varchar(50) NOT NULL,
  `last_updated` timestamp NOT NULL default CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP,
  UNIQUE KEY `IP` (`IP`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2015-06-14 15:03:16
