-- MySQL dump 10.13  Distrib 8.0.30, for macos12 (arm64)
--
-- Host: 124.221.91.143    Database: astar_questionnaire
-- ------------------------------------------------------
-- Server version	8.0.32

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `gen_table`
--

DROP TABLE IF EXISTS `gen_table`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `gen_table` (
                             `table_id` bigint NOT NULL AUTO_INCREMENT COMMENT '编号',
                             `table_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '表名称',
                             `table_comment` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '表描述',
                             `sub_table_name` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '关联子表的表名',
                             `sub_table_fk_name` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '子表关联的外键名',
                             `class_name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '实体类名称',
                             `tpl_category` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT 'crud' COMMENT '使用的模板（crud单表操作 tree树表操作）',
                             `tpl_web_type` varchar(30) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '前端模板类型（element-ui模版 element-plus模版）',
                             `package_name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '生成包路径',
                             `module_name` varchar(30) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '生成模块名',
                             `business_name` varchar(30) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '生成业务名',
                             `function_name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '生成功能名',
                             `function_author` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '生成功能作者',
                             `gen_type` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '0' COMMENT '生成代码方式（0zip压缩包 1自定义路径）',
                             `gen_path` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '/' COMMENT '生成路径（不填默认项目路径）',
                             `options` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '其它生成选项',
                             `create_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '创建者',
                             `create_time` datetime DEFAULT NULL COMMENT '创建时间',
                             `update_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '更新者',
                             `update_time` datetime DEFAULT NULL COMMENT '更新时间',
                             `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '备注',
                             PRIMARY KEY (`table_id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='代码生成业务表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `gen_table`
--

LOCK TABLES `gen_table` WRITE;
/*!40000 ALTER TABLE `gen_table` DISABLE KEYS */;
INSERT INTO `gen_table` (`table_id`, `table_name`, `table_comment`, `sub_table_name`, `sub_table_fk_name`, `class_name`, `tpl_category`, `tpl_web_type`, `package_name`, `module_name`, `business_name`, `function_name`, `function_author`, `gen_type`, `gen_path`, `options`, `create_by`, `create_time`, `update_by`, `update_time`, `remark`) VALUES (3,'tb_questionnaire_user','填写问卷管理',NULL,NULL,'TbQuestionnaireUser','crud','','com.astar.system','system','user','填写问卷管理','astar','0','/',NULL,'admin','2024-03-02 20:57:25','',NULL,NULL);
/*!40000 ALTER TABLE `gen_table` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `gen_table_column`
--

DROP TABLE IF EXISTS `gen_table_column`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `gen_table_column` (
                                    `column_id` bigint NOT NULL AUTO_INCREMENT COMMENT '编号',
                                    `table_id` bigint DEFAULT NULL COMMENT '归属表编号',
                                    `column_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '列名称',
                                    `column_comment` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '列描述',
                                    `column_type` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '列类型',
                                    `java_type` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT 'JAVA类型',
                                    `java_field` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT 'JAVA字段名',
                                    `is_pk` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '是否主键（1是）',
                                    `is_increment` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '是否自增（1是）',
                                    `is_required` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '是否必填（1是）',
                                    `is_insert` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '是否为插入字段（1是）',
                                    `is_edit` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '是否编辑字段（1是）',
                                    `is_list` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '是否列表字段（1是）',
                                    `is_query` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '是否查询字段（1是）',
                                    `query_type` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT 'EQ' COMMENT '查询方式（等于、不等于、大于、小于、范围）',
                                    `html_type` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '显示类型（文本框、文本域、下拉框、复选框、单选框、日期控件）',
                                    `dict_type` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '字典类型',
                                    `sort` int DEFAULT NULL COMMENT '排序',
                                    `create_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '创建者',
                                    `create_time` datetime DEFAULT NULL COMMENT '创建时间',
                                    `update_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '更新者',
                                    `update_time` datetime DEFAULT NULL COMMENT '更新时间',
                                    PRIMARY KEY (`column_id`)
) ENGINE=InnoDB AUTO_INCREMENT=18 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='代码生成业务表字段';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `gen_table_column`
--

LOCK TABLES `gen_table_column` WRITE;
/*!40000 ALTER TABLE `gen_table_column` DISABLE KEYS */;
INSERT INTO `gen_table_column` (`column_id`, `table_id`, `column_name`, `column_comment`, `column_type`, `java_type`, `java_field`, `is_pk`, `is_increment`, `is_required`, `is_insert`, `is_edit`, `is_list`, `is_query`, `query_type`, `html_type`, `dict_type`, `sort`, `create_by`, `create_time`, `update_by`, `update_time`) VALUES (1,1,'id','主键','int','Long','id','1','1','0','1',NULL,NULL,NULL,'EQ','input','',1,'admin','2024-03-01 23:13:01','',NULL),(2,1,'created_time','创建时间','datetime','Date','createdTime','0','0','0','1','1','1','1','EQ','datetime','',2,'admin','2024-03-01 23:13:01','',NULL),(3,1,'created_by','创建人','varchar(64)','String','createdBy','0','0','0','1','1','1','1','EQ','input','',3,'admin','2024-03-01 23:13:01','',NULL),(4,1,'updated_time','更新时间','datetime','Date','updatedTime','0','0','0','1','1','1','1','EQ','datetime','',4,'admin','2024-03-01 23:13:01','',NULL),(5,1,'updated_by','更新人','varchar(64)','String','updatedBy','0','0','0','1','1','1','1','EQ','input','',5,'admin','2024-03-01 23:13:01','',NULL),(6,1,'title','标题','varchar(255)','String','title','0','0','0','1','1','1','1','EQ','input','',6,'admin','2024-03-01 23:13:01','',NULL),(7,1,'form_json','表单配置','json','String','formJson','0','0','0','1','1','1','1','EQ',NULL,'',7,'admin','2024-03-01 23:13:01','',NULL),(8,1,'form_url','表单地址','varchar(255)','String','formUrl','0','0','0','1','1','1','1','EQ','input','',8,'admin','2024-03-01 23:13:01','',NULL),(9,1,'status','表单状态：false未发布，true已发布','tinyint','Long','status','0','0','0','1','1','1','1','EQ','radio','',9,'admin','2024-03-01 23:13:01','',NULL),(10,2,'id','主键','int','Long','id','1','1','0','1',NULL,NULL,NULL,'EQ','input','',1,'admin','2024-03-01 23:13:01','',NULL),(11,2,'created_time','创建时间','datetime','Date','createdTime','0','0','0','1','1','1','1','EQ','datetime','',2,'admin','2024-03-01 23:13:01','',NULL),(12,2,'data_json','表单配置','json','String','dataJson','0','0','0','1','1','1','1','EQ',NULL,'',3,'admin','2024-03-01 23:13:01','',NULL),(13,3,'id','主键','int','Long','id','1','1','0','1',NULL,NULL,NULL,'EQ','input','',1,'admin','2024-03-02 20:57:25','',NULL),(14,3,'created_time','创建时间','datetime','Date','createdTime','0','0','0','1','1','1','1','EQ','datetime','',2,'admin','2024-03-02 20:57:25','',NULL),(15,3,'qs_id','问卷ID','int','Long','qsId','0','0','0','1','1','1','1','EQ','input','',3,'admin','2024-03-02 20:57:25','',NULL),(16,3,'data_json','表单配置','json','String','dataJson','0','0','0','1','1','1','1','EQ',NULL,'',4,'admin','2024-03-02 20:57:25','',NULL),(17,3,'ip_addr','ip','varchar(255)','String','ipAddr','0','0','0','1','1','1','1','EQ','input','',5,'admin','2024-03-02 20:57:25','',NULL);
/*!40000 ALTER TABLE `gen_table_column` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `qrtz_blob_triggers`
--

DROP TABLE IF EXISTS `qrtz_blob_triggers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `qrtz_blob_triggers` (
                                      `sched_name` varchar(120) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '调度名称',
                                      `trigger_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'qrtz_triggers表trigger_name的外键',
                                      `trigger_group` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'qrtz_triggers表trigger_group的外键',
                                      `blob_data` blob COMMENT '存放持久化Trigger对象',
                                      PRIMARY KEY (`sched_name`,`trigger_name`,`trigger_group`),
                                      CONSTRAINT `qrtz_blob_triggers_ibfk_1` FOREIGN KEY (`sched_name`, `trigger_name`, `trigger_group`) REFERENCES `qrtz_triggers` (`sched_name`, `trigger_name`, `trigger_group`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='Blob类型的触发器表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `qrtz_blob_triggers`
--

LOCK TABLES `qrtz_blob_triggers` WRITE;
/*!40000 ALTER TABLE `qrtz_blob_triggers` DISABLE KEYS */;
/*!40000 ALTER TABLE `qrtz_blob_triggers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `qrtz_calendars`
--

DROP TABLE IF EXISTS `qrtz_calendars`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `qrtz_calendars` (
                                  `sched_name` varchar(120) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '调度名称',
                                  `calendar_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '日历名称',
                                  `calendar` blob NOT NULL COMMENT '存放持久化calendar对象',
                                  PRIMARY KEY (`sched_name`,`calendar_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='日历信息表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `qrtz_calendars`
--

LOCK TABLES `qrtz_calendars` WRITE;
/*!40000 ALTER TABLE `qrtz_calendars` DISABLE KEYS */;
/*!40000 ALTER TABLE `qrtz_calendars` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `qrtz_cron_triggers`
--

DROP TABLE IF EXISTS `qrtz_cron_triggers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `qrtz_cron_triggers` (
                                      `sched_name` varchar(120) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '调度名称',
                                      `trigger_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'qrtz_triggers表trigger_name的外键',
                                      `trigger_group` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'qrtz_triggers表trigger_group的外键',
                                      `cron_expression` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'cron表达式',
                                      `time_zone_id` varchar(80) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '时区',
                                      PRIMARY KEY (`sched_name`,`trigger_name`,`trigger_group`),
                                      CONSTRAINT `qrtz_cron_triggers_ibfk_1` FOREIGN KEY (`sched_name`, `trigger_name`, `trigger_group`) REFERENCES `qrtz_triggers` (`sched_name`, `trigger_name`, `trigger_group`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='Cron类型的触发器表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `qrtz_cron_triggers`
--

LOCK TABLES `qrtz_cron_triggers` WRITE;
/*!40000 ALTER TABLE `qrtz_cron_triggers` DISABLE KEYS */;
/*!40000 ALTER TABLE `qrtz_cron_triggers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `qrtz_fired_triggers`
--

DROP TABLE IF EXISTS `qrtz_fired_triggers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `qrtz_fired_triggers` (
                                       `sched_name` varchar(120) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '调度名称',
                                       `entry_id` varchar(95) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '调度器实例id',
                                       `trigger_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'qrtz_triggers表trigger_name的外键',
                                       `trigger_group` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'qrtz_triggers表trigger_group的外键',
                                       `instance_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '调度器实例名',
                                       `fired_time` bigint NOT NULL COMMENT '触发的时间',
                                       `sched_time` bigint NOT NULL COMMENT '定时器制定的时间',
                                       `priority` int NOT NULL COMMENT '优先级',
                                       `state` varchar(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '状态',
                                       `job_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '任务名称',
                                       `job_group` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '任务组名',
                                       `is_nonconcurrent` varchar(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '是否并发',
                                       `requests_recovery` varchar(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '是否接受恢复执行',
                                       PRIMARY KEY (`sched_name`,`entry_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='已触发的触发器表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `qrtz_fired_triggers`
--

LOCK TABLES `qrtz_fired_triggers` WRITE;
/*!40000 ALTER TABLE `qrtz_fired_triggers` DISABLE KEYS */;
/*!40000 ALTER TABLE `qrtz_fired_triggers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `qrtz_job_details`
--

DROP TABLE IF EXISTS `qrtz_job_details`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `qrtz_job_details` (
                                    `sched_name` varchar(120) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '调度名称',
                                    `job_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '任务名称',
                                    `job_group` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '任务组名',
                                    `description` varchar(250) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '相关介绍',
                                    `job_class_name` varchar(250) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '执行任务类名称',
                                    `is_durable` varchar(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '是否持久化',
                                    `is_nonconcurrent` varchar(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '是否并发',
                                    `is_update_data` varchar(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '是否更新数据',
                                    `requests_recovery` varchar(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '是否接受恢复执行',
                                    `job_data` blob COMMENT '存放持久化job对象',
                                    PRIMARY KEY (`sched_name`,`job_name`,`job_group`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='任务详细信息表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `qrtz_job_details`
--

LOCK TABLES `qrtz_job_details` WRITE;
/*!40000 ALTER TABLE `qrtz_job_details` DISABLE KEYS */;
/*!40000 ALTER TABLE `qrtz_job_details` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `qrtz_locks`
--

DROP TABLE IF EXISTS `qrtz_locks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `qrtz_locks` (
                              `sched_name` varchar(120) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '调度名称',
                              `lock_name` varchar(40) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '悲观锁名称',
                              PRIMARY KEY (`sched_name`,`lock_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='存储的悲观锁信息表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `qrtz_locks`
--

LOCK TABLES `qrtz_locks` WRITE;
/*!40000 ALTER TABLE `qrtz_locks` DISABLE KEYS */;
/*!40000 ALTER TABLE `qrtz_locks` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `qrtz_paused_trigger_grps`
--

DROP TABLE IF EXISTS `qrtz_paused_trigger_grps`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `qrtz_paused_trigger_grps` (
                                            `sched_name` varchar(120) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '调度名称',
                                            `trigger_group` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'qrtz_triggers表trigger_group的外键',
                                            PRIMARY KEY (`sched_name`,`trigger_group`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='暂停的触发器表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `qrtz_paused_trigger_grps`
--

LOCK TABLES `qrtz_paused_trigger_grps` WRITE;
/*!40000 ALTER TABLE `qrtz_paused_trigger_grps` DISABLE KEYS */;
/*!40000 ALTER TABLE `qrtz_paused_trigger_grps` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `qrtz_scheduler_state`
--

DROP TABLE IF EXISTS `qrtz_scheduler_state`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `qrtz_scheduler_state` (
                                        `sched_name` varchar(120) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '调度名称',
                                        `instance_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '实例名称',
                                        `last_checkin_time` bigint NOT NULL COMMENT '上次检查时间',
                                        `checkin_interval` bigint NOT NULL COMMENT '检查间隔时间',
                                        PRIMARY KEY (`sched_name`,`instance_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='调度器状态表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `qrtz_scheduler_state`
--

LOCK TABLES `qrtz_scheduler_state` WRITE;
/*!40000 ALTER TABLE `qrtz_scheduler_state` DISABLE KEYS */;
/*!40000 ALTER TABLE `qrtz_scheduler_state` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `qrtz_simple_triggers`
--

DROP TABLE IF EXISTS `qrtz_simple_triggers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `qrtz_simple_triggers` (
                                        `sched_name` varchar(120) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '调度名称',
                                        `trigger_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'qrtz_triggers表trigger_name的外键',
                                        `trigger_group` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'qrtz_triggers表trigger_group的外键',
                                        `repeat_count` bigint NOT NULL COMMENT '重复的次数统计',
                                        `repeat_interval` bigint NOT NULL COMMENT '重复的间隔时间',
                                        `times_triggered` bigint NOT NULL COMMENT '已经触发的次数',
                                        PRIMARY KEY (`sched_name`,`trigger_name`,`trigger_group`),
                                        CONSTRAINT `qrtz_simple_triggers_ibfk_1` FOREIGN KEY (`sched_name`, `trigger_name`, `trigger_group`) REFERENCES `qrtz_triggers` (`sched_name`, `trigger_name`, `trigger_group`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='简单触发器的信息表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `qrtz_simple_triggers`
--

LOCK TABLES `qrtz_simple_triggers` WRITE;
/*!40000 ALTER TABLE `qrtz_simple_triggers` DISABLE KEYS */;
/*!40000 ALTER TABLE `qrtz_simple_triggers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `qrtz_simprop_triggers`
--

DROP TABLE IF EXISTS `qrtz_simprop_triggers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `qrtz_simprop_triggers` (
                                         `sched_name` varchar(120) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '调度名称',
                                         `trigger_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'qrtz_triggers表trigger_name的外键',
                                         `trigger_group` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'qrtz_triggers表trigger_group的外键',
                                         `str_prop_1` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT 'String类型的trigger的第一个参数',
                                         `str_prop_2` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT 'String类型的trigger的第二个参数',
                                         `str_prop_3` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT 'String类型的trigger的第三个参数',
                                         `int_prop_1` int DEFAULT NULL COMMENT 'int类型的trigger的第一个参数',
                                         `int_prop_2` int DEFAULT NULL COMMENT 'int类型的trigger的第二个参数',
                                         `long_prop_1` bigint DEFAULT NULL COMMENT 'long类型的trigger的第一个参数',
                                         `long_prop_2` bigint DEFAULT NULL COMMENT 'long类型的trigger的第二个参数',
                                         `dec_prop_1` decimal(13,4) DEFAULT NULL COMMENT 'decimal类型的trigger的第一个参数',
                                         `dec_prop_2` decimal(13,4) DEFAULT NULL COMMENT 'decimal类型的trigger的第二个参数',
                                         `bool_prop_1` varchar(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT 'Boolean类型的trigger的第一个参数',
                                         `bool_prop_2` varchar(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT 'Boolean类型的trigger的第二个参数',
                                         PRIMARY KEY (`sched_name`,`trigger_name`,`trigger_group`),
                                         CONSTRAINT `qrtz_simprop_triggers_ibfk_1` FOREIGN KEY (`sched_name`, `trigger_name`, `trigger_group`) REFERENCES `qrtz_triggers` (`sched_name`, `trigger_name`, `trigger_group`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='同步机制的行锁表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `qrtz_simprop_triggers`
--

LOCK TABLES `qrtz_simprop_triggers` WRITE;
/*!40000 ALTER TABLE `qrtz_simprop_triggers` DISABLE KEYS */;
/*!40000 ALTER TABLE `qrtz_simprop_triggers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `qrtz_triggers`
--

DROP TABLE IF EXISTS `qrtz_triggers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `qrtz_triggers` (
                                 `sched_name` varchar(120) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '调度名称',
                                 `trigger_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '触发器的名字',
                                 `trigger_group` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '触发器所属组的名字',
                                 `job_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'qrtz_job_details表job_name的外键',
                                 `job_group` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'qrtz_job_details表job_group的外键',
                                 `description` varchar(250) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '相关介绍',
                                 `next_fire_time` bigint DEFAULT NULL COMMENT '上一次触发时间（毫秒）',
                                 `prev_fire_time` bigint DEFAULT NULL COMMENT '下一次触发时间（默认为-1表示不触发）',
                                 `priority` int DEFAULT NULL COMMENT '优先级',
                                 `trigger_state` varchar(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '触发器状态',
                                 `trigger_type` varchar(8) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '触发器的类型',
                                 `start_time` bigint NOT NULL COMMENT '开始时间',
                                 `end_time` bigint DEFAULT NULL COMMENT '结束时间',
                                 `calendar_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '日程表名称',
                                 `misfire_instr` smallint DEFAULT NULL COMMENT '补偿执行的策略',
                                 `job_data` blob COMMENT '存放持久化job对象',
                                 PRIMARY KEY (`sched_name`,`trigger_name`,`trigger_group`),
                                 KEY `sched_name` (`sched_name`,`job_name`,`job_group`),
                                 CONSTRAINT `qrtz_triggers_ibfk_1` FOREIGN KEY (`sched_name`, `job_name`, `job_group`) REFERENCES `qrtz_job_details` (`sched_name`, `job_name`, `job_group`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='触发器详细信息表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `qrtz_triggers`
--

LOCK TABLES `qrtz_triggers` WRITE;
/*!40000 ALTER TABLE `qrtz_triggers` DISABLE KEYS */;
/*!40000 ALTER TABLE `qrtz_triggers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sys_config`
--

DROP TABLE IF EXISTS `sys_config`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sys_config` (
                              `config_id` int NOT NULL AUTO_INCREMENT COMMENT '参数主键',
                              `config_name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '参数名称',
                              `config_key` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '参数键名',
                              `config_value` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '参数键值',
                              `config_type` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT 'N' COMMENT '系统内置（Y是 N否）',
                              `create_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '创建者',
                              `create_time` datetime DEFAULT NULL COMMENT '创建时间',
                              `update_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '更新者',
                              `update_time` datetime DEFAULT NULL COMMENT '更新时间',
                              `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '备注',
                              PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=100 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='参数配置表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sys_config`
--

LOCK TABLES `sys_config` WRITE;
/*!40000 ALTER TABLE `sys_config` DISABLE KEYS */;
INSERT INTO `sys_config` (`config_id`, `config_name`, `config_key`, `config_value`, `config_type`, `create_by`, `create_time`, `update_by`, `update_time`, `remark`) VALUES (1,'主框架页-默认皮肤样式名称','sys.index.skinName','skin-blue','Y','admin','2024-03-01 19:39:39','',NULL,'蓝色 skin-blue、绿色 skin-green、紫色 skin-purple、红色 skin-red、黄色 skin-yellow'),(2,'用户管理-账号初始密码','sys.user.initPassword','123456','Y','admin','2024-03-01 19:39:39','',NULL,'初始化密码 123456'),(3,'主框架页-侧边栏主题','sys.index.sideTheme','theme-dark','Y','admin','2024-03-01 19:39:39','',NULL,'深色主题theme-dark，浅色主题theme-light'),(4,'账号自助-验证码开关','sys.account.captchaEnabled','true','Y','admin','2024-03-01 19:39:39','',NULL,'是否开启验证码功能（true开启，false关闭）'),(5,'账号自助-是否开启用户注册功能','sys.account.registerUser','true','Y','admin','2024-03-01 19:39:39','admin','2024-03-02 10:41:37','是否开启注册用户功能（true开启，false关闭）'),(6,'用户登录-黑名单列表','sys.login.blackIPList','','Y','admin','2024-03-01 19:39:40','',NULL,'设置登录IP黑名单限制，多个匹配项以;分隔，支持匹配（*通配、网段）');
/*!40000 ALTER TABLE `sys_config` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sys_dept`
--

DROP TABLE IF EXISTS `sys_dept`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sys_dept` (
                            `dept_id` bigint NOT NULL AUTO_INCREMENT COMMENT '部门id',
                            `parent_id` bigint DEFAULT '0' COMMENT '父部门id',
                            `ancestors` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '祖级列表',
                            `dept_name` varchar(30) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '部门名称',
                            `order_num` int DEFAULT '0' COMMENT '显示顺序',
                            `leader` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '负责人',
                            `phone` varchar(11) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '联系电话',
                            `email` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '邮箱',
                            `status` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '0' COMMENT '部门状态（0正常 1停用）',
                            `del_flag` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '0' COMMENT '删除标志（0代表存在 2代表删除）',
                            `create_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '创建者',
                            `create_time` datetime DEFAULT NULL COMMENT '创建时间',
                            `update_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '更新者',
                            `update_time` datetime DEFAULT NULL COMMENT '更新时间',
                            PRIMARY KEY (`dept_id`)
) ENGINE=InnoDB AUTO_INCREMENT=200 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='部门表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sys_dept`
--

LOCK TABLES `sys_dept` WRITE;
/*!40000 ALTER TABLE `sys_dept` DISABLE KEYS */;
INSERT INTO `sys_dept` (`dept_id`, `parent_id`, `ancestors`, `dept_name`, `order_num`, `leader`, `phone`, `email`, `status`, `del_flag`, `create_by`, `create_time`, `update_by`, `update_time`) VALUES (100,0,'0','一颗星',0,'一颗星','15555555555','','0','0','admin','2024-03-01 19:39:37','admin','2024-03-02 19:00:12'),(101,100,'0,100','北京总部',1,'一颗星','15888888888','astar@qq.com','0','0','admin','2024-03-01 19:39:37','admin','2024-03-02 19:00:33'),(102,100,'0,100','长沙分公司',2,'一颗星','15888888888','ry@qq.com','0','2','admin','2024-03-01 19:39:37','',NULL),(103,101,'0,100,101','研发部门',1,'一颗星','15888888888','astar@qq.com','0','0','admin','2024-03-01 19:39:37','admin','2024-03-02 19:00:42'),(104,101,'0,100,101','市场部门',2,'一颗星','15888888888','ry@qq.com','0','2','admin','2024-03-01 19:39:37','',NULL),(105,101,'0,100,101','测试部门',3,'一颗星','15888888888','ry@qq.com','0','2','admin','2024-03-01 19:39:37','',NULL),(106,101,'0,100,101','财务部门',4,'一颗星','15888888888','ry@qq.com','0','2','admin','2024-03-01 19:39:37','',NULL),(107,101,'0,100,101','运维部门',5,'一颗星','15888888888','ry@qq.com','0','2','admin','2024-03-01 19:39:37','',NULL),(108,102,'0,100,102','市场部门',1,'一颗星','15888888888','ry@qq.com','0','2','admin','2024-03-01 19:39:37','',NULL),(109,102,'0,100,102','财务部门',2,'一颗星','15888888888','ry@qq.com','0','2','admin','2024-03-01 19:39:37','',NULL);
/*!40000 ALTER TABLE `sys_dept` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sys_dict_data`
--

DROP TABLE IF EXISTS `sys_dict_data`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sys_dict_data` (
                                 `dict_code` bigint NOT NULL AUTO_INCREMENT COMMENT '字典编码',
                                 `dict_sort` int DEFAULT '0' COMMENT '字典排序',
                                 `dict_label` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '字典标签',
                                 `dict_value` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '字典键值',
                                 `dict_type` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '字典类型',
                                 `css_class` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '样式属性（其他样式扩展）',
                                 `list_class` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '表格回显样式',
                                 `is_default` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT 'N' COMMENT '是否默认（Y是 N否）',
                                 `status` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '0' COMMENT '状态（0正常 1停用）',
                                 `create_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '创建者',
                                 `create_time` datetime DEFAULT NULL COMMENT '创建时间',
                                 `update_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '更新者',
                                 `update_time` datetime DEFAULT NULL COMMENT '更新时间',
                                 `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '备注',
                                 PRIMARY KEY (`dict_code`)
) ENGINE=InnoDB AUTO_INCREMENT=100 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='字典数据表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sys_dict_data`
--

LOCK TABLES `sys_dict_data` WRITE;
/*!40000 ALTER TABLE `sys_dict_data` DISABLE KEYS */;
INSERT INTO `sys_dict_data` (`dict_code`, `dict_sort`, `dict_label`, `dict_value`, `dict_type`, `css_class`, `list_class`, `is_default`, `status`, `create_by`, `create_time`, `update_by`, `update_time`, `remark`) VALUES (1,1,'男','0','sys_user_sex','','','Y','0','admin','2024-03-01 19:39:39','',NULL,'性别男'),(2,2,'女','1','sys_user_sex','','','N','0','admin','2024-03-01 19:39:39','',NULL,'性别女'),(3,3,'未知','2','sys_user_sex','','','N','0','admin','2024-03-01 19:39:39','',NULL,'性别未知'),(4,1,'显示','0','sys_show_hide','','primary','Y','0','admin','2024-03-01 19:39:39','',NULL,'显示菜单'),(5,2,'隐藏','1','sys_show_hide','','danger','N','0','admin','2024-03-01 19:39:39','',NULL,'隐藏菜单'),(6,1,'正常','0','sys_normal_disable','','primary','Y','0','admin','2024-03-01 19:39:39','',NULL,'正常状态'),(7,2,'停用','1','sys_normal_disable','','danger','N','0','admin','2024-03-01 19:39:39','',NULL,'停用状态'),(8,1,'正常','0','sys_job_status','','primary','Y','0','admin','2024-03-01 19:39:39','',NULL,'正常状态'),(9,2,'暂停','1','sys_job_status','','danger','N','0','admin','2024-03-01 19:39:39','',NULL,'停用状态'),(10,1,'默认','DEFAULT','sys_job_group','','','Y','0','admin','2024-03-01 19:39:39','',NULL,'默认分组'),(11,2,'系统','SYSTEM','sys_job_group','','','N','0','admin','2024-03-01 19:39:39','',NULL,'系统分组'),(12,1,'是','Y','sys_yes_no','','primary','Y','0','admin','2024-03-01 19:39:39','',NULL,'系统默认是'),(13,2,'否','N','sys_yes_no','','danger','N','0','admin','2024-03-01 19:39:39','',NULL,'系统默认否'),(14,1,'通知','1','sys_notice_type','','warning','Y','0','admin','2024-03-01 19:39:39','',NULL,'通知'),(15,2,'公告','2','sys_notice_type','','success','N','0','admin','2024-03-01 19:39:39','',NULL,'公告'),(16,1,'正常','0','sys_notice_status','','primary','Y','0','admin','2024-03-01 19:39:39','',NULL,'正常状态'),(17,2,'关闭','1','sys_notice_status','','danger','N','0','admin','2024-03-01 19:39:39','',NULL,'关闭状态'),(18,99,'其他','0','sys_oper_type','','info','N','0','admin','2024-03-01 19:39:39','',NULL,'其他操作'),(19,1,'新增','1','sys_oper_type','','info','N','0','admin','2024-03-01 19:39:39','',NULL,'新增操作'),(20,2,'修改','2','sys_oper_type','','info','N','0','admin','2024-03-01 19:39:39','',NULL,'修改操作'),(21,3,'删除','3','sys_oper_type','','danger','N','0','admin','2024-03-01 19:39:39','',NULL,'删除操作'),(22,4,'授权','4','sys_oper_type','','primary','N','0','admin','2024-03-01 19:39:39','',NULL,'授权操作'),(23,5,'导出','5','sys_oper_type','','warning','N','0','admin','2024-03-01 19:39:39','',NULL,'导出操作'),(24,6,'导入','6','sys_oper_type','','warning','N','0','admin','2024-03-01 19:39:39','',NULL,'导入操作'),(25,7,'强退','7','sys_oper_type','','danger','N','0','admin','2024-03-01 19:39:39','',NULL,'强退操作'),(26,8,'生成代码','8','sys_oper_type','','warning','N','0','admin','2024-03-01 19:39:39','',NULL,'生成操作'),(27,9,'清空数据','9','sys_oper_type','','danger','N','0','admin','2024-03-01 19:39:39','',NULL,'清空操作'),(28,1,'成功','0','sys_common_status','','primary','N','0','admin','2024-03-01 19:39:39','',NULL,'正常状态'),(29,2,'失败','1','sys_common_status','','danger','N','0','admin','2024-03-01 19:39:39','',NULL,'停用状态');
/*!40000 ALTER TABLE `sys_dict_data` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sys_dict_type`
--

DROP TABLE IF EXISTS `sys_dict_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sys_dict_type` (
                                 `dict_id` bigint NOT NULL AUTO_INCREMENT COMMENT '字典主键',
                                 `dict_name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '字典名称',
                                 `dict_type` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '字典类型',
                                 `status` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '0' COMMENT '状态（0正常 1停用）',
                                 `create_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '创建者',
                                 `create_time` datetime DEFAULT NULL COMMENT '创建时间',
                                 `update_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '更新者',
                                 `update_time` datetime DEFAULT NULL COMMENT '更新时间',
                                 `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '备注',
                                 PRIMARY KEY (`dict_id`),
                                 UNIQUE KEY `dict_type` (`dict_type`)
) ENGINE=InnoDB AUTO_INCREMENT=100 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='字典类型表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sys_dict_type`
--

LOCK TABLES `sys_dict_type` WRITE;
/*!40000 ALTER TABLE `sys_dict_type` DISABLE KEYS */;
INSERT INTO `sys_dict_type` (`dict_id`, `dict_name`, `dict_type`, `status`, `create_by`, `create_time`, `update_by`, `update_time`, `remark`) VALUES (1,'用户性别','sys_user_sex','0','admin','2024-03-01 19:39:39','',NULL,'用户性别列表'),(2,'菜单状态','sys_show_hide','0','admin','2024-03-01 19:39:39','',NULL,'菜单状态列表'),(3,'系统开关','sys_normal_disable','0','admin','2024-03-01 19:39:39','',NULL,'系统开关列表'),(4,'任务状态','sys_job_status','0','admin','2024-03-01 19:39:39','',NULL,'任务状态列表'),(5,'任务分组','sys_job_group','0','admin','2024-03-01 19:39:39','',NULL,'任务分组列表'),(6,'系统是否','sys_yes_no','0','admin','2024-03-01 19:39:39','',NULL,'系统是否列表'),(7,'通知类型','sys_notice_type','0','admin','2024-03-01 19:39:39','',NULL,'通知类型列表'),(8,'通知状态','sys_notice_status','0','admin','2024-03-01 19:39:39','',NULL,'通知状态列表'),(9,'操作类型','sys_oper_type','0','admin','2024-03-01 19:39:39','',NULL,'操作类型列表'),(10,'系统状态','sys_common_status','0','admin','2024-03-01 19:39:39','',NULL,'登录状态列表');
/*!40000 ALTER TABLE `sys_dict_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sys_job`
--

DROP TABLE IF EXISTS `sys_job`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sys_job` (
                           `job_id` bigint NOT NULL AUTO_INCREMENT COMMENT '任务ID',
                           `job_name` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL DEFAULT '' COMMENT '任务名称',
                           `job_group` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL DEFAULT 'DEFAULT' COMMENT '任务组名',
                           `invoke_target` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '调用目标字符串',
                           `cron_expression` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT 'cron执行表达式',
                           `misfire_policy` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '3' COMMENT '计划执行错误策略（1立即执行 2执行一次 3放弃执行）',
                           `concurrent` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '1' COMMENT '是否并发执行（0允许 1禁止）',
                           `status` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '0' COMMENT '状态（0正常 1暂停）',
                           `create_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '创建者',
                           `create_time` datetime DEFAULT NULL COMMENT '创建时间',
                           `update_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '更新者',
                           `update_time` datetime DEFAULT NULL COMMENT '更新时间',
                           `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '备注信息',
                           PRIMARY KEY (`job_id`,`job_name`,`job_group`)
) ENGINE=InnoDB AUTO_INCREMENT=100 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='定时任务调度表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sys_job`
--

LOCK TABLES `sys_job` WRITE;
/*!40000 ALTER TABLE `sys_job` DISABLE KEYS */;
INSERT INTO `sys_job` (`job_id`, `job_name`, `job_group`, `invoke_target`, `cron_expression`, `misfire_policy`, `concurrent`, `status`, `create_by`, `create_time`, `update_by`, `update_time`, `remark`) VALUES (1,'系统默认（无参）','DEFAULT','ryTask.ryNoParams','0/10 * * * * ?','3','1','1','admin','2024-03-01 19:39:40','',NULL,''),(2,'系统默认（有参）','DEFAULT','ryTask.ryParams(\'ry\')','0/15 * * * * ?','3','1','1','admin','2024-03-01 19:39:40','',NULL,''),(3,'系统默认（多参）','DEFAULT','ryTask.ryMultipleParams(\'ry\', true, 2000L, 316.50D, 100)','0/20 * * * * ?','3','1','1','admin','2024-03-01 19:39:40','',NULL,'');
/*!40000 ALTER TABLE `sys_job` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sys_job_log`
--

DROP TABLE IF EXISTS `sys_job_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sys_job_log` (
                               `job_log_id` bigint NOT NULL AUTO_INCREMENT COMMENT '任务日志ID',
                               `job_name` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '任务名称',
                               `job_group` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '任务组名',
                               `invoke_target` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '调用目标字符串',
                               `job_message` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '日志信息',
                               `status` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '0' COMMENT '执行状态（0正常 1失败）',
                               `exception_info` varchar(2000) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '异常信息',
                               `create_time` datetime DEFAULT NULL COMMENT '创建时间',
                               PRIMARY KEY (`job_log_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='定时任务调度日志表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sys_job_log`
--

LOCK TABLES `sys_job_log` WRITE;
/*!40000 ALTER TABLE `sys_job_log` DISABLE KEYS */;
/*!40000 ALTER TABLE `sys_job_log` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sys_logininfor`
--

DROP TABLE IF EXISTS `sys_logininfor`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sys_logininfor` (
                                  `info_id` bigint NOT NULL AUTO_INCREMENT COMMENT '访问ID',
                                  `user_name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '用户账号',
                                  `ipaddr` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '登录IP地址',
                                  `login_location` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '登录地点',
                                  `browser` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '浏览器类型',
                                  `os` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '操作系统',
                                  `status` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '0' COMMENT '登录状态（0成功 1失败）',
                                  `msg` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '提示消息',
                                  `login_time` datetime DEFAULT NULL COMMENT '访问时间',
                                  PRIMARY KEY (`info_id`),
                                  KEY `idx_sys_logininfor_s` (`status`),
                                  KEY `idx_sys_logininfor_lt` (`login_time`)
) ENGINE=InnoDB AUTO_INCREMENT=154 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='系统访问记录';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sys_logininfor`
--

LOCK TABLES `sys_logininfor` WRITE;
/*!40000 ALTER TABLE `sys_logininfor` DISABLE KEYS */;
INSERT INTO `sys_logininfor` (`info_id`, `user_name`, `ipaddr`, `login_location`, `browser`, `os`, `status`, `msg`, `login_time`) VALUES (100,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','登录成功','2024-03-01 19:47:43'),(101,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','登录成功','2024-03-01 21:36:59'),(102,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','登录成功','2024-03-01 23:11:13'),(103,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','登录成功','2024-03-02 09:45:13'),(104,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','退出成功','2024-03-02 10:41:42'),(105,'admin2','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','注册成功','2024-03-02 10:41:58'),(106,'admin2','127.0.0.1','内网IP','Chrome 12','Mac OS X','1','验证码错误','2024-03-02 10:42:04'),(107,'admin2','127.0.0.1','内网IP','Chrome 12','Mac OS X','1','用户不存在/密码错误','2024-03-02 10:42:07'),(108,'admin2','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','登录成功','2024-03-02 10:42:12'),(109,'admin2','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','退出成功','2024-03-02 10:42:18'),(110,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','登录成功','2024-03-02 10:42:25'),(111,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','登录成功','2024-03-02 12:35:28'),(112,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','登录成功','2024-03-02 13:12:29'),(113,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','登录成功','2024-03-02 14:09:18'),(114,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','登录成功','2024-03-02 14:32:16'),(115,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','1','验证码错误','2024-03-02 15:30:04'),(116,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','登录成功','2024-03-02 15:30:09'),(117,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','登录成功','2024-03-02 17:13:55'),(118,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','登录成功','2024-03-02 18:57:39'),(119,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','登录成功','2024-03-02 19:12:08'),(120,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','退出成功','2024-03-02 19:28:37'),(121,'test','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','注册成功','2024-03-02 19:29:00'),(122,'test222','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','注册成功','2024-03-02 19:33:52'),(123,'test222','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','登录成功','2024-03-02 19:34:01'),(124,'test222','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','退出成功','2024-03-02 19:34:50'),(125,'wzy','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','注册成功','2024-03-02 19:35:19'),(126,'wzt','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','注册成功','2024-03-02 19:36:40'),(127,'wzy','127.0.0.1','内网IP','Chrome 12','Mac OS X','1','用户不存在/密码错误','2024-03-02 19:36:50'),(128,'wzt','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','登录成功','2024-03-02 19:37:00'),(129,'wzt','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','退出成功','2024-03-02 19:37:43'),(130,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','登录成功','2024-03-02 19:37:52'),(131,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','退出成功','2024-03-02 19:40:48'),(132,'wzt','127.0.0.1','内网IP','Chrome 12','Mac OS X','1','验证码错误','2024-03-02 19:40:55'),(133,'wzt','127.0.0.1','内网IP','Chrome 12','Mac OS X','1','验证码错误','2024-03-02 19:40:58'),(134,'wzt','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','登录成功','2024-03-02 19:41:00'),(135,'wzt','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','退出成功','2024-03-02 19:41:22'),(136,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','1','用户不存在/密码错误','2024-03-02 19:41:30'),(137,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','登录成功','2024-03-02 19:41:40'),(138,'admin','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','退出成功','2024-03-02 19:46:12'),(139,'wzt','127.0.0.1','内网IP','Chrome 12','Mac OS X','0','登录成功','2024-03-02 19:46:19'),(140,'admin','120.244.234.130','XX XX','Chrome 12','Mac OS X','0','登录成功','2024-03-02 20:40:12'),(141,'admin','120.244.234.130','XX XX','Chrome 12','Mac OS X','0','退出成功','2024-03-02 20:40:40'),(142,'admin','120.244.234.130','XX XX','Chrome 12','Mac OS X','0','登录成功','2024-03-02 20:40:46'),(143,'admin','120.244.234.130','XX XX','Chrome 12','Mac OS X','0','退出成功','2024-03-02 20:40:55'),(144,'wzy','120.244.234.130','XX XX','Chrome 12','Mac OS X','0','注册成功','2024-03-02 20:41:12'),(145,'wzy','120.244.234.130','XX XX','Chrome 12','Mac OS X','0','登录成功','2024-03-02 20:41:18'),(146,'wzy','120.244.234.130','XX XX','Chrome 12','Mac OS X','0','退出成功','2024-03-02 20:57:05'),(147,'admin','120.244.234.130','XX XX','Chrome 12','Mac OS X','0','登录成功','2024-03-02 20:57:13'),(148,'admin','120.244.234.130','XX XX','Chrome 12','Mac OS X','0','退出成功','2024-03-02 21:01:03'),(149,'wzy','120.244.234.130','XX XX','Chrome 12','Mac OS X','0','登录成功','2024-03-02 21:01:09'),(150,'wzy','120.244.234.130','XX XX','Chrome 12','Mac OS X','0','退出成功','2024-03-02 21:04:20'),(151,'admin','120.244.234.130','XX XX','Chrome 12','Mac OS X','0','登录成功','2024-03-02 21:04:25'),(152,'admin','120.244.234.130','XX XX','Chrome 12','Mac OS X','0','退出成功','2024-03-02 21:04:59'),(153,'wzy','120.244.234.130','XX XX','Chrome 12','Mac OS X','0','登录成功','2024-03-02 21:05:06');
/*!40000 ALTER TABLE `sys_logininfor` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sys_menu`
--

DROP TABLE IF EXISTS `sys_menu`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sys_menu` (
                            `menu_id` bigint NOT NULL AUTO_INCREMENT COMMENT '菜单ID',
                            `menu_name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '菜单名称',
                            `parent_id` bigint DEFAULT '0' COMMENT '父菜单ID',
                            `order_num` int DEFAULT '0' COMMENT '显示顺序',
                            `path` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '路由地址',
                            `component` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '组件路径',
                            `query` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '路由参数',
                            `is_frame` int DEFAULT '1' COMMENT '是否为外链（0是 1否）',
                            `is_cache` int DEFAULT '0' COMMENT '是否缓存（0缓存 1不缓存）',
                            `menu_type` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '菜单类型（M目录 C菜单 F按钮）',
                            `visible` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '0' COMMENT '菜单状态（0显示 1隐藏）',
                            `status` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '0' COMMENT '菜单状态（0正常 1停用）',
                            `perms` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '权限标识',
                            `icon` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '#' COMMENT '菜单图标',
                            `create_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '创建者',
                            `create_time` datetime DEFAULT NULL COMMENT '创建时间',
                            `update_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '更新者',
                            `update_time` datetime DEFAULT NULL COMMENT '更新时间',
                            `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '备注',
                            PRIMARY KEY (`menu_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2011 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='菜单权限表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sys_menu`
--

LOCK TABLES `sys_menu` WRITE;
/*!40000 ALTER TABLE `sys_menu` DISABLE KEYS */;
INSERT INTO `sys_menu` (`menu_id`, `menu_name`, `parent_id`, `order_num`, `path`, `component`, `query`, `is_frame`, `is_cache`, `menu_type`, `visible`, `status`, `perms`, `icon`, `create_by`, `create_time`, `update_by`, `update_time`, `remark`) VALUES (1,'系统管理',0,1,'system',NULL,'',1,0,'M','0','0','','system','admin','2024-03-01 19:39:37','',NULL,'系统管理目录'),(2,'系统监控',0,2,'monitor',NULL,'',1,0,'M','0','0','','monitor','admin','2024-03-01 19:39:37','',NULL,'系统监控目录'),(3,'系统工具',0,3,'tool',NULL,'',1,0,'M','0','0','','tool','admin','2024-03-01 19:39:37','',NULL,'系统工具目录'),(4,'一颗星官网',0,4,'https://gitee.com/wy521a',NULL,'',0,0,'M','0','0','','guide','admin','2024-03-01 19:39:37','',NULL,'一颗星官网地址'),(100,'用户管理',1,1,'user','system/user/index','',1,0,'C','0','0','system:user:list','user','admin','2024-03-01 19:39:37','',NULL,'用户管理菜单'),(101,'角色管理',1,2,'role','system/role/index','',1,0,'C','0','0','system:role:list','peoples','admin','2024-03-01 19:39:37','',NULL,'角色管理菜单'),(102,'菜单管理',1,3,'menu','system/menu/index','',1,0,'C','0','0','system:menu:list','tree-table','admin','2024-03-01 19:39:37','',NULL,'菜单管理菜单'),(103,'部门管理',1,4,'dept','system/dept/index','',1,0,'C','0','0','system:dept:list','tree','admin','2024-03-01 19:39:37','',NULL,'部门管理菜单'),(104,'岗位管理',1,5,'post','system/post/index','',1,0,'C','0','0','system:post:list','post','admin','2024-03-01 19:39:37','',NULL,'岗位管理菜单'),(105,'字典管理',1,6,'dict','system/dict/index','',1,0,'C','0','0','system:dict:list','dict','admin','2024-03-01 19:39:37','',NULL,'字典管理菜单'),(106,'参数设置',1,7,'config','system/config/index','',1,0,'C','0','0','system:config:list','edit','admin','2024-03-01 19:39:37','',NULL,'参数设置菜单'),(107,'通知公告',1,8,'notice','system/notice/index','',1,0,'C','0','0','system:notice:list','message','admin','2024-03-01 19:39:37','',NULL,'通知公告菜单'),(108,'日志管理',1,9,'log','','',1,0,'M','0','0','','log','admin','2024-03-01 19:39:37','',NULL,'日志管理菜单'),(109,'在线用户',2,1,'online','monitor/online/index','',1,0,'C','0','0','monitor:online:list','online','admin','2024-03-01 19:39:37','',NULL,'在线用户菜单'),(110,'定时任务',2,2,'job','monitor/job/index','',1,0,'C','0','0','monitor:job:list','job','admin','2024-03-01 19:39:37','',NULL,'定时任务菜单'),(111,'数据监控',2,3,'druid','monitor/druid/index','',1,0,'C','0','0','monitor:druid:list','druid','admin','2024-03-01 19:39:37','',NULL,'数据监控菜单'),(112,'服务监控',2,4,'server','monitor/server/index','',1,0,'C','0','0','monitor:server:list','server','admin','2024-03-01 19:39:37','',NULL,'服务监控菜单'),(113,'缓存监控',2,5,'cache','monitor/cache/index','',1,0,'C','0','0','monitor:cache:list','redis','admin','2024-03-01 19:39:37','',NULL,'缓存监控菜单'),(114,'缓存列表',2,6,'cacheList','monitor/cache/list','',1,0,'C','0','0','monitor:cache:list','redis-list','admin','2024-03-01 19:39:37','',NULL,'缓存列表菜单'),(115,'表单构建22',3,1,'build','tool/build/index2222','',1,0,'C','0','1','tool:build:list','build','admin','2024-03-01 19:39:37','admin','2024-03-02 09:58:49','表单构建菜单'),(116,'代码生成',3,2,'gen','tool/gen/index','',1,0,'C','0','0','tool:gen:list','code','admin','2024-03-01 19:39:37','',NULL,'代码生成菜单'),(117,'系统接口',3,3,'swagger','tool/swagger/index','',1,0,'C','0','0','tool:swagger:list','swagger','admin','2024-03-01 19:39:37','',NULL,'系统接口菜单'),(500,'操作日志',108,1,'operlog','monitor/operlog/index','',1,0,'C','0','0','monitor:operlog:list','form','admin','2024-03-01 19:39:37','',NULL,'操作日志菜单'),(501,'登录日志',108,2,'logininfor','monitor/logininfor/index','',1,0,'C','0','0','monitor:logininfor:list','logininfor','admin','2024-03-01 19:39:37','',NULL,'登录日志菜单'),(1000,'用户查询',100,1,'','','',1,0,'F','0','0','system:user:query','#','admin','2024-03-01 19:39:38','',NULL,''),(1001,'用户新增',100,2,'','','',1,0,'F','0','0','system:user:add','#','admin','2024-03-01 19:39:38','',NULL,''),(1002,'用户修改',100,3,'','','',1,0,'F','0','0','system:user:edit','#','admin','2024-03-01 19:39:38','',NULL,''),(1003,'用户删除',100,4,'','','',1,0,'F','0','0','system:user:remove','#','admin','2024-03-01 19:39:38','',NULL,''),(1004,'用户导出',100,5,'','','',1,0,'F','0','0','system:user:export','#','admin','2024-03-01 19:39:38','',NULL,''),(1005,'用户导入',100,6,'','','',1,0,'F','0','0','system:user:import','#','admin','2024-03-01 19:39:38','',NULL,''),(1006,'重置密码',100,7,'','','',1,0,'F','0','0','system:user:resetPwd','#','admin','2024-03-01 19:39:38','',NULL,''),(1007,'角色查询',101,1,'','','',1,0,'F','0','0','system:role:query','#','admin','2024-03-01 19:39:38','',NULL,''),(1008,'角色新增',101,2,'','','',1,0,'F','0','0','system:role:add','#','admin','2024-03-01 19:39:38','',NULL,''),(1009,'角色修改',101,3,'','','',1,0,'F','0','0','system:role:edit','#','admin','2024-03-01 19:39:38','',NULL,''),(1010,'角色删除',101,4,'','','',1,0,'F','0','0','system:role:remove','#','admin','2024-03-01 19:39:38','',NULL,''),(1011,'角色导出',101,5,'','','',1,0,'F','0','0','system:role:export','#','admin','2024-03-01 19:39:38','',NULL,''),(1012,'菜单查询',102,1,'','','',1,0,'F','0','0','system:menu:query','#','admin','2024-03-01 19:39:38','',NULL,''),(1013,'菜单新增',102,2,'','','',1,0,'F','0','0','system:menu:add','#','admin','2024-03-01 19:39:38','',NULL,''),(1014,'菜单修改',102,3,'','','',1,0,'F','0','0','system:menu:edit','#','admin','2024-03-01 19:39:38','',NULL,''),(1015,'菜单删除',102,4,'','','',1,0,'F','0','0','system:menu:remove','#','admin','2024-03-01 19:39:38','',NULL,''),(1016,'部门查询',103,1,'','','',1,0,'F','0','0','system:dept:query','#','admin','2024-03-01 19:39:38','',NULL,''),(1017,'部门新增',103,2,'','','',1,0,'F','0','0','system:dept:add','#','admin','2024-03-01 19:39:38','',NULL,''),(1018,'部门修改',103,3,'','','',1,0,'F','0','0','system:dept:edit','#','admin','2024-03-01 19:39:38','',NULL,''),(1019,'部门删除',103,4,'','','',1,0,'F','0','0','system:dept:remove','#','admin','2024-03-01 19:39:38','',NULL,''),(1020,'岗位查询',104,1,'','','',1,0,'F','0','0','system:post:query','#','admin','2024-03-01 19:39:38','',NULL,''),(1021,'岗位新增',104,2,'','','',1,0,'F','0','0','system:post:add','#','admin','2024-03-01 19:39:38','',NULL,''),(1022,'岗位修改',104,3,'','','',1,0,'F','0','0','system:post:edit','#','admin','2024-03-01 19:39:38','',NULL,''),(1023,'岗位删除',104,4,'','','',1,0,'F','0','0','system:post:remove','#','admin','2024-03-01 19:39:38','',NULL,''),(1024,'岗位导出',104,5,'','','',1,0,'F','0','0','system:post:export','#','admin','2024-03-01 19:39:38','',NULL,''),(1025,'字典查询',105,1,'#','','',1,0,'F','0','0','system:dict:query','#','admin','2024-03-01 19:39:38','',NULL,''),(1026,'字典新增',105,2,'#','','',1,0,'F','0','0','system:dict:add','#','admin','2024-03-01 19:39:38','',NULL,''),(1027,'字典修改',105,3,'#','','',1,0,'F','0','0','system:dict:edit','#','admin','2024-03-01 19:39:38','',NULL,''),(1028,'字典删除',105,4,'#','','',1,0,'F','0','0','system:dict:remove','#','admin','2024-03-01 19:39:38','',NULL,''),(1029,'字典导出',105,5,'#','','',1,0,'F','0','0','system:dict:export','#','admin','2024-03-01 19:39:38','',NULL,''),(1030,'参数查询',106,1,'#','','',1,0,'F','0','0','system:config:query','#','admin','2024-03-01 19:39:38','',NULL,''),(1031,'参数新增',106,2,'#','','',1,0,'F','0','0','system:config:add','#','admin','2024-03-01 19:39:38','',NULL,''),(1032,'参数修改',106,3,'#','','',1,0,'F','0','0','system:config:edit','#','admin','2024-03-01 19:39:38','',NULL,''),(1033,'参数删除',106,4,'#','','',1,0,'F','0','0','system:config:remove','#','admin','2024-03-01 19:39:38','',NULL,''),(1034,'参数导出',106,5,'#','','',1,0,'F','0','0','system:config:export','#','admin','2024-03-01 19:39:38','',NULL,''),(1035,'公告查询',107,1,'#','','',1,0,'F','0','0','system:notice:query','#','admin','2024-03-01 19:39:38','',NULL,''),(1036,'公告新增',107,2,'#','','',1,0,'F','0','0','system:notice:add','#','admin','2024-03-01 19:39:38','',NULL,''),(1037,'公告修改',107,3,'#','','',1,0,'F','0','0','system:notice:edit','#','admin','2024-03-01 19:39:38','',NULL,''),(1038,'公告删除',107,4,'#','','',1,0,'F','0','0','system:notice:remove','#','admin','2024-03-01 19:39:38','',NULL,''),(1039,'操作查询',500,1,'#','','',1,0,'F','0','0','monitor:operlog:query','#','admin','2024-03-01 19:39:38','',NULL,''),(1040,'操作删除',500,2,'#','','',1,0,'F','0','0','monitor:operlog:remove','#','admin','2024-03-01 19:39:38','',NULL,''),(1041,'日志导出',500,3,'#','','',1,0,'F','0','0','monitor:operlog:export','#','admin','2024-03-01 19:39:38','',NULL,''),(1042,'登录查询',501,1,'#','','',1,0,'F','0','0','monitor:logininfor:query','#','admin','2024-03-01 19:39:38','',NULL,''),(1043,'登录删除',501,2,'#','','',1,0,'F','0','0','monitor:logininfor:remove','#','admin','2024-03-01 19:39:38','',NULL,''),(1044,'日志导出',501,3,'#','','',1,0,'F','0','0','monitor:logininfor:export','#','admin','2024-03-01 19:39:38','',NULL,''),(1045,'账户解锁',501,4,'#','','',1,0,'F','0','0','monitor:logininfor:unlock','#','admin','2024-03-01 19:39:38','',NULL,''),(1046,'在线查询',109,1,'#','','',1,0,'F','0','0','monitor:online:query','#','admin','2024-03-01 19:39:38','',NULL,''),(1047,'批量强退',109,2,'#','','',1,0,'F','0','0','monitor:online:batchLogout','#','admin','2024-03-01 19:39:38','',NULL,''),(1048,'单条强退',109,3,'#','','',1,0,'F','0','0','monitor:online:forceLogout','#','admin','2024-03-01 19:39:38','',NULL,''),(1049,'任务查询',110,1,'#','','',1,0,'F','0','0','monitor:job:query','#','admin','2024-03-01 19:39:38','',NULL,''),(1050,'任务新增',110,2,'#','','',1,0,'F','0','0','monitor:job:add','#','admin','2024-03-01 19:39:38','',NULL,''),(1051,'任务修改',110,3,'#','','',1,0,'F','0','0','monitor:job:edit','#','admin','2024-03-01 19:39:38','',NULL,''),(1052,'任务删除',110,4,'#','','',1,0,'F','0','0','monitor:job:remove','#','admin','2024-03-01 19:39:38','',NULL,''),(1053,'状态修改',110,5,'#','','',1,0,'F','0','0','monitor:job:changeStatus','#','admin','2024-03-01 19:39:38','',NULL,''),(1054,'任务导出',110,6,'#','','',1,0,'F','0','0','monitor:job:export','#','admin','2024-03-01 19:39:38','',NULL,''),(1055,'生成查询',116,1,'#','','',1,0,'F','0','0','tool:gen:query','#','admin','2024-03-01 19:39:38','',NULL,''),(1056,'生成修改',116,2,'#','','',1,0,'F','0','0','tool:gen:edit','#','admin','2024-03-01 19:39:38','',NULL,''),(1057,'生成删除',116,3,'#','','',1,0,'F','0','0','tool:gen:remove','#','admin','2024-03-01 19:39:38','',NULL,''),(1058,'导入代码',116,4,'#','','',1,0,'F','0','0','tool:gen:import','#','admin','2024-03-01 19:39:38','',NULL,''),(1059,'预览代码',116,5,'#','','',1,0,'F','0','0','tool:gen:preview','#','admin','2024-03-01 19:39:38','',NULL,''),(1060,'生成代码',116,6,'#','','',1,0,'F','0','0','tool:gen:code','#','admin','2024-03-01 19:39:38','',NULL,''),(2000,'问卷调查',0,2,'questionnaire',NULL,NULL,1,0,'M','0','0',NULL,'table','admin','2024-03-01 20:51:37','',NULL,''),(2001,'问卷管理',2000,1,'index','questionnaire/index',NULL,1,1,'C','0','0','system:questionnaire:list','build','admin','2024-03-01 20:52:45','admin','2024-03-01 23:27:10',''),(2004,'详情',2000,2,'',NULL,NULL,1,0,'F','0','0','system:questionnaire:query','#','admin','2024-03-02 19:42:26','',NULL,''),(2005,'新增',2000,3,'',NULL,NULL,1,0,'F','0','0','system:questionnaire:add','#','admin','2024-03-02 19:42:52','',NULL,''),(2006,'修改',2000,4,'',NULL,NULL,1,0,'F','0','0','system:questionnaire:edit','#','admin','2024-03-02 19:43:04','',NULL,''),(2007,'删除',2000,5,'',NULL,NULL,1,0,'F','0','0','system:questionnaire:remove','#','admin','2024-03-02 19:43:21','',NULL,''),(2008,'发布',2000,6,'',NULL,NULL,1,0,'F','0','0','system:questionnaire:publish','#','admin','2024-03-02 19:43:40','',NULL,''),(2009,'配置问卷',2000,7,'',NULL,NULL,1,0,'F','0','0','questionnaire:form:edit','#','admin','2024-03-02 20:59:53','',NULL,''),(2010,'统计',2000,8,'',NULL,NULL,1,0,'F','0','0','system:questionnaire:get','#','admin','2024-03-02 21:04:38','',NULL,'');
/*!40000 ALTER TABLE `sys_menu` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sys_notice`
--

DROP TABLE IF EXISTS `sys_notice`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sys_notice` (
                              `notice_id` int NOT NULL AUTO_INCREMENT COMMENT '公告ID',
                              `notice_title` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '公告标题',
                              `notice_type` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '公告类型（1通知 2公告）',
                              `notice_content` longblob COMMENT '公告内容',
                              `status` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '0' COMMENT '公告状态（0正常 1关闭）',
                              `create_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '创建者',
                              `create_time` datetime DEFAULT NULL COMMENT '创建时间',
                              `update_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '更新者',
                              `update_time` datetime DEFAULT NULL COMMENT '更新时间',
                              `remark` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '备注',
                              PRIMARY KEY (`notice_id`)
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='通知公告表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sys_notice`
--

LOCK TABLES `sys_notice` WRITE;
/*!40000 ALTER TABLE `sys_notice` DISABLE KEYS */;
INSERT INTO `sys_notice` (`notice_id`, `notice_title`, `notice_type`, `notice_content`, `status`, `create_by`, `create_time`, `update_by`, `update_time`, `remark`) VALUES (1,'温馨提醒：2018-07-01 一颗星新版本发布啦','2',_binary '新版本内容','0','admin','2024-03-01 19:39:40','',NULL,'管理员'),(2,'维护通知：2018-07-01 一颗星系统凌晨维护','1',_binary '维护内容','0','admin','2024-03-01 19:39:40','',NULL,'管理员');
/*!40000 ALTER TABLE `sys_notice` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sys_oper_log`
--

DROP TABLE IF EXISTS `sys_oper_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sys_oper_log` (
                                `oper_id` bigint NOT NULL AUTO_INCREMENT COMMENT '日志主键',
                                `title` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '模块标题',
                                `business_type` int DEFAULT '0' COMMENT '业务类型（0其它 1新增 2修改 3删除）',
                                `method` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '方法名称',
                                `request_method` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '请求方式',
                                `operator_type` int DEFAULT '0' COMMENT '操作类别（0其它 1后台用户 2手机端用户）',
                                `oper_name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '操作人员',
                                `dept_name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '部门名称',
                                `oper_url` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '请求URL',
                                `oper_ip` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '主机地址',
                                `oper_location` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '操作地点',
                                `oper_param` varchar(2000) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '请求参数',
                                `json_result` varchar(2000) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '返回参数',
                                `status` int DEFAULT '0' COMMENT '操作状态（0正常 1异常）',
                                `error_msg` varchar(2000) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '错误消息',
                                `oper_time` datetime DEFAULT NULL COMMENT '操作时间',
                                `cost_time` bigint DEFAULT '0' COMMENT '消耗时间',
                                PRIMARY KEY (`oper_id`),
                                KEY `idx_sys_oper_log_bt` (`business_type`),
                                KEY `idx_sys_oper_log_s` (`status`),
                                KEY `idx_sys_oper_log_ot` (`oper_time`)
) ENGINE=InnoDB AUTO_INCREMENT=229 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='操作日志记录';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sys_oper_log`
--

LOCK TABLES `sys_oper_log` WRITE;
/*!40000 ALTER TABLE `sys_oper_log` DISABLE KEYS */;
INSERT INTO `sys_oper_log` (`oper_id`, `title`, `business_type`, `method`, `request_method`, `operator_type`, `oper_name`, `dept_name`, `oper_url`, `oper_ip`, `oper_location`, `oper_param`, `json_result`, `status`, `error_msg`, `oper_time`, `cost_time`) VALUES (190,'菜单管理',3,'com.astar.web.controller.system.SysMenuController.remove()','DELETE',1,'admin','研发部门','/system/menu/4','127.0.0.1','内网IP','{}','{\"msg\":\"菜单已分配,不允许删除\",\"code\":601}',0,NULL,'2024-03-02 18:58:56',17),(191,'菜单管理',3,'com.astar.web.controller.system.SysMenuController.remove()','DELETE',1,'admin','研发部门','/system/menu/4','127.0.0.1','内网IP','{}','{\"msg\":\"菜单已分配,不允许删除\",\"code\":601}',0,NULL,'2024-03-02 18:59:02',12),(192,'角色管理',3,'com.astar.web.controller.system.SysRoleController.remove()','DELETE',1,'admin','研发部门','/system/role/2','127.0.0.1','内网IP','{}',NULL,1,'普通角色已分配,不能删除','2024-03-02 18:59:15',21),(193,'用户管理',3,'com.astar.web.controller.system.SysUserController.remove()','DELETE',1,'admin','研发部门','/system/user/2','127.0.0.1','内网IP','{}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 18:59:23',14),(194,'用户管理',3,'com.astar.web.controller.system.SysUserController.remove()','DELETE',1,'admin','研发部门','/system/user/100','127.0.0.1','内网IP','{}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 18:59:25',17),(195,'部门管理',3,'com.astar.web.controller.system.SysDeptController.remove()','DELETE',1,'admin','研发部门','/system/dept/101','127.0.0.1','内网IP','{}','{\"msg\":\"存在下级部门,不允许删除\",\"code\":601}',0,NULL,'2024-03-02 18:59:34',6),(196,'部门管理',3,'com.astar.web.controller.system.SysDeptController.remove()','DELETE',1,'admin','研发部门','/system/dept/103','127.0.0.1','内网IP','{}','{\"msg\":\"部门存在用户,不允许删除\",\"code\":601}',0,NULL,'2024-03-02 18:59:38',14),(197,'部门管理',3,'com.astar.web.controller.system.SysDeptController.remove()','DELETE',1,'admin','研发部门','/system/dept/104','127.0.0.1','内网IP','{}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 18:59:41',13),(198,'部门管理',3,'com.astar.web.controller.system.SysDeptController.remove()','DELETE',1,'admin','研发部门','/system/dept/105','127.0.0.1','内网IP','{}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 18:59:43',18),(199,'部门管理',3,'com.astar.web.controller.system.SysDeptController.remove()','DELETE',1,'admin','研发部门','/system/dept/106','127.0.0.1','内网IP','{}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 18:59:44',16),(200,'部门管理',3,'com.astar.web.controller.system.SysDeptController.remove()','DELETE',1,'admin','研发部门','/system/dept/107','127.0.0.1','内网IP','{}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 18:59:47',14),(201,'部门管理',3,'com.astar.web.controller.system.SysDeptController.remove()','DELETE',1,'admin','研发部门','/system/dept/108','127.0.0.1','内网IP','{}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 18:59:50',15),(202,'部门管理',3,'com.astar.web.controller.system.SysDeptController.remove()','DELETE',1,'admin','研发部门','/system/dept/109','127.0.0.1','内网IP','{}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 18:59:52',16),(203,'部门管理',3,'com.astar.web.controller.system.SysDeptController.remove()','DELETE',1,'admin','研发部门','/system/dept/102','127.0.0.1','内网IP','{}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 18:59:54',8),(204,'部门管理',2,'com.astar.web.controller.system.SysDeptController.edit()','PUT',1,'admin','研发部门','/system/dept','127.0.0.1','内网IP','{\"ancestors\":\"0\",\"children\":[],\"deptId\":100,\"deptName\":\"一颗星\",\"email\":\"\",\"leader\":\"一颗星\",\"orderNum\":0,\"params\":{},\"parentId\":0,\"phone\":\"15555555555\",\"status\":\"0\",\"updateBy\":\"admin\"}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 19:00:12',9),(205,'部门管理',2,'com.astar.web.controller.system.SysDeptController.edit()','PUT',1,'admin','研发部门','/system/dept','127.0.0.1','内网IP','{\"ancestors\":\"0,100\",\"children\":[],\"deptId\":101,\"deptName\":\"北京总部\",\"email\":\"astar@qq.com\",\"leader\":\"一颗星\",\"orderNum\":1,\"params\":{},\"parentId\":100,\"parentName\":\"一颗星\",\"phone\":\"15888888888\",\"status\":\"0\",\"updateBy\":\"admin\"}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 19:00:33',21),(206,'部门管理',2,'com.astar.web.controller.system.SysDeptController.edit()','PUT',1,'admin','研发部门','/system/dept','127.0.0.1','内网IP','{\"ancestors\":\"0,100,101\",\"children\":[],\"deptId\":103,\"deptName\":\"研发部门\",\"email\":\"astar@qq.com\",\"leader\":\"一颗星\",\"orderNum\":1,\"params\":{},\"parentId\":101,\"parentName\":\"北京总部\",\"phone\":\"15888888888\",\"status\":\"0\",\"updateBy\":\"admin\"}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 19:00:42',21),(207,'菜单管理',3,'com.astar.web.controller.system.SysMenuController.remove()','DELETE',1,'admin','研发部门','/system/menu/4','127.0.0.1','内网IP','{}','{\"msg\":\"菜单已分配,不允许删除\",\"code\":601}',0,NULL,'2024-03-02 19:00:52',4),(208,'角色管理',3,'com.astar.web.controller.system.SysRoleController.remove()','DELETE',1,'admin','研发部门','/system/role/2','127.0.0.1','内网IP','{}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 19:00:56',31),(209,'角色管理',2,'com.astar.web.controller.system.SysRoleController.edit()','PUT',1,'admin','研发部门','/system/role','127.0.0.1','内网IP','{\"admin\":true,\"createTime\":\"2024-03-01 19:39:37\",\"dataScope\":\"1\",\"delFlag\":\"0\",\"deptCheckStrictly\":true,\"flag\":false,\"menuCheckStrictly\":true,\"menuIds\":[1,100,1000,1001,1002,1003,1004,1005,1006,101,1007,1008,1009,1010,1011,102,1012,1013,1014,1015,103,1016,1017,1018,1019,104,1020,1021,1022,1023,1024,105,1025,1026,1027,1028,1029,106,1030,1031,1032,1033,1034,107,1035,1036,1037,1038,108,500,1039,1040,1041,501,1042,1043,1044,1045,2,109,1046,1047,1048,110,1049,1050,1051,1052,1053,1054,111,112,113,114,2000,2001,3,115,116,1055,1056,1057,1058,1059,1060,117],\"params\":{},\"remark\":\"超级管理员\",\"roleId\":1,\"roleKey\":\"admin\",\"roleName\":\"超级管理员\",\"roleSort\":1,\"status\":\"0\"}',NULL,1,'不允许操作超级管理员角色','2024-03-02 19:01:18',1),(210,'角色管理',1,'com.astar.web.controller.system.SysRoleController.add()','POST',1,'admin','研发部门','/system/role','127.0.0.1','内网IP','{\"admin\":false,\"deptCheckStrictly\":true,\"deptIds\":[],\"flag\":false,\"menuCheckStrictly\":true,\"menuIds\":[2000,2001],\"params\":{},\"remark\":\"一颗星\",\"roleKey\":\"admin\",\"roleName\":\"一颗星\",\"roleSort\":2,\"status\":\"0\"}','{\"msg\":\"新增角色\'一颗星\'失败，角色权限已存在\",\"code\":500}',0,NULL,'2024-03-02 19:01:48',10),(211,'角色管理',1,'com.astar.web.controller.system.SysRoleController.add()','POST',1,'admin','研发部门','/system/role','127.0.0.1','内网IP','{\"admin\":false,\"createBy\":\"admin\",\"deptCheckStrictly\":true,\"deptIds\":[],\"flag\":false,\"menuCheckStrictly\":true,\"menuIds\":[2000,2001],\"params\":{},\"remark\":\"一颗星\",\"roleId\":100,\"roleKey\":\"astar\",\"roleName\":\"一颗星\",\"roleSort\":2,\"status\":\"0\"}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 19:01:55',27),(212,'个人信息',2,'com.astar.web.controller.system.SysProfileController.updateProfile()','PUT',1,'admin','研发部门','/system/user/profile','127.0.0.1','内网IP','{\"admin\":false,\"email\":\"astar@qq.com\",\"nickName\":\"一颗星\",\"params\":{},\"phonenumber\":\"15888888888\",\"sex\":\"0\"}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 19:12:32',13),(213,'个人信息',2,'com.astar.web.controller.system.SysProfileController.updatePwd()','PUT',1,'admin','研发部门','/system/user/profile/updatePwd','127.0.0.1','内网IP','{}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 19:38:07',249),(214,'菜单管理',1,'com.astar.web.controller.system.SysMenuController.add()','POST',1,'admin','研发部门','/system/menu','127.0.0.1','内网IP','{\"children\":[],\"createBy\":\"admin\",\"isCache\":\"0\",\"isFrame\":\"1\",\"menuName\":\"详情\",\"menuType\":\"F\",\"orderNum\":2,\"params\":{},\"parentId\":2000,\"perms\":\"system:questionnaire:query\",\"status\":\"0\",\"visible\":\"0\"}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 19:42:26',13),(215,'菜单管理',1,'com.astar.web.controller.system.SysMenuController.add()','POST',1,'admin','研发部门','/system/menu','127.0.0.1','内网IP','{\"children\":[],\"createBy\":\"admin\",\"isCache\":\"0\",\"isFrame\":\"1\",\"menuName\":\"新增\",\"menuType\":\"F\",\"orderNum\":3,\"params\":{},\"parentId\":2000,\"perms\":\"system:questionnaire:add\",\"status\":\"0\",\"visible\":\"0\"}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 19:42:52',14),(216,'菜单管理',1,'com.astar.web.controller.system.SysMenuController.add()','POST',1,'admin','研发部门','/system/menu','127.0.0.1','内网IP','{\"children\":[],\"createBy\":\"admin\",\"isCache\":\"0\",\"isFrame\":\"1\",\"menuName\":\"修改\",\"menuType\":\"F\",\"orderNum\":4,\"params\":{},\"parentId\":2000,\"perms\":\"system:questionnaire:edit\",\"status\":\"0\",\"visible\":\"0\"}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 19:43:04',7),(217,'菜单管理',1,'com.astar.web.controller.system.SysMenuController.add()','POST',1,'admin','研发部门','/system/menu','127.0.0.1','内网IP','{\"children\":[],\"createBy\":\"admin\",\"isCache\":\"0\",\"isFrame\":\"1\",\"menuName\":\"删除\",\"menuType\":\"F\",\"orderNum\":5,\"params\":{},\"parentId\":2000,\"perms\":\"system:questionnaire:remove\",\"status\":\"0\",\"visible\":\"0\"}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 19:43:21',7),(218,'菜单管理',1,'com.astar.web.controller.system.SysMenuController.add()','POST',1,'admin','研发部门','/system/menu','127.0.0.1','内网IP','{\"children\":[],\"createBy\":\"admin\",\"isCache\":\"0\",\"isFrame\":\"1\",\"menuName\":\"发布\",\"menuType\":\"F\",\"orderNum\":6,\"params\":{},\"parentId\":2000,\"perms\":\"system:questionnaire:publish\",\"status\":\"0\",\"visible\":\"0\"}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 19:43:40',16),(219,'角色管理',2,'com.astar.web.controller.system.SysRoleController.edit()','PUT',1,'admin','研发部门','/system/role','127.0.0.1','内网IP','{\"admin\":false,\"createTime\":\"2024-03-02 19:01:55\",\"dataScope\":\"1\",\"delFlag\":\"0\",\"deptCheckStrictly\":true,\"flag\":false,\"menuCheckStrictly\":true,\"menuIds\":[2000,2001,2004,2005,2006,2007,2008],\"params\":{},\"remark\":\"一颗星\",\"roleId\":100,\"roleKey\":\"admin\",\"roleName\":\"一颗星\",\"roleSort\":2,\"status\":\"0\"}','{\"msg\":\"修改角色\'一颗星\'失败，角色权限已存在\",\"code\":500}',0,NULL,'2024-03-02 19:44:28',13),(220,'问卷调查管理',3,'com.astar.web.controller.questionnaire.QuestionnaireController.remove()','DELETE',1,'wzt',NULL,'/questionnaire/13','127.0.0.1','内网IP','{}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 19:46:35',13),(221,'个人信息',2,'com.astar.web.controller.system.SysProfileController.updatePwd()','PUT',1,'admin','研发部门','/system/user/profile/updatePwd','120.244.234.130','XX XX','{}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 20:40:35',292),(222,'问卷调查管理',1,'com.astar.web.controller.questionnaire.QuestionnaireController.add()','POST',1,'wzy',NULL,'/questionnaire','120.244.234.130','XX XX','{\"createdBy\":\"wzy\",\"id\":14,\"params\":{},\"remark\":\"非常感谢您认真填写此问卷！\",\"title\":\"大学生就业问卷调查\"}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 20:54:06',35),(223,'代码生成',6,'com.astar.generator.controller.GenController.importTableSave()','POST',1,'admin','研发部门','/tool/gen/importTable','120.244.234.130','XX XX','{\"tables\":\"tb_questionnaire_user\"}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 20:57:25',112),(224,'菜单管理',1,'com.astar.web.controller.system.SysMenuController.add()','POST',1,'admin','研发部门','/system/menu','120.244.234.130','XX XX','{\"children\":[],\"createBy\":\"admin\",\"isCache\":\"0\",\"isFrame\":\"1\",\"menuName\":\"配置问卷\",\"menuType\":\"F\",\"orderNum\":7,\"params\":{},\"parentId\":2000,\"perms\":\"questionnaire:form:edit\",\"status\":\"0\",\"visible\":\"0\"}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 20:59:53',28),(225,'问卷调查管理',2,'com.astar.web.controller.questionnaire.QuestionnaireController.edit()','PUT',1,'wzy',NULL,'/questionnaire','120.244.234.130','XX XX','{\"formJson\":\"{\\\"formRef\\\":\\\"elForm\\\",\\\"formModel\\\":\\\"formData\\\",\\\"size\\\":\\\"medium\\\",\\\"labelPosition\\\":\\\"right\\\",\\\"labelWidth\\\":100,\\\"formRules\\\":\\\"rules\\\",\\\"gutter\\\":15,\\\"disabled\\\":false,\\\"span\\\":24,\\\"formBtns\\\":true,\\\"fields\\\":[{\\\"__config__\\\":{\\\"label\\\":\\\"姓名\\\",\\\"labelWidth\\\":null,\\\"showLabel\\\":true,\\\"changeTag\\\":true,\\\"tag\\\":\\\"el-input\\\",\\\"tagIcon\\\":\\\"input\\\",\\\"required\\\":true,\\\"layout\\\":\\\"colFormItem\\\",\\\"span\\\":24,\\\"document\\\":\\\"https://element.eleme.cn/#/zh-CN/component/input\\\",\\\"regList\\\":[],\\\"formId\\\":101,\\\"renderKey\\\":\\\"1011709384474421\\\"},\\\"__slot__\\\":{\\\"prepend\\\":\\\"\\\",\\\"append\\\":\\\"\\\"},\\\"type\\\":\\\"input\\\",\\\"placeholder\\\":\\\"请输入姓名\\\",\\\"style\\\":{\\\"width\\\":\\\"100%\\\"},\\\"clearable\\\":true,\\\"prefix-icon\\\":\\\"\\\",\\\"suffix-icon\\\":\\\"\\\",\\\"maxlength\\\":null,\\\"show-word-limit\\\":false,\\\"readonly\\\":false,\\\"disabled\\\":false,\\\"__vModel__\\\":\\\"field101\\\"},{\\\"__config__\\\":{\\\"label\\\":\\\"是否就业\\\",\\\"labelWidth\\\":null,\\\"showLabel\\\":true,\\\"tag\\\":\\\"el-radio-group\\\",\\\"tagIcon\\\":\\\"radio\\\",\\\"changeTag\\\":true,\\\"layout\\\":\\\"colFormItem\\\",\\\"span\\\":24,\\\"optionType\\\":\\\"default\\\",\\\"regList\\\":[],\\\"required\\\":true,\\\"border\\\":false,\\\"document\\\":\\\"https://element.eleme.cn/#/zh-CN/component/radio\\\",\\\"formId\\\":102,\\\"renderKey\\\":\\\"1021709384488343\\\"},\\\"type\\\":\\\"radio\\\",\\\"__slot__\\\":{\\\"options\\\":[{\\\"label\\\":\\\"就业\\\",\\\"value\\\":1},{\\\"label\\\":\\\"未就业\\\",\\\"value\\\":2}]},\\\"style\\\":{},\\\"size\\\":\\\"medium\\\",\\\"disabled\\\":false,\\\"__vModel__\\\":\\\"field102\\\"},{\\\"__config__\\\":{\\\"label\\\":\\\"就业日期\\\",\\\"tag\\\":\\\"el-date-picker\\\",\\\"tagIcon\\\":\\\"date\\\",\\\"defaultValue\\\":null,\\\"showLabel\\\":true,\\\"labelWidth\\\":null,\\\"span\\\":24,\\\"layout\\\":\\\"colFormItem\\\",\\\"required\\\":true,\\\"regList\\\":[],\\\"changeTag\\\":true,\\\"document\\\":\\\"https://element.eleme.cn/#/zh-CN/component/date-picker\\\",\\\"formId\\\":103,\\\"renderKey\\\":\\\"1031709384504930\\\"},\\\"placeholder\\\":\\\"请选择就业日期\\\",\\\"type\\\":\\\"date\\\",\\\"style\\\":{\\\"width\\\":\\\"100%\\\"},\\\"disabled\\\":false,\\\"clearable\\\":true,\\\"format\\\":\\\"yyyy-MM-dd\\\",\\\"value-format\\\":\\\"yyyy-MM-dd\\\",\\\"readonly\\\":false,\\\"__vModel__\\\":\\\"field103\\\"},{','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 21:03:13',25),(226,'问卷调查管理',2,'com.astar.web.controller.questionnaire.QuestionnaireController.publish()','PUT',1,'wzy',NULL,'/questionnaire/publish','120.244.234.130','XX XX','{\"formUrl\":\"JcIkpV\",\"id\":14,\"params\":{},\"status\":true,\"updatedBy\":\"wzy\"}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 21:03:19',37),(227,'菜单管理',1,'com.astar.web.controller.system.SysMenuController.add()','POST',1,'admin','研发部门','/system/menu','120.244.234.130','XX XX','{\"children\":[],\"createBy\":\"admin\",\"isCache\":\"0\",\"isFrame\":\"1\",\"menuName\":\"统计\",\"menuType\":\"F\",\"orderNum\":8,\"params\":{},\"parentId\":2000,\"perms\":\"system:questionnaire:get\",\"status\":\"0\",\"visible\":\"0\"}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 21:04:38',14),(228,'填写问卷管理',1,'com.astar.web.controller.questionnaire.QsController.fillQs()','POST',1,'wzy',NULL,'/qs/fillQs','120.244.234.130','XX XX','{\"dataJson\":\"{\\\"field101\\\":\\\"一颗星\\\",\\\"field102\\\":2,\\\"field103\\\":\\\"2024-03-02\\\",\\\"field104\\\":1,\\\"field105\\\":\\\"测试问卷调查系统\\\"}\",\"id\":9,\"ipAddr\":\"120.244.234.130\",\"params\":{},\"qsId\":14}','{\"msg\":\"操作成功\",\"code\":200}',0,NULL,'2024-03-02 21:05:57',24);
/*!40000 ALTER TABLE `sys_oper_log` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sys_post`
--

DROP TABLE IF EXISTS `sys_post`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sys_post` (
                            `post_id` bigint NOT NULL AUTO_INCREMENT COMMENT '岗位ID',
                            `post_code` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '岗位编码',
                            `post_name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '岗位名称',
                            `post_sort` int NOT NULL COMMENT '显示顺序',
                            `status` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '状态（0正常 1停用）',
                            `create_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '创建者',
                            `create_time` datetime DEFAULT NULL COMMENT '创建时间',
                            `update_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '更新者',
                            `update_time` datetime DEFAULT NULL COMMENT '更新时间',
                            `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '备注',
                            PRIMARY KEY (`post_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='岗位信息表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sys_post`
--

LOCK TABLES `sys_post` WRITE;
/*!40000 ALTER TABLE `sys_post` DISABLE KEYS */;
INSERT INTO `sys_post` (`post_id`, `post_code`, `post_name`, `post_sort`, `status`, `create_by`, `create_time`, `update_by`, `update_time`, `remark`) VALUES (1,'ceo','董事长',1,'0','admin','2024-03-01 19:39:37','',NULL,''),(2,'se','项目经理',2,'0','admin','2024-03-01 19:39:37','',NULL,''),(3,'hr','人力资源',3,'0','admin','2024-03-01 19:39:37','',NULL,''),(4,'user','普通员工',4,'0','admin','2024-03-01 19:39:37','',NULL,'');
/*!40000 ALTER TABLE `sys_post` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sys_role`
--

DROP TABLE IF EXISTS `sys_role`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sys_role` (
                            `role_id` bigint NOT NULL AUTO_INCREMENT COMMENT '角色ID',
                            `role_name` varchar(30) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '角色名称',
                            `role_key` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '角色权限字符串',
                            `role_sort` int NOT NULL COMMENT '显示顺序',
                            `data_scope` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '1' COMMENT '数据范围（1：全部数据权限 2：自定数据权限 3：本部门数据权限 4：本部门及以下数据权限）',
                            `menu_check_strictly` tinyint(1) DEFAULT '1' COMMENT '菜单树选择项是否关联显示',
                            `dept_check_strictly` tinyint(1) DEFAULT '1' COMMENT '部门树选择项是否关联显示',
                            `status` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '角色状态（0正常 1停用）',
                            `del_flag` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '0' COMMENT '删除标志（0代表存在 2代表删除）',
                            `create_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '创建者',
                            `create_time` datetime DEFAULT NULL COMMENT '创建时间',
                            `update_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '更新者',
                            `update_time` datetime DEFAULT NULL COMMENT '更新时间',
                            `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '备注',
                            PRIMARY KEY (`role_id`)
) ENGINE=InnoDB AUTO_INCREMENT=101 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='角色信息表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sys_role`
--

LOCK TABLES `sys_role` WRITE;
/*!40000 ALTER TABLE `sys_role` DISABLE KEYS */;
INSERT INTO `sys_role` (`role_id`, `role_name`, `role_key`, `role_sort`, `data_scope`, `menu_check_strictly`, `dept_check_strictly`, `status`, `del_flag`, `create_by`, `create_time`, `update_by`, `update_time`, `remark`) VALUES (1,'超级管理员','admin',1,'1',1,1,'0','0','admin','2024-03-01 19:39:37','',NULL,'超级管理员'),(2,'普通角色','common',2,'2',1,1,'0','2','admin','2024-03-01 19:39:37','',NULL,'普通角色'),(100,'一颗星','admin',2,'1',1,1,'0','0','admin','2024-03-02 19:01:55','',NULL,'一颗星');
/*!40000 ALTER TABLE `sys_role` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sys_role_dept`
--

DROP TABLE IF EXISTS `sys_role_dept`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sys_role_dept` (
                                 `role_id` bigint NOT NULL COMMENT '角色ID',
                                 `dept_id` bigint NOT NULL COMMENT '部门ID',
                                 PRIMARY KEY (`role_id`,`dept_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='角色和部门关联表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sys_role_dept`
--

LOCK TABLES `sys_role_dept` WRITE;
/*!40000 ALTER TABLE `sys_role_dept` DISABLE KEYS */;
/*!40000 ALTER TABLE `sys_role_dept` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sys_role_menu`
--

DROP TABLE IF EXISTS `sys_role_menu`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sys_role_menu` (
                                 `role_id` bigint NOT NULL COMMENT '角色ID',
                                 `menu_id` bigint NOT NULL COMMENT '菜单ID',
                                 PRIMARY KEY (`role_id`,`menu_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='角色和菜单关联表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sys_role_menu`
--

LOCK TABLES `sys_role_menu` WRITE;
/*!40000 ALTER TABLE `sys_role_menu` DISABLE KEYS */;
INSERT INTO `sys_role_menu` (`role_id`, `menu_id`) VALUES (100,2000),(100,2001),(100,2004),(100,2005),(100,2006),(100,2007),(100,2008),(100,2009),(100,2010);
/*!40000 ALTER TABLE `sys_role_menu` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sys_user`
--

DROP TABLE IF EXISTS `sys_user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sys_user` (
                            `user_id` bigint NOT NULL AUTO_INCREMENT COMMENT '用户ID',
                            `dept_id` bigint DEFAULT NULL COMMENT '部门ID',
                            `user_name` varchar(30) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '用户账号',
                            `nick_name` varchar(30) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '用户昵称',
                            `user_type` varchar(2) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '00' COMMENT '用户类型（00系统用户）',
                            `email` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '用户邮箱',
                            `phonenumber` varchar(11) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '手机号码',
                            `sex` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '0' COMMENT '用户性别（0男 1女 2未知）',
                            `avatar` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '头像地址',
                            `password` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '密码',
                            `status` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '0' COMMENT '帐号状态（0正常 1停用）',
                            `del_flag` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '0' COMMENT '删除标志（0代表存在 2代表删除）',
                            `login_ip` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '最后登录IP',
                            `login_date` datetime DEFAULT NULL COMMENT '最后登录时间',
                            `create_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '创建者',
                            `create_time` datetime DEFAULT NULL COMMENT '创建时间',
                            `update_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '更新者',
                            `update_time` datetime DEFAULT NULL COMMENT '更新时间',
                            `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '备注',
                            PRIMARY KEY (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=106 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='用户信息表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sys_user`
--

LOCK TABLES `sys_user` WRITE;
/*!40000 ALTER TABLE `sys_user` DISABLE KEYS */;
INSERT INTO `sys_user` (`user_id`, `dept_id`, `user_name`, `nick_name`, `user_type`, `email`, `phonenumber`, `sex`, `avatar`, `password`, `status`, `del_flag`, `login_ip`, `login_date`, `create_by`, `create_time`, `update_by`, `update_time`, `remark`) VALUES (1,103,'admin','一颗星','00','astar@qq.com','15888888888','0','','$2a$10$JQxqOWykZHqqAgE7Wj/wjeKkOPj4/dHKTzfZ38CoyzmUK7zVU0kRy','0','0','120.244.234.130','2024-03-02 21:04:26','admin','2024-03-01 19:39:37','','2024-03-02 21:04:25','管理员'),(104,NULL,'wzt','wzt','00','','','0','','$2a$10$25xTSWQxHPDWjJ62cKafF.BmgGP7kjnMSr4EU/3Qv7mYqk.GVGpSu','0','0','127.0.0.1','2024-03-02 19:46:20','','2024-03-02 19:36:40','','2024-03-02 19:46:19',NULL),(105,NULL,'wzy','wzy','00','','','0','','$2a$10$Ze3APXY.PU6yhng1FEmMJO4OFBTmEEHZ1RCxsNayHdvLAySKP0G4m','0','0','120.244.234.130','2024-03-02 21:05:06','','2024-03-02 20:41:12','','2024-03-02 21:05:06',NULL);
/*!40000 ALTER TABLE `sys_user` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sys_user_post`
--

DROP TABLE IF EXISTS `sys_user_post`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sys_user_post` (
                                 `user_id` bigint NOT NULL COMMENT '用户ID',
                                 `post_id` bigint NOT NULL COMMENT '岗位ID',
                                 PRIMARY KEY (`user_id`,`post_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='用户与岗位关联表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sys_user_post`
--

LOCK TABLES `sys_user_post` WRITE;
/*!40000 ALTER TABLE `sys_user_post` DISABLE KEYS */;
INSERT INTO `sys_user_post` (`user_id`, `post_id`) VALUES (1,1);
/*!40000 ALTER TABLE `sys_user_post` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sys_user_role`
--

DROP TABLE IF EXISTS `sys_user_role`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sys_user_role` (
                                 `user_id` bigint NOT NULL COMMENT '用户ID',
                                 `role_id` bigint NOT NULL COMMENT '角色ID',
                                 PRIMARY KEY (`user_id`,`role_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='用户和角色关联表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sys_user_role`
--

LOCK TABLES `sys_user_role` WRITE;
/*!40000 ALTER TABLE `sys_user_role` DISABLE KEYS */;
INSERT INTO `sys_user_role` (`user_id`, `role_id`) VALUES (1,1),(104,100),(105,100);
/*!40000 ALTER TABLE `sys_user_role` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_questionnaire`
--

DROP TABLE IF EXISTS `tb_questionnaire`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `tb_questionnaire` (
                                    `id` int NOT NULL AUTO_INCREMENT COMMENT '主键',
                                    `created_time` datetime DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                                    `created_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '创建人',
                                    `updated_time` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
                                    `updated_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '更新人',
                                    `title` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '标题',
                                    `form_json` json DEFAULT NULL COMMENT '表单配置',
                                    `form_url` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '表单地址',
                                    `status` tinyint DEFAULT '0' COMMENT '表单状态：false未发布，true已发布',
                                    `del_flag` char(1) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '0' COMMENT '删除标志（0代表存在 2代表删除）',
                                    `remark` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci COMMENT '描述',
                                    PRIMARY KEY (`id`),
                                    UNIQUE KEY `tb_questionnaire_pk` (`form_url`)
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='问卷调查管理';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_questionnaire`
--

LOCK TABLES `tb_questionnaire` WRITE;
/*!40000 ALTER TABLE `tb_questionnaire` DISABLE KEYS */;
INSERT INTO `tb_questionnaire` (`id`, `created_time`, `created_by`, `updated_time`, `updated_by`, `title`, `form_json`, `form_url`, `status`, `del_flag`, `remark`) VALUES (12,'2024-03-02 17:27:12','admin','2024-03-02 17:28:11','admin','评分问卷调查','{\"size\": \"medium\", \"span\": 24, \"fields\": [{\"type\": \"input\", \"style\": {\"width\": \"100%\"}, \"__slot__\": {\"append\": \"\", \"prepend\": \"\"}, \"disabled\": false, \"readonly\": false, \"clearable\": true, \"maxlength\": null, \"__config__\": {\"tag\": \"el-input\", \"span\": 24, \"label\": \"单行文本\", \"formId\": 101, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"input\", \"document\": \"https://element.eleme.cn/#/zh-CN/component/input\", \"required\": true, \"changeTag\": true, \"renderKey\": \"1011709371676616\", \"showLabel\": true, \"labelWidth\": null}, \"__vModel__\": \"field101\", \"placeholder\": \"请输入单行文本单行文本\", \"prefix-icon\": \"\", \"suffix-icon\": \"\", \"show-word-limit\": false}, {\"type\": \"textarea\", \"style\": {\"width\": \"100%\"}, \"autosize\": {\"maxRows\": 4, \"minRows\": 4}, \"disabled\": false, \"readonly\": false, \"maxlength\": null, \"__config__\": {\"tag\": \"el-input\", \"span\": 24, \"label\": \"多行文本\", \"formId\": 102, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"textarea\", \"document\": \"https://element.eleme.cn/#/zh-CN/component/input\", \"required\": true, \"changeTag\": true, \"renderKey\": \"1021709371677509\", \"showLabel\": true, \"labelWidth\": null}, \"__vModel__\": \"field102\", \"placeholder\": \"请输入多行文本\", \"show-word-limit\": false}, {\"type\": \"password\", \"style\": {\"width\": \"100%\"}, \"__slot__\": {\"append\": \"\", \"prepend\": \"\"}, \"disabled\": false, \"readonly\": false, \"clearable\": true, \"maxlength\": null, \"__config__\": {\"tag\": \"el-input\", \"span\": 24, \"label\": \"密码\", \"formId\": 103, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"password\", \"document\": \"https://element.eleme.cn/#/zh-CN/component/input\", \"required\": true, \"changeTag\": true, \"renderKey\": \"1031709371678330\", \"showLabel\": true, \"labelWidth\": null}, \"__vModel__\": \"field103\", \"placeholder\": \"请输入密码\", \"prefix-icon\": \"\", \"suffix-icon\": \"\", \"show-password\": true, \"show-word-limit\": false}, {\"step\": 1, \"type\": \"step\", \"disabled\": false, \"__config__\": {\"tag\": \"el-input-number\", \"span\": 24, \"label\": \"计数器\", \"formId\": 104, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"number\", \"document\": \"https://element.eleme.cn/#/zh-CN/component/input-number\", \"required\": true, \"changeTag\": true, \"renderKey\": \"1041709371678707\", \"showLabel\": true, \"labelWidth\": null}, \"__vModel__\": \"field104\", \"placeholder\": \"计数器\", \"step-strictly\": false, \"controls-position\": \"\"}, {\"type\": \"editor\", \"height\": 300, \"branding\": false, \"__config__\": {\"tag\": \"tinymce\", \"span\": 24, \"label\": \"编辑器\", \"formId\": 105, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"rich-text\", \"document\": \"http://tinymce.ax-z.cn\", \"required\": true, \"changeTag\": true, \"renderKey\": 1709371679402, \"showLabel\": true, \"labelWidth\": null, \"defaultValue\": null}, \"__vModel__\": \"field105\", \"placeholder\": \"请输入编辑器\"}, {\"type\": \"select\", \"style\": {\"width\": \"100%\"}, \"__slot__\": {\"options\": [{\"label\": \"选项一\", \"value\": 1}, {\"label\": \"选项二\", \"value\": 2}]}, \"disabled\": false, \"multiple\": false, \"clearable\": true, \"__config__\": {\"tag\": \"el-select\", \"span\": 24, \"label\": \"下拉选择\", \"formId\": 106, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"select\", \"document\": \"https://element.eleme.cn/#/zh-CN/component/select\", \"required\": true, \"changeTag\": true, \"renderKey\": \"1061709371680267\", \"showLabel\": true, \"labelWidth\": null}, \"__vModel__\": \"field106\", \"filterable\": false, \"placeholder\": \"请选择下拉选择\"}, {\"size\": \"medium\", \"type\": \"radio\", \"style\": {}, \"__slot__\": {\"options\": [{\"label\": \"选项一\", \"value\": 1}, {\"label\": \"选项二\", \"value\": 2}]}, \"disabled\": false, \"__config__\": {\"tag\": \"el-radio-group\", \"span\": 24, \"label\": \"单选框组\", \"border\": false, \"formId\": 108, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"radio\", \"document\": \"https://element.eleme.cn/#/zh-CN/component/radio\", \"required\": true, \"changeTag\": true, \"renderKey\": \"1081709371681235\", \"showLabel\": true, \"labelWidth\": null, \"optionType\": \"default\"}, \"__vModel__\": \"field108\"}, {\"size\": \"medium\", \"type\": \"checkbox\", \"style\": {}, \"__slot__\": {\"options\": [{\"label\": \"选项一\", \"value\": 1}, {\"label\": \"选项二\", \"value\": 2}]}, \"disabled\": false, \"__config__\": {\"tag\": \"el-checkbox-group\", \"span\": 24, \"label\": \"多选框组\", \"border\": false, \"formId\": 109, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"checkbox\", \"document\": \"https://element.eleme.cn/#/zh-CN/component/checkbox\", \"required\": true, \"changeTag\": true, \"renderKey\": \"1091709371681527\", \"showLabel\": true, \"labelWidth\": null, \"optionType\": \"default\", \"defaultValue\": []}, \"__vModel__\": \"field109\"}, {\"type\": \"switch\", \"style\": {}, \"disabled\": false, \"__config__\": {\"tag\": \"el-switch\", \"span\": 24, \"label\": \"开关\", \"formId\": 110, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"switch\", \"document\": \"https://element.eleme.cn/#/zh-CN/component/switch\", \"required\": true, \"changeTag\": true, \"renderKey\": \"1101709371682568\", \"showLabel\": true, \"labelWidth\": null, \"defaultValue\": false}, \"__vModel__\": \"field110\", \"active-text\": \"\", \"active-color\": null, \"active-value\": true, \"inactive-text\": \"\", \"inactive-color\": null, \"inactive-value\": false}, {\"max\": 100, \"min\": 0, \"step\": 1, \"type\": \"slider\", \"range\": false, \"disabled\": false, \"__config__\": {\"tag\": \"el-slider\", \"span\": 24, \"label\": \"滑块\", \"formId\": 111, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"slider\", \"document\": \"https://element.eleme.cn/#/zh-CN/component/slider\", \"required\": true, \"changeTag\": true, \"renderKey\": \"1111709371682889\", \"showLabel\": true, \"labelWidth\": null, \"defaultValue\": 0}, \"__vModel__\": \"field111\", \"show-stops\": false}, {\"type\": \"time\", \"style\": {\"width\": \"100%\"}, \"format\": \"HH:mm:ss\", \"disabled\": false, \"clearable\": true, \"__config__\": {\"tag\": \"el-time-picker\", \"span\": 24, \"label\": \"时间选择\", \"formId\": 112, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"time\", \"document\": \"https://element.eleme.cn/#/zh-CN/component/time-picker\", \"required\": true, \"changeTag\": true, \"renderKey\": \"1121709371683416\", \"showLabel\": true, \"labelWidth\": null, \"defaultValue\": null}, \"__vModel__\": \"field112\", \"placeholder\": \"请选择时间选择\", \"value-format\": \"HH:mm:ss\", \"picker-options\": {\"selectableRange\": \"00:00:00-23:59:59\"}}, {\"type\": \"timerange\", \"style\": {\"width\": \"100%\"}, \"format\": \"HH:mm:ss\", \"disabled\": false, \"is-range\": true, \"clearable\": true, \"__config__\": {\"tag\": \"el-time-picker\", \"span\": 24, \"label\": \"时间范围\", \"formId\": 113, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"time-range\", \"document\": \"https://element.eleme.cn/#/zh-CN/component/time-picker\", \"required\": true, \"changeTag\": true, \"renderKey\": \"1131709371683734\", \"showLabel\": true, \"labelWidth\": null, \"defaultValue\": null}, \"__vModel__\": \"field113\", \"value-format\": \"HH:mm:ss\", \"end-placeholder\": \"结束时间\", \"range-separator\": \"至\", \"start-placeholder\": \"开始时间\"}, {\"type\": \"date\", \"style\": {\"width\": \"100%\"}, \"format\": \"yyyy-MM-dd\", \"disabled\": false, \"readonly\": false, \"clearable\": true, \"__config__\": {\"tag\": \"el-date-picker\", \"span\": 24, \"label\": \"日期选择\", \"formId\": 114, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"date\", \"document\": \"https://element.eleme.cn/#/zh-CN/component/date-picker\", \"required\": true, \"changeTag\": true, \"renderKey\": \"1141709371684329\", \"showLabel\": true, \"labelWidth\": null, \"defaultValue\": null}, \"__vModel__\": \"field114\", \"placeholder\": \"请选择日期选择\", \"value-format\": \"yyyy-MM-dd\"}, {\"type\": \"daterange\", \"style\": {\"width\": \"100%\"}, \"format\": \"yyyy-MM-dd\", \"disabled\": false, \"readonly\": false, \"clearable\": true, \"__config__\": {\"tag\": \"el-date-picker\", \"span\": 24, \"label\": \"日期范围\", \"formId\": 115, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"date-range\", \"document\": \"https://element.eleme.cn/#/zh-CN/component/date-picker\", \"required\": true, \"changeTag\": true, \"renderKey\": \"1151709371684681\", \"showLabel\": true, \"labelWidth\": null, \"defaultValue\": null}, \"__vModel__\": \"field115\", \"value-format\": \"yyyy-MM-dd\", \"end-placeholder\": \"结束日期\", \"range-separator\": \"至\", \"start-placeholder\": \"开始日期\"}, {\"max\": 5, \"type\": \"rate\", \"style\": {}, \"disabled\": false, \"show-text\": false, \"__config__\": {\"tag\": \"el-rate\", \"span\": 24, \"label\": \"评分\", \"formId\": 116, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"rate\", \"document\": \"https://element.eleme.cn/#/zh-CN/component/rate\", \"required\": true, \"changeTag\": true, \"renderKey\": \"1161709371685196\", \"showLabel\": true, \"labelWidth\": null, \"defaultValue\": 0}, \"__vModel__\": \"field116\", \"allow-half\": false, \"show-score\": false}, {\"size\": \"medium\", \"type\": \"color\", \"disabled\": false, \"__config__\": {\"tag\": \"el-color-picker\", \"span\": 24, \"label\": \"颜色选择\", \"formId\": 117, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"color\", \"document\": \"https://element.eleme.cn/#/zh-CN/component/color-picker\", \"required\": true, \"changeTag\": true, \"renderKey\": \"1171709371685684\", \"showLabel\": true, \"labelWidth\": null, \"defaultValue\": null}, \"__vModel__\": \"field117\", \"show-alpha\": false, \"color-format\": \"\"}], \"gutter\": 15, \"formRef\": \"elForm\", \"disabled\": false, \"formBtns\": true, \"formModel\": \"formData\", \"formRules\": \"rules\", \"labelWidth\": 100, \"labelPosition\": \"right\"}','JEoNgV',1,'0','感谢您的评价'),(14,'2024-03-02 20:54:06','wzy','2024-03-02 21:03:19','wzy','大学生就业问卷调查','{\"size\": \"medium\", \"span\": 24, \"fields\": [{\"type\": \"input\", \"style\": {\"width\": \"100%\"}, \"__slot__\": {\"append\": \"\", \"prepend\": \"\"}, \"disabled\": false, \"readonly\": false, \"clearable\": true, \"maxlength\": null, \"__config__\": {\"tag\": \"el-input\", \"span\": 24, \"label\": \"姓名\", \"formId\": 101, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"input\", \"document\": \"https://element.eleme.cn/#/zh-CN/component/input\", \"required\": true, \"changeTag\": true, \"renderKey\": \"1011709384474421\", \"showLabel\": true, \"labelWidth\": null}, \"__vModel__\": \"field101\", \"placeholder\": \"请输入姓名\", \"prefix-icon\": \"\", \"suffix-icon\": \"\", \"show-word-limit\": false}, {\"size\": \"medium\", \"type\": \"radio\", \"style\": {}, \"__slot__\": {\"options\": [{\"label\": \"就业\", \"value\": 1}, {\"label\": \"未就业\", \"value\": 2}]}, \"disabled\": false, \"__config__\": {\"tag\": \"el-radio-group\", \"span\": 24, \"label\": \"是否就业\", \"border\": false, \"formId\": 102, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"radio\", \"document\": \"https://element.eleme.cn/#/zh-CN/component/radio\", \"required\": true, \"changeTag\": true, \"renderKey\": \"1021709384488343\", \"showLabel\": true, \"labelWidth\": null, \"optionType\": \"default\"}, \"__vModel__\": \"field102\"}, {\"type\": \"date\", \"style\": {\"width\": \"100%\"}, \"format\": \"yyyy-MM-dd\", \"disabled\": false, \"readonly\": false, \"clearable\": true, \"__config__\": {\"tag\": \"el-date-picker\", \"span\": 24, \"label\": \"就业日期\", \"formId\": 103, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"date\", \"document\": \"https://element.eleme.cn/#/zh-CN/component/date-picker\", \"required\": true, \"changeTag\": true, \"renderKey\": \"1031709384504930\", \"showLabel\": true, \"labelWidth\": null, \"defaultValue\": null}, \"__vModel__\": \"field103\", \"placeholder\": \"请选择就业日期\", \"value-format\": \"yyyy-MM-dd\"}, {\"type\": \"select\", \"style\": {\"width\": \"100%\"}, \"__slot__\": {\"options\": [{\"label\": \"北京\", \"value\": 1}, {\"label\": \"上海\", \"value\": 2}, {\"label\": \"深圳\", \"value\": \"\"}, {\"label\": \"广州\", \"value\": \"\"}]}, \"disabled\": false, \"multiple\": false, \"clearable\": true, \"__config__\": {\"tag\": \"el-select\", \"span\": 24, \"label\": \"工作地点\", \"formId\": 104, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"select\", \"document\": \"https://element.eleme.cn/#/zh-CN/component/select\", \"required\": true, \"changeTag\": true, \"renderKey\": \"1041709384519492\", \"showLabel\": true, \"labelWidth\": null}, \"__vModel__\": \"field104\", \"filterable\": false, \"placeholder\": \"请选择工作地点\"}, {\"type\": \"textarea\", \"style\": {\"width\": \"100%\"}, \"autosize\": {\"maxRows\": 4, \"minRows\": 4}, \"disabled\": false, \"readonly\": false, \"maxlength\": null, \"__config__\": {\"tag\": \"el-input\", \"span\": 24, \"label\": \"备注\", \"formId\": 105, \"layout\": \"colFormItem\", \"regList\": [], \"tagIcon\": \"textarea\", \"document\": \"https://element.eleme.cn/#/zh-CN/component/input\", \"required\": true, \"changeTag\": true, \"renderKey\": \"1051709384547092\", \"showLabel\": true, \"labelWidth\": null}, \"__vModel__\": \"field105\", \"placeholder\": \"请输入备注\", \"show-word-limit\": false}], \"gutter\": 15, \"formRef\": \"elForm\", \"disabled\": false, \"formBtns\": true, \"formModel\": \"formData\", \"formRules\": \"rules\", \"labelWidth\": 100, \"labelPosition\": \"right\"}','JcIkpV',1,'0','非常感谢您认真填写此问卷！');
/*!40000 ALTER TABLE `tb_questionnaire` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_questionnaire_user`
--

DROP TABLE IF EXISTS `tb_questionnaire_user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `tb_questionnaire_user` (
                                         `id` int NOT NULL AUTO_INCREMENT COMMENT '主键',
                                         `created_time` datetime DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                                         `qs_id` int DEFAULT NULL COMMENT '问卷ID',
                                         `data_json` json DEFAULT NULL COMMENT '表单配置',
                                         `ip_addr` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT 'ip',
                                         PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='填写问卷管理';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_questionnaire_user`
--

LOCK TABLES `tb_questionnaire_user` WRITE;
/*!40000 ALTER TABLE `tb_questionnaire_user` DISABLE KEYS */;
INSERT INTO `tb_questionnaire_user` (`id`, `created_time`, `qs_id`, `data_json`, `ip_addr`) VALUES (5,'2024-03-02 17:28:50',12,'{\"field101\": \"你好\", \"field102\": \"多行文本1\", \"field103\": \"123\", \"field104\": 3, \"field105\": \"<p><span style=\\\"color: #e03e2d;\\\">测试</span></p>\", \"field106\": 1, \"field108\": 2, \"field109\": [1, 2], \"field110\": true, \"field111\": 40, \"field112\": \"17:28:41\", \"field113\": [\"17:28:42\", \"18:28:42\"], \"field114\": \"2024-03-20\", \"field115\": [\"2024-03-13\", \"2024-04-22\"], \"field116\": 3, \"field117\": \"#DC1010\"}','127.0.0.1'),(6,'2024-03-02 17:30:19',13,'{\"field102\": [1, 12]}','127.0.0.1'),(7,'2024-03-02 17:30:33',13,'{\"field102\": [1, 2, 14]}','127.0.0.1'),(8,'2024-03-02 18:07:33',12,'{\"field101\": \"123\", \"field102\": \"123\", \"field103\": \"123\", \"field104\": 3, \"field105\": \"<p>123</p>\", \"field106\": 2, \"field108\": 1, \"field109\": [1], \"field110\": false, \"field111\": 8, \"field112\": \"18:07:22\", \"field113\": [\"18:07:23\", \"19:07:23\"], \"field114\": \"2024-03-11\", \"field115\": [\"2024-03-28\", \"2024-04-28\"], \"field116\": 5, \"field117\": \"#1A0D0D\"}','127.0.0.1'),(9,'2024-03-02 21:05:57',14,'{\"field101\": \"一颗星\", \"field102\": 2, \"field103\": \"2024-03-02\", \"field104\": 1, \"field105\": \"测试问卷调查系统\"}','120.244.234.130');
/*!40000 ALTER TABLE `tb_questionnaire_user` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2024-03-02 21:08:03
