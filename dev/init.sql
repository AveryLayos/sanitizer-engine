-- init.sql
CREATE TABLE IF NOT EXISTS `job_request` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `file_content` longblob NOT NULL,
  `file_content_content_type` varchar(255) NOT NULL,
  `score` int DEFAULT NULL,
  `status` varchar(255) NOT NULL,
  `file_type` varchar(255) NOT NULL,
  `request_type` varchar(255) NOT NULL,
  `priority` varchar(255) NOT NULL,
  `file_name` varchar(255) DEFAULT NULL,
  `user_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
CREATE TABLE `job_execution_report` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `start_time` datetime(6),
  `end_time` datetime(6),
  `execution_node` varchar(255) DEFAULT NULL,
  `execution_log` longtext,
  `status` varchar(255) NOT NULL,
  `job_request_id` bigint DEFAULT NULL,
  `user_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_job_execution_report__job_request_id` FOREIGN KEY (`job_request_id`) REFERENCES `job_request` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
