-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Хост: localhost

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- База данных: `modsec_logs`
--

-- --------------------------------------------------------

--
-- Структура таблицы `logs`
--

CREATE TABLE `logs` (
  `id` int(11) NOT NULL,
  `REQUEST_METHOD` varchar(10) DEFAULT NULL,
  `REQUEST_URI` text DEFAULT NULL,
  `REMOTE_ADDR` varchar(45) DEFAULT NULL,
  `ruleId` varchar(10) DEFAULT NULL,
  `Host` varchar(255) DEFAULT NULL,
  `msg` text DEFAULT NULL,
  `data` text DEFAULT NULL,
  `unique_id` varchar(50) DEFAULT NULL,
  `severity` varchar(20) DEFAULT NULL,
  `maturity` int(2) DEFAULT NULL,
  `accuracy` int(2) DEFAULT NULL,
  `User_Agent` text DEFAULT NULL,
  `responce_header` int(3) DEFAULT NULL,
  `Engine_Mode` varchar(20) DEFAULT NULL,
  `Score` int(2) DEFAULT NULL,
  `SQLi` int(2) DEFAULT NULL,
  `XSS` int(2) DEFAULT NULL,
  `phase` int(1) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Индексы сохранённых таблиц
--

--
-- Индексы таблицы `logs`
--
ALTER TABLE `logs`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT для сохранённых таблиц
--

--
-- AUTO_INCREMENT для таблицы `logs`
--
ALTER TABLE `logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
