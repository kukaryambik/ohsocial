CREATE TABLE `userList` (
  `ID` bigint unsigned AUTO_INCREMENT NOT NULL PRIMARY KEY,
  `login` varchar(255) NOT NULL UNIQUE,
  `password` varchar(64) NOT NULL,
  `firstName` varchar(255) NOT NULL DEFAULT '',
  `lastName` varchar(255) NOT NULL DEFAULT '',
  `dateOfBirth` varchar(10) NOT NULL DEFAULT '',
  `gender` varchar(10) NOT NULL DEFAULT '',
  `interests` varchar(255) NOT NULL DEFAULT '',
  `bio` varchar(255) NOT NULL DEFAULT '',
  `location` varchar(255) NOT NULL DEFAULT '',
  `created` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) DEFAULT CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
--
CREATE INDEX userListLoginPassword ON userList (login, password);
CREATE INDEX userListLoginName ON userList (login, firstName, lastName, updated);
--
CREATE TABLE `chatList` (
  `ID` bigint unsigned AUTO_INCREMENT NOT NULL PRIMARY KEY,
  `name` varchar(255) NOT NULL DEFAULT '',
  `created` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) DEFAULT CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
--
CREATE INDEX chatListIDName ON chatList (ID, name);
--
CREATE TABLE `chatUser` (
  `chatID` bigint unsigned NOT NULL,
  `userID` bigint unsigned NOT NULL,
  PRIMARY KEY (chatID, userID),
  CONSTRAINT chatUserChatID FOREIGN KEY (chatID) REFERENCES chatList(ID) ON DELETE CASCADE,
  CONSTRAINT chatUserUserID FOREIGN KEY (userID) REFERENCES userList(ID)
);
--
CREATE TABLE `chats` (
  `chatID` bigint unsigned NOT NULL REFERENCES chatList (ID) ON DELETE CASCADE,
  `userID` bigint unsigned NOT NULL REFERENCES userList (ID),
  `msg` text,
  `created` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) DEFAULT CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci PARTITION BY HASH (chatID);
--
CREATE INDEX chatsChatUserTime ON chats (chatID, userID, created);
