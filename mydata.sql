CREATE TABLE Users
(
  User_Id INT PRIMARY KEY,
  Username VARCHAR
(50) NOT NULL,
  Password VARCHAR
(50) NOT NULL,
  FirstName VARCHAR(50) NOT NULL,
  LastName VARCHAR(50) NOT NULL,
  Gender VARCHAR(50) NOT NULL,
  Email VARCHAR(50) NOT NULL UNIQUE,
  Hash VARCHAR(100) NOT NULL,
  Age NUMBER(2) NOT NULL CHECK (Age BETWEEN 0 AND 75),
  UserType VARCHAR(10) NOT NULL CHECK (UserType IN ('admin', 'student'))
);

CREATE TABLE TestResults
(
  TestResultsId INT PRIMARY KEY,
  User_Id INT NOT NULL,
  SubjectId INT NOT NULL,
  Score INT NOT NULL,
  FOREIGN KEY (User_Id) REFERENCES Users(User_Id),
  FOREIGN KEY (SubjectId) REFERENCES Subjects(SubjectId)
);

CREATE TABLE QuestionsAnswers
(
  QuestionAnswersID INT PRIMARY KEY,
  QuestionText VARCHAR(500) NOT NULL,
  Option1_Answer VARCHAR(500) NOT NULL,
  Option2_Answer VARCHAR(500) NOT NULL,
  Option3_Answer VARCHAR(500) NOT NULL,
  Option4_Answer VARCHAR(500) NOT NULL,
  SelectedOption INT NOT NULL,
  Correct_Answer INT NOT NULL,
  User_Id INT NOT NULL,
  SubjectID INT NOT NULL,
  FOREIGN KEY (SubjectID) REFERENCES Subjects(SubjectID),
  FOREIGN KEY (User_Id) REFERENCES Users(User_Id)
);

-- create the Courses table
CREATE TABLE Subjects
(
  SubjectId INT PRIMARY KEY,
  SubjectName VARCHAR(255) NOT NULL,
  SubjectText VARCHAR
(255) NOT NULL
);

UPDATE TestResults
SET CorrectAnswers = (
  SELECT COUNT(*)
FROM QuestionsAnswers
WHERE QuestionsAnswers.User_Id = TestResults.User_Id AND
  QuestionsAnswers.SubjectID = TestResults.SubjectId AND
  QuestionsAnswers.Correct_Answer = QuestionsAnswers.SelectedOption
);

CREATE TABLE TestResults
(
  TestResultsId INT PRIMARY KEY,
  User_Id INT NOT NULL,
  SubjectId INT NOT NULL,
  CorrectAnswers INT NOT NULL,
  Score INT NOT NULL,
  FOREIGN KEY (User_Id) REFERENCES Users(User_Id),
  FOREIGN KEY (SubjectId) REFERENCES Subjects(SubjectId)
);


CREATE TABLE questions
(
  questions_id INT PRIMARY KEY,
  question_text VARCHAR(500) NOT NULL,
  option_a TEXT NOT NULL,
  option_b TEXT NOT NULL,
  option_c TEXT NOT NULL,
  option_d TEXT NOT NULL,
  correct_option INT NOT NULL,
  created_by INT NOT NULL,
  SubjectId INT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE responses
(
  id SERIAL PRIMARY KEY,
  question_id INTEGER NOT NULL,
  student_id INTEGER NOT NULL,
  answer INTEGER NOT NULL,
  is_correct BOOLEAN NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);




CREATE TABLE questions
(
  questions_id BIGSERIAL PRIMARY KEY,
  question_prompt TEXT NOT NULL,
  option_a TEXT NOT NULL,
  option_b TEXT NOT NULL,
  option_c TEXT NOT NULL,
  option_d TEXT NOT NULL,
  correct_option INT NOT NULL,
  created_by INT NOT NULL,
  SubjectId INT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE responses
(
  responses_id INT PRIMARY KEY,
  questions_id INT NOT NULL,
  User_Id INT NOT NULL,
  answer INT NOT NULL,
  is_correct BOOLEAN NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE topics
(
  topicsId BIGINT PRIMARY KEY,
  topicsName VARCHAR(255) NOT NULL,
  topicsText VARCHAR(255) NOT NULL,
  topicscreator VARCHAR(30) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);

ALTER TABLE topics 
ALTER COLUMN topicsId TYPE
SERIAL,
ALTER COLUMN topicsId
DROP DEFAULT,
ALTER COLUMN topicsId
SET NOT NULL;




newly adopted
CREATE TABLE topics
(
  topicsId BIGSERIAL PRIMARY KEY,
  topicsName VARCHAR(255) NOT NULL,
  topicsText VARCHAR(255) NOT NULL,
  topicscreator VARCHAR(30) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);



CREATE TABLE questions
(
  questions_id BIGSERIAL PRIMARY KEY,
  question_prompt TEXT NOT NULL,
  option_a VARCHAR(255) NOT NULL,
  option_b VARCHAR(255) NOT NULL,
  option_c VARCHAR(255) NOT NULL,
  option_d VARCHAR(255) NOT NULL,
  correct_option INT NOT NULL,
  created_by INT NOT NULL,
  topicsId INT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (created_by) REFERENCES Users(User_Id),
  FOREIGN KEY (topicsId) REFERENCES topics(topicsId)
);

apr 29

CREATE TABLE questions
(
  questions_id BIGSERIAL PRIMARY KEY,
  question_prompt TEXT NOT NULL,
  option_a VARCHAR(255) NOT NULL,
  option_b VARCHAR(255) NOT NULL,
  option_c VARCHAR(255) NOT NULL,
  option_d VARCHAR(255) NOT NULL,
  correct_option INT NOT NULL,
  topicsId INT ,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (topicsId) REFERENCES topics(topicsId)
);

CREATE TABLE topics
(
  topicsId BIGSERIAL PRIMARY KEY,
  topicsName VARCHAR(255) NOT NULL,
  topicsText VARCHAR(255) NOT NULL,
  topicscreator VARCHAR(30) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);



CREATE TABLE questions
(
  questions_id BIGSERIAL PRIMARY KEY,
  topicsName VARCHAR (255) NOT NULL,
  question_prompt TEXT NOT NULL,
  option_a VARCHAR(255) NOT NULL,
  option_b VARCHAR(255) NOT NULL,
  option_c VARCHAR(255) NOT NULL,
  option_d VARCHAR(255) NOT NULL,
  correct_option INT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE TestResults
(
  TestResultsId BIGSERIAL PRIMARY KEY,
  User_Id INT NOT NULL,
  questions_id INT NOT NULL,
  testdate TIMESTAMP DEFAULT
CURRENT_TIMESTAMP,
  Score INT NOT NULL,
  FOREIGN KEY (User_Id) REFERENCES Users(User_Id),
  FOREIGN KEY (questions_id) REFERENCES questions(questions_id)
);

CREATE TABLE responses
(
  responses_id BIGSERIAL PRIMARY KEY,
  questions_id INT NOT NULL,
  answer INT NOT NULL,
  is_correct BOOLEAN NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE Users
(
  User_Id INT PRIMARY KEY,
  Username VARCHAR
(50) NOT NULL,
  Password VARCHAR
(50) NOT NULL,
  FirstName VARCHAR(50) NOT NULL,
  LastName VARCHAR(50) NOT NULL,
  Gender VARCHAR(50) NOT NULL,
  Email VARCHAR(50) NOT NULL UNIQUE,
  Hash VARCHAR(100) NOT NULL,
  Age NUMBER(2) NOT NULL CHECK (Age BETWEEN 0 AND 75),
  UserType VARCHAR(10) NOT NULL CHECK (UserType IN ('admin', 'student'))
);

CREATE TABLE Sessions
(
  SessionID VARCHAR(100) PRIMARY KEY,
  User_Id INT NOT NULL,
  CONSTRAINT FK_UserID FOREIGN KEY (User_Id) REFERENCES Users(User_Id)
);
