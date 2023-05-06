CREATE TABLE Users
(
    User_Id bigserial PRIMARY KEY,
    FirstName VARCHAR(50) NOT NULL,
    LastName VARCHAR(50) NOT NULL,
    Gender VARCHAR(50) NOT NULL,
    Email VARCHAR(50) NOT NULL UNIQUE,
    Age NUMBER(2) NOT NULL CHECK (Age BETWEEN 0 AND 75),
    UserType VARCHAR(10) NOT NULL CHECK (UserType IN ('admin', 'student'))
);



CREATE TABLE QuestionsAnswers
(
    QuestionAnswersID bigserial PRIMARY KEY,
    QuestionText VARCHAR(500) NOT NULL,
    Option1_Answer VARCHAR(500) NOT NULL,
    Option2_Answer VARCHAR(500) NOT NULL,
    Option3_Answer VARCHAR(500) NOT NULL,
    Option4_Answer VARCHAR(500) NOT NULL,
    SelectedOption INT NOT NULL,
    Correct_Answer INT NOT NULL,
    SubjectId INT NOT NULL,
    FOREIGN KEY (SubjectId) REFERENCES Subjects(SubjectId)
);

-- create the Courses table
CREATE TABLE Subjects
(
    SubjectId bigserial PRIMARY KEY,
    SubjectName VARCHAR(255) NOT NULL,
    SubjectText VARCHAR(255) NOT NULL
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
    TestResultsId bigserial PRIMARY KEY,
    User_Id INT NOT NULL,
    SubjectId INT NOT NULL,
    TestDate DATE NOT NULL,
    CorrectAnswers INT NOT NULL,
    Score INT NOT NULL,
    FOREIGN KEY (User_Id) REFERENCES Users(User_Id),
    FOREIGN KEY (SubjectId) REFERENCES Subjects(SubjectId)
);
