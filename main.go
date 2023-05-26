package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"

	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	//uuid "github.com/gofrs/uuid/v3"
	"golang.org/x/crypto/bcrypt"

	//"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
)

var dbSession = map[string]string{}
var dbUser = map[string]Users{}
var store = sessions.NewCookieStore([]byte("super-secret"))

/*
	type Users struct {
		User_Id  int
		UserType string
	}
*/
type Users struct {
	User_Id   int
	Username  string
	Password  string
	FirstName string
	LastName  string
	Gender    string
	Email     string
	Hash      string
	Age       int
	UserType  string
}

type Question struct {
	QuestionID     int
	TopicsName     string
	QuestionPrompt string
	OptionA        string
	OptionB        string
	OptionC        string
	OptionD        string
	CorrectOption  int
	CreatedAt      time.Time
}

type Response struct {
	ResponseID int
	QuestionID int
	//StudentID  int                 removed
	Answer    int
	IsCorrect bool
	UserID    int
	CreatedAt time.Time
}

type TestResult struct {
	TestResultsId int64
	UserID        int
	QuestionID    int
	Testdate      time.Time
	Score         int
	Question      Question
	Response      Response
}

/*
	type TestResult struct {
		UserID     int
		QuestionID int
		Score      int
		CreatedAt  time.Time
	}
*/
var (
	templates = template.Must(template.ParseGlob("template/*"))
)
var db *sql.DB
var err error

//var store = sessions.NewCookieStore([]byte("msc-project"))

func main() {
	fmt.Println("initailizing the Msc Project PostgreSQL database.....")
	db, err = sql.Open("postgres", "user=postgres password=charles dbname=elearning host=localhost port=5432 sslmode=disable")
	if err != nil {
		fmt.Println("Error connecting to the PostgreSQL database:", err.Error())
		return
	}
	fmt.Println("The Msc Project PostgreSQL database seems okay")
	defer db.Close()

	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	http.HandleFunc("/", home)
	http.HandleFunc("/index", index)
	http.HandleFunc("/register", register)
	http.HandleFunc("/registerAuthorization", registerAuthorization)
	http.HandleFunc("/login", login)
	http.HandleFunc("/loginAuthorization", loginAuthorization)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/student", Auth(student))
	//the questions part
	http.HandleFunc("/insertquestion", (insertquestion))
	http.HandleFunc("/insertedquestion", (insertedquestion))
	http.HandleFunc("/question", (question))
	http.HandleFunc("/updatequestion", (updatequestion))
	http.HandleFunc("/deletequestion", (deletequestion))
	//student part
	// Route to show all questions to student
	http.HandleFunc("/viewquestions", viewquestions)

	// Route to answer the questions by student
	http.HandleFunc("/answerquestions", (answerquestions))
	http.HandleFunc("/testresults", testresults)

	//get by topic name
	http.HandleFunc("/computer-science/questions", viewComputerScienceQuestions)
	http.HandleFunc("/artificial-intelligence/questions", viewArtificialIntelligenceQuestions)
	http.HandleFunc("/data-analytics/questions", viewDataAnalyticsQuestions)
	http.HandleFunc("/coding/questions", viewCodingQuestions)
	http.HandleFunc("/profile", profile)
	http.HandleFunc("/admin", admin)
	http.HandleFunc("/checkresult", checkresult)
	http.HandleFunc("/viewresult", viewresult)

	//server
	http.ListenAndServe("localhost:8080", nil)
	//http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("./assets/"))))
	//http.ListenAndServe("localhost:8000", context.Clearhandler(http.DefaultServeMux))

}

func home(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "home.html", nil)

}

func index(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "index.html", nil)

}

func admin(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "admin.html", nil)

}

func GetUserByID(id int) (*Users, error) {
	// Run a query to retrieve the user data
	query := "SELECT User_Id, Username, FirstName, LastName, Gender, Email, Age, UserType FROM Users WHERE User_Id = $1"
	row := db.QueryRow(query, id)

	// Parse the query results into a User struct
	user := &Users{}
	err = row.Scan(&user.User_Id, &user.Username, &user.FirstName, &user.LastName, &user.Gender, &user.Email, &user.Age, &user.UserType)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func UpdateUser(user *Users) error {
	// Create update query
	query := "UPDATE Users SET Username = $1, FirstName = $2, LastName = $3, Gender = $4, Email = $5, Age = $6 WHERE User_Id = $7"

	// Execute the query
	_, err := db.Exec(query, user.Username, user.FirstName, user.LastName, user.Gender, user.Email, user.Age, user.User_Id)
	if err != nil {
		return err
	}

	return nil
}

func profile(w http.ResponseWriter, r *http.Request) {
	userID := getUser(r)
	if userID == nil || *userID == 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	user, err := GetUserByID(*userID)
	if err != nil {
		fmt.Println(err.Error())
	}

	//j := Users{}
	templates.ExecuteTemplate(w, "profile.html", user)

}

func alreadyLoggedIn(w http.ResponseWriter, r *http.Request) bool {
	// Check if the user is already logged in by looking for a cookie with the user ID
	cookie, err := r.Cookie("userid")
	if err == nil {
		// If the cookie exists, check if the user ID is valid
		userID, err := strconv.Atoi(cookie.Value)
		if err == nil && userID > 0 {
			// If the user ID is valid, the user is already logged in
			return true
		}
	}
	// If the cookie doesn't exist or the user ID is not valid, the user is not logged in
	return false
}

// register serves form for registring new users
func register(w http.ResponseWriter, r *http.Request) {
	if alreadyLoggedIn(w, r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	templates.ExecuteTemplate(w, "register.html", nil)

}

// initialization
var usernameAlphanum = true
var usernameLength bool
var passwordLowerC, passwordUpperC, passwordNumber, passwordSpecial, passwordNoSpaces, passwordLenght bool

// registerAuthorization creates new user in database
func registerAuthorization(w http.ResponseWriter, r *http.Request) {
	/*
		Usernames criteria Verification
		Password criteria Verification
		Check if same username exist in the database
		Convert the password string to bycrypt hash password
		Store the Username and bycrypt hash in the database


	*/
	//	Usernames criteria Verification
	r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")
	firstname := r.FormValue("firstname")
	lastname := r.FormValue("lastname")
	agestr := r.FormValue("age")
	gender := r.FormValue("gender")
	email := r.FormValue("email")
	usertype := r.FormValue("usertype")

	//age conversion from string to integer
	age, err := strconv.Atoi(agestr)
	if err != nil {
		http.Error(w, "invalid age valid", http.StatusBadRequest)
	}

	//age check
	//if 18 <= age || age >= 100 {
	//	http.Error(w, "use correct age", http.StatusBadRequest)
	//}

	// check for alphanumeric characters
	for _, use := range username {
		if unicode.IsLetter(use) == false && unicode.IsNumber(use) == false {
			usernameAlphanum = false
		}
	}

	//username length
	if 6 <= len(username) && len(username) >= 30 {
		usernameLength = true
	}

	passwordNoSpaces = true

	for _, char := range password {
		switch {
		// func IsLower(r rune) bool
		case unicode.IsLower(char):
			passwordLowerC = true
		// func IsUpper(r rune) bool
		case unicode.IsUpper(char):
			passwordUpperC = true
		// func IsNumber(r rune) bool
		case unicode.IsNumber(char):
			passwordNumber = true
		// func IsPunct(r rune) bool, func IsSymbol(r rune) bool
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			passwordSpecial = true
		// func IsSpace(r rune) bool, type rune = int32
		case unicode.IsSpace(int32(char)):
			passwordNoSpaces = false
		}
	}
	if 8 < len(password) && len(password) < 64 {
		passwordLenght = true
	}

	if !passwordLowerC || !passwordUpperC || !passwordNumber || !passwordSpecial || !passwordLenght || !passwordNoSpaces || !usernameAlphanum || !usernameLength {
		templates.ExecuteTemplate(w, "register.html", "Kindly check to see that your username and password meet criteria")
		return
	}

	if username == "" || firstname == "" || lastname == "" || agestr == "" || password == "" || gender == "" || email == "" {
		templates.ExecuteTemplate(w, "register.html", "Ensure that you fill all the fields")
		return
	}

	// check to see if username exists in the database
	smnt := "SELECT User_Id FROM users WHERE username = $1"
	row := db.QueryRow(smnt, username)
	var User_Id string
	err = row.Scan(&User_Id)
	if err != sql.ErrNoRows {
		templates.ExecuteTemplate(w, "register.html", "The Username entered already exist")
		fmt.Println(err)
		return
	}

	// check to see if email exists in the database
	emt := "SELECT User_Id FROM users WHERE email = $1"
	row1 := db.QueryRow(emt, email)
	var Emmmm string
	err = row1.Scan(&Emmmm)
	if err != sql.ErrNoRows {
		templates.ExecuteTemplate(w, "register.html", "Email already exist!")
		fmt.Println(err)
		return
	}
	// creating hash from given password for better security
	var hash []byte
	hash, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var insertStmnt *sql.Stmt
	insertStmnt, err = db.Prepare("INSERT INTO users (username, firstname, lastname, age, gender, email, usertype, hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);")
	if err != nil {
		fmt.Println("error preparing statement:", err)
		templates.ExecuteTemplate(w, "register.html", "there was a problem registering account")
		return
	}
	defer insertStmnt.Close()

	res, err := insertStmnt.Exec(username, firstname, lastname, age, gender, email, usertype, hash)
	if err != nil {
		panic(err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		fmt.Println(err)
		fmt.Println(n)
		panic(err)
	}
	//session added
	// session, err := store.New(r, "session")
	// session.Values["User_Id"] = User_Id
	// session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
	return

}

func generateSessionID() string {
	// Generate 32 bytes of random data
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}
	// Encode the random data as a base64 string
	return base64.StdEncoding.EncodeToString(bytes)
}

func getUserRole(username string) string {
	var usertype string
	err := db.QueryRow("SELECT usertype FROM users WHERE username = $1", username).Scan(&usertype)
	if err != nil {
		fmt.Println(err)
	}
	return usertype
}

func login(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "login.html", nil)

}

func loginAuthorization(w http.ResponseWriter, r *http.Request) {

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		templates.ExecuteTemplate(w, "login.html", "Please fill out this field")
		return
	}

	// //convert to switch
	// switch {
	// case username == "":
	// 	templates.ExecuteTemplate(w, "login.html", "Ensure that you fill username field")
	// 	return
	// case password == "":
	// 	templates.ExecuteTemplate(w, "login.html", "Ensure that you fill password field")
	// 	return
	// }

	//check to see if username exist in database
	var User_Id, hash string
	smt := `SELECT User_Id, hash FROM users WHERE username = $1;`
	row := db.QueryRow(smt, username)
	err := row.Scan(&User_Id, &hash)
	if err != nil {
		templates.ExecuteTemplate(w, "login.html", "Username not found in our database. Check username again or signup!")
		return
	}

	// check to see if hash of password exist in the database
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err == nil {
		session, _ := store.New(r, "session")

		// Set the User_Id value in the session
		session.Values["User_Id"] = User_Id

		// Generate a new session ID
		sessionID := generateSessionID()

		// Set the session cookie with the sessionID and User_Id values
		cookie := &http.Cookie{
			Name:    "session",
			Value:   sessionID,
			Path:    "/",
			Expires: time.Now().Add(24 * time.Hour),
		}
		http.SetCookie(w, cookie)

		// Insert a new row into the Sessions table
		_, err = db.Exec("INSERT INTO Sessions (SessionID, User_Id) SELECT $1, User_Id FROM Users WHERE Username = $2", sessionID, username)
		if err != nil {
			fmt.Println(err.Error())
			return
		}

		usertype := getUserRole(username)

		if usertype == "admin" {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		} else {
			http.Redirect(w, r, "/index", http.StatusSeeOther)
			return
		}

		// http.Redirect(w, r, "/index", http.StatusSeeOther)
		// return
	}
	templates.ExecuteTemplate(w, "login.html", "Confirm Username and/or Password")
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	delete(session.Values, "User_Id")
	session.Save(r, w)
	templates.ExecuteTemplate(w, "login.html", "Logged Out")

}

func Auth(HandlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		_, ok := session.Values["User_Id"]
		if !ok {
			http.Redirect(w, r, "/login", 302)
			return
		}
		HandlerFunc.ServeHTTP(w, r)
	}
}

func student(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "learner.html", nil)

}

// Function to get all questions
func getAllQuestions() ([]Question, error) {
	var questions []Question
	rows, err := db.Query("SELECT * FROM questions")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var question Question
		err := rows.Scan(&question.QuestionID, &question.QuestionPrompt, &question.OptionA, &question.OptionB, &question.OptionC, &question.OptionD, &question.CorrectOption)
		if err != nil {
			return nil, err
		}
		questions = append(questions, question)
	}

	return questions, nil
}

// Function to get responses for a specific student
func getResponsesForStudent(studentID int) ([]Response, error) {
	var responses []Response
	rows, err := db.Query("SELECT * FROM responses WHERE student_id = $1", studentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var response Response
		err := rows.Scan(&response.ResponseID, &response.QuestionID, &response.Answer, &response.IsCorrect, &response.CreatedAt)
		if err != nil {
			return nil, err
		}
		responses = append(responses, response)
	}

	return responses, nil
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		panic(err.Error())
	}
}

// test

// Submits a response to a question
func submitResponse(response Response) error {
	// Prepare the SQL query
	query := `
        INSERT INTO Responses (QuestionID, Answer, IsCorrect, CreatedAt)
        VALUES ($1, $2, $3, $4, $5)
    `
	// Execute the query with the provided response data
	_, err := db.Exec(query, response.QuestionID, response.Answer, response.IsCorrect, response.CreatedAt)
	if err != nil {
		return err
	}

	return nil
}

// Calculates the test results for a given student
func calculateTestResults(studentID int) (int, int, error) {
	// Prepare the SQL query
	query := `
        SELECT COUNT(*) FROM Responses
        WHERE StudentID = $1 AND IsCorrect = true
    `
	// Execute the query to get the number of correct responses
	var correctAnswers int
	err := db.QueryRow(query, studentID).Scan(&correctAnswers)
	if err != nil {
		return 0, 0, err
	}

	// Calculate the score (out of 100)
	score := (correctAnswers * 100) / 10

	return correctAnswers, score, nil
}

func alreadyLoggedIn1(w http.ResponseWriter, r *http.Request) bool {
	// Check if the user is already logged in by looking for a cookie with the user ID
	cookie, err := r.Cookie("userid")
	if err == nil {
		// If the cookie exists, check if the user ID is valid
		userID, err := strconv.Atoi(cookie.Value)
		if err == nil && userID > 0 {
			// If the user ID is valid, the user is already logged in
			return true
		}
	}
	// If the cookie doesn't exist or the user ID is not valid, the user is not logged in
	return false
}

// Questions set by admin
func insertquestion(w http.ResponseWriter, r *http.Request) {
	// userID := getUser(r)
	// admin := 1
	// if userID != &admin {
	// 	fmt.Println("User isn't admin. Access denied")
	// 	http.Error(w, "Access denied. You must be the admin to access this information", http.StatusForbidden)
	// 	return
	// }

	usertype := r.FormValue("usertype")
	if usertype == "student" {
		http.Redirect(w, r, "/register", http.StatusSeeOther)
		return
	}

	templates.ExecuteTemplate(w, "insertquestion.html", nil)
}

func insertedquestion(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		topicsName := r.FormValue("topicsName")
		question_prompt := r.FormValue("question_prompt")
		option_a := r.FormValue("option_a")
		option_b := r.FormValue("option_b")
		option_c := r.FormValue("option_c")
		option_d := r.FormValue("option_d")
		correct_option := r.FormValue("correct_option")
		//created_at := r.FormValue("created_at")

		// if topicsName == "" || question_prompt == "" || option_a == "" || option_b == "" || option_c == "" || option_d == "" || correct_option == "" {
		// 	templates.ExecuteTemplate(w, "insertedtopic.html", "Error! Check to see that all fields have been completed")
		// 	fmt.Println("1 is ", err.Error())
		// 	return
		// }

		//switch statement on inserting question
		switch {
		case topicsName == "":
			templates.ExecuteTemplate(w, "insertedtopic.html", "Error! Check to see that a topic name is entered")
			return
		case question_prompt == "":
			templates.ExecuteTemplate(w, "insertedtopic.html", "Error! Check to see that A QUESTION is entered")
			return
		case option_a == "":
			templates.ExecuteTemplate(w, "insertedtopic.html", "Error! Check to see that option A is entered")
			return
		case option_b == "":
			templates.ExecuteTemplate(w, "insertedtopic.html", "Error! Check to see that option B is entered")
			return
		case option_c == "":
			templates.ExecuteTemplate(w, "insertedtopic.html", "Error! Check to see that option C is entered")
			return
		case option_d == "":
			templates.ExecuteTemplate(w, "insertedtopic.html", "Error! Check to see that option D is entered")
			return
		case correct_option == "":
			templates.ExecuteTemplate(w, "insertedtopic.html", "Error! Check to see that the correct option is entered")
			return
		}

		smt := `INSERT into questions (topicsName, question_prompt, option_a, option_b, option_c, option_d, correct_option) VALUES ($1, $2, $3, $4, $5, $6, $7);`
		ins, err := db.Prepare(smt)
		if err != nil {
			fmt.Println("2 is ", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		defer ins.Close()

		res, err := ins.Exec(topicsName, question_prompt, option_a, option_b, option_c, option_d, correct_option)
		checkError(err)

		n, err := res.RowsAffected()
		checkError(err)

		//fmt.Fprintln(w, "Inserted successfully", n)
		//templates.ExecuteTemplate(w, "insertdone.html", "INSERTED SUCCESFULLY")
		fmt.Println(n)
		http.Redirect(w, r, "/question", 307)
		return

	}
	// templates.ExecuteTemplate(w, "insertdone.html", "Item inserted successfully")
	// had to mute that or it displays d content of inserdone.html after execution.
}

func question(w http.ResponseWriter, r *http.Request) {

	smt := `SELECT * FROM questions;`
	rows, err := db.Query(smt)
	if err != nil {
		panic(err.Error())
	}

	defer rows.Close()

	var questions []Question

	for rows.Next() {
		q := Question{}
		err = rows.Scan(&q.QuestionID, &q.TopicsName, &q.QuestionPrompt, &q.OptionA, &q.OptionB, &q.OptionC, &q.OptionD, &q.CorrectOption, &q.CreatedAt)
		if err != nil {
			panic(err.Error())
		}
		questions = append(questions, q)

	}
	err = templates.ExecuteTemplate(w, "questions.html", questions)
	if err != nil {
		panic(err.Error())
	}

}

// Get what you want to update then insert
func updatequestion(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Retrieve topic from database and render form
		r.ParseForm()
		questions_id := r.FormValue("questions_id")
		smt := `SELECT * FROM questions WHERE questions_id = $1;`
		u := Question{}
		row := db.QueryRow(smt, questions_id)
		err = row.Scan(&u.QuestionID, &u.TopicsName, &u.QuestionPrompt, &u.OptionA, &u.OptionB, &u.OptionC, &u.OptionD, &u.CorrectOption, &u.CreatedAt)
		if err != nil {
			fmt.Println("error could be here", err)
			http.Redirect(w, r, "/", 307)
			return
		}
		err = templates.ExecuteTemplate(w, "updatequestion.html", u)
		if err != nil {
			panic(err.Error())
		}
	} else if r.Method == http.MethodPost {
		// Process update request and redirect to updatedtopic.html
		r.ParseForm()
		questions_id := r.FormValue("questions_id")
		topicsName := r.FormValue("topicsName")
		question_prompt := r.FormValue("question_prompt")
		option_a := r.FormValue("option_a")
		option_b := r.FormValue("option_b")
		option_c := r.FormValue("option_c")
		option_d := r.FormValue("option_d")
		correct_option := r.FormValue("correct_option")
		//created_at := r.FormValue("created_at")

		if topicsName == "" || question_prompt == "" || option_a == "" || option_b == "" || option_c == "" || option_d == "" || correct_option == "" {
			templates.ExecuteTemplate(w, "updatequestion.html", "Error inserting data! Check all fields!")
			return
		}

		upt := `UPDATE questions SET topicsName = $1, question_prompt = $2, option_a = $3, option_b = $4, option_c = $5, option_d = $6, correct_option = $7 WHERE questions_id = $8;`
		inst, err := db.Prepare(upt)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		defer inst.Close()

		res, err := inst.Exec(topicsName, question_prompt, option_a, option_b, option_c, option_d, correct_option, questions_id)
		checkError(err)

		n, err := res.RowsAffected()
		checkError(err)

		fmt.Println(n)

		http.Redirect(w, r, "/question", http.StatusFound) //start here
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func deletequestion(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	questionIDStr := r.FormValue("questions_id")
	if questionIDStr == "" {
		http.Error(w, "questions_id is required", http.StatusBadRequest)
		return
	}
	questions_id, err := strconv.ParseInt(questionIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid Id value", http.StatusBadRequest)
		return
	}

	// Delete responses associated with the question
	delResponses := `DELETE FROM responses WHERE questions_id = $1;`
	_, err = db.Exec(delResponses, questions_id)
	if err != nil {
		http.Error(w, "Error deleting responses: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Delete the question
	delQuestion := `DELETE FROM questions WHERE questions_id = $1;`
	_, err = db.Exec(delQuestion, questions_id)
	if err != nil {
		http.Error(w, "Error deleting question: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// del := `DELETE FROM questions WHERE questions_id = $1;`
	// smt, err := db.Prepare(del)
	// if err != nil {
	// 	panic(err.Error())
	// }
	// defer smt.Close()

	// res, err := smt.Exec(questions_id)
	// if err != nil {
	// 	panic(err.Error())
	// }

	// n, err := res.RowsAffected()
	// if err != nil {
	// 	panic(err.Error())
	// }

	//fmt.Println(n, "Deleted")
	http.Redirect(w, r, "/question", 307)
	return

}

// sunday real one
func getUser(r *http.Request) *int {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil
	}

	sessionID := cookie.Value
	row := db.QueryRow("SELECT User_Id FROM Sessions WHERE SessionID = $1", sessionID)
	var userID int
	err = row.Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			// handle "no rows in result set" error here
			fmt.Println("No rows in result set")
		} else {
			// handle other errors here
			fmt.Println("Error retrieving user ID:", err)
		}
		return nil
	}
	fmt.Println("User ID:", userID)
	return &userID
}

var fm = template.FuncMap{
	"Au": getUser,
}

// student part
// function to show all questions to student
func viewquestions(w http.ResponseWriter, r *http.Request) {
	userID := getUser(r)
	if userID == nil || *userID == 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	rows, err := db.Query("SELECT questions_id, topicsName, question_prompt, option_a, option_b, option_c, option_d, correct_option FROM questions")
	if err != nil {
		fmt.Println(err)
	}
	defer rows.Close()

	questions := []Question{}
	for rows.Next() {
		var question Question
		if err := rows.Scan(&question.QuestionID, &question.TopicsName, &question.QuestionPrompt, &question.OptionA, &question.OptionB, &question.OptionC, &question.OptionD, &question.CorrectOption); err != nil {
			fmt.Println(err)
		}
		questions = append(questions, question)
	}

	if err := rows.Err(); err != nil {
		fmt.Println(err)
	}

	templates.ExecuteTemplate(w, "viewquestions.html", questions)
}

// // cool but issues
func Alreadyloggedin(r *http.Request) (int, error) {
	c, err := r.Cookie("charlescookie")
	if err != nil {
		return 0, err
	}
	un := dbSession[c.Value]
	_, ok := dbUser[un]
	if ok {
		userID, err := strconv.Atoi(un)
		if err != nil {
			return 0, err
		}
		return userID, nil
	}
	return 0, nil
}

func answerquestions(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	userID := getUser(r)
	if userID == nil || *userID == 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method != "POST" {
		http.Redirect(w, r, "/viewquestions", http.StatusSeeOther)
		return
	}

	fmt.Println("lets the user be", userID)

	err = r.ParseForm()
	if err != nil {
		fmt.Println(err)
	}

	responses := []Response{}
	for key, values := range r.Form {
		if !strings.HasPrefix(key, "question-") {
			continue
		}

		questionID, err := strconv.ParseInt(key[9:], 10, 64)
		if err != nil {
			fmt.Println(err)
		}

		option, err := strconv.ParseInt(values[0], 10, 64)
		if err != nil {
			fmt.Println(err)
		}

		row := db.QueryRow("SELECT correct_option FROM questions WHERE questions_id = $1", questionID)
		var correctOption int64
		err = row.Scan(&correctOption)
		if err != nil {
			fmt.Println(err)
		}

		isCorrect := false
		if option == correctOption {
			isCorrect = true
		}
		//var UserID int
		//UserID := *userID
		responses = append(responses, Response{
			QuestionID: int(questionID),
			Answer:     int(option),
			IsCorrect:  isCorrect,
			UserID:     int(*userID),
		})
	}

	for _, response := range responses {
		//_, err = db.Exec("INSERT INTO responses (answer, is_correct, questions_id) SELECT $1, $2, questions_id FROM questions WHERE questions_id = $3", response.Answer, response.IsCorrect, response.QuestionID)
		//_, err = db.Exec("INSERT INTO responses (answer, is_correct, questions_id, User_Id) SELECT $1, $2, questions_id FROM questions WHERE questions_id = $3, User_Id FROM Users WHERE User_Id = $4", response.Answer, response.IsCorrect, response.QuestionID, response.UserID)
		_, err = db.Exec("INSERT INTO responses (answer, is_correct, questions_id, User_Id) SELECT $1, $2, q.questions_id, u.User_Id FROM questions q JOIN users u ON u.User_Id = $4 WHERE q.questions_id = $3", response.Answer, response.IsCorrect, response.QuestionID, response.UserID)

		if err != nil {
			fmt.Println("err 1 is ", err.Error())
			log.Fatal(err)
		}
	}
	fmt.Println("view answers completed succesfully")
	http.Redirect(w, r, "/testresults", http.StatusSeeOther)
}

func testresults(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	userID := getUser(r)
	if userID == nil || *userID == 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	fmt.Println("got into testresults page")

	//lets try this
	rows, err := db.Query(`
	SELECT questions.question_prompt, responses.answer, responses.is_correct, Users.User_id
	FROM Users
	INNER JOIN responses ON responses.User_id = Users.User_id
	INNER JOIN questions ON responses.questions_id = questions.questions_id
	LEFT JOIN TestResults ON responses.User_id = TestResults.User_id AND responses.questions_id = TestResults.questions_id
	WHERE Users.User_id = $1 AND DATE(responses.created_at) = CURRENT_DATE AND questions.topicsName = (
		SELECT topicsName 
		FROM questions 
		WHERE questions.questions_id = (
			SELECT responses.questions_id 
			FROM responses 
			WHERE responses.User_id = Users.User_id 
			ORDER BY responses.created_at DESC 
			LIMIT 1
		)
	)`, userID)

	fmt.Println("rows:", rows)

	if err != nil {
		fmt.Println("error querying test results:", err.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	score := 0
	sumOfQuestions := 0
	testResults := []TestResult{}
	for rows.Next() {
		var questionPrompt string
		var answer int
		var isCorrect bool
		//var scores sql.NullInt64
		var User_id int
		// var testdate time.Time

		err = rows.Scan(&questionPrompt, &answer, &isCorrect, &User_id)

		//testResults = append(testResults, TestResult{questionPrompt, answer, isCorrect, User_id})
		if err != nil {
			fmt.Println("error scanning test result:", err.Error())
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		fmt.Println("Question:", questionPrompt)
		fmt.Println("Answer:", answer)
		fmt.Println("IsCorrect:", isCorrect)
		//fmt.Println("Scores Valid:", scores.Valid)

		// if scores.Valid{
		// 	score += int(scores.Int64)
		// 	sumOfQuestions++
		// }

		if isCorrect {
			score++
		}
		sumOfQuestions++

		fmt.Println(questionPrompt, answer, isCorrect)
		question := Question{QuestionPrompt: questionPrompt}
		response := Response{Answer: answer, IsCorrect: isCorrect}
		testResult := TestResult{Question: question, Response: response}

		testResults = append(testResults, testResult)
	}
	// to calculate the percentage of the right answers
	var percentage float64
	if sumOfQuestions > 0 {
		percentage = (float64(score) / float64(sumOfQuestions)) * 100
		fmt.Println("percentage is ", percentage)
	} else {
		fmt.Println("questions dont exist")
	}
	//percentage := ((float64(score)  / float64(sumOfQuestions)) * 100)

	data := struct {
		TestResults []TestResult
		Score       int
		Percentage  float64
	}{
		TestResults: testResults,
		Score:       score,
		Percentage:  percentage,
	}
	//fmt.Println(data)     delete later
	fmt.Println("successfully executed test results")

	//inserting testresult into the testresults database
	//	_, err = db.Exec("INSERT INTO responses (answer, is_correct, questions_id, User_Id) SELECT $1, $2, q.questions_id, u.User_Id FROM questions q JOIN users u ON u.User_Id = $4 WHERE q.questions_id = $3", response.Answer, response.IsCorrect, response.QuestionID, response.UserID)
	// var test []TestResult
	// _, err = db.Exec("INSERT INTO TestResults (Score, User_Id, questions_id) SELECT $1, u.User_Id, q.questions_id FROM questions q JOIN users u ON u.User_Id = $2 WHERE q.questions_id = $3",)
	
	// smt, err := db.Prepare("INSERT INTO TestResults (User_Id, questions_id, Score) SELECT u.User_Id, q.questions_id, $3 FROM questions q JOIN users u ON u.User_Id = $1 WHERE q.questions_id = $2")
	// if err != nil {
	// 	fmt.Println("the error from this prepared statement is", err.Error())
	// 	return
	// }

	// defer smt.Close()
	// for _, testR := range testResults{
	// 	_, err = smt.Exec(*userID, testR.Question.QuestionID, score)
	// 	if err != nil {
	// 		fmt.Println("the error from this prepared statement is", err.Error())
	// 		return
	// 	}
	// }

	// _, err = smt.Exec(*userID, testResults[0].Question.QuestionID, score)
	// if err != nil {
	// 	fmt.Println("the error from this prepared statement is", err.Error())
	// 	return
	// }


	templates.ExecuteTemplate(w, "testresults.html", data)
}

//getting questions according to topic or subject name

func getQuestionsByTopicName(topicName string) ([]Question, error) {
	smt := `SELECT * FROM questions WHERE topicsName=$1`
	rows, err := db.Query(smt, topicName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var questions []Question

	for rows.Next() {
		q := Question{}
		err = rows.Scan(&q.QuestionID, &q.TopicsName, &q.QuestionPrompt, &q.OptionA, &q.OptionB, &q.OptionC, &q.OptionD, &q.CorrectOption, &q.CreatedAt)
		if err != nil {
			return nil, err
		}
		questions = append(questions, q)
	}

	return questions, nil
}

func renderQuestionsPage(w http.ResponseWriter, questions []Question) {

	err := templates.ExecuteTemplate(w, "viewquestions.html", questions)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func viewComputerScienceQuestions(w http.ResponseWriter, r *http.Request) {
	userID := getUser(r)
	if userID == nil || *userID == 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	questions, err := getQuestionsByTopicName("Computer Science")
	if err != nil {
		http.Error(w, "Failed to get questions", http.StatusInternalServerError)
		return
	}

	renderQuestionsPage(w, questions)
}

func viewArtificialIntelligenceQuestions(w http.ResponseWriter, r *http.Request) {
	userID := getUser(r)
	if userID == nil || *userID == 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	questions, err := getQuestionsByTopicName("Artificial Intelligence")
	if err != nil {
		http.Error(w, "Failed to get questions", http.StatusInternalServerError)
		return
	}

	renderQuestionsPage(w, questions)
}

func viewDataAnalyticsQuestions(w http.ResponseWriter, r *http.Request) {
	userID := getUser(r)
	if userID == nil || *userID == 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	questions, err := getQuestionsByTopicName("Data Analytics")
	if err != nil {
		http.Error(w, "Failed to get questions", http.StatusInternalServerError)
		return
	}

	renderQuestionsPage(w, questions)
}

func viewCodingQuestions(w http.ResponseWriter, r *http.Request) {
	userID := getUser(r)
	if userID == nil || *userID == 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	questions, err := getQuestionsByTopicName("Coding")
	if err != nil {
		http.Error(w, "Failed to get questions", http.StatusInternalServerError)
		return
	}

	renderQuestionsPage(w, questions)
}

func checkresult(w http.ResponseWriter, r *http.Request) {
	userID := getUser(r)
	if userID == nil || *userID == 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	templates.ExecuteTemplate(w, "checkresult.html", nil)

}

func viewresult(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	userID := getUser(r)
	if userID == nil || *userID == 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	fmt.Println("got into viewresults page")

	username := r.FormValue("username")

	err := db.QueryRow(`SELECT User_id FROM Users WHERE username = $1`, username).Scan(&userID)

	fmt.Println("username:", username)
	//lets try this
	rows, err := db.Query(`
	SELECT questions.question_prompt, responses.answer, responses.is_correct, Users.username
	FROM Users
	INNER JOIN responses ON responses.User_id = Users.User_id
	INNER JOIN questions ON responses.questions_id = questions.questions_id
	LEFT JOIN TestResults ON responses.User_id = TestResults.User_id AND responses.questions_id = TestResults.questions_id
	WHERE Users.User_id = $1 AND DATE(responses.created_at) = CURRENT_DATE AND questions.topicsName = (
		SELECT topicsName 
		FROM questions 
		WHERE questions.questions_id = (
			SELECT responses.questions_id 
			FROM responses 
			WHERE responses.User_id = Users.User_id 
			ORDER BY responses.created_at DESC 
			LIMIT 1
		)
	)`, userID)

	if err != nil {
		fmt.Println("error querying test results:", err.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	score := 0
	sumOfQuestions := 0
	testResults := []TestResult{}
	for rows.Next() {
		var questionPrompt string
		var answer int
		var isCorrect bool
		//var scores sql.NullInt64
		var theusername string
		// var testdate time.Time

		err = rows.Scan(&questionPrompt, &answer, &isCorrect, &theusername)

		if err != nil {
			fmt.Println("error scanning test result:", err.Error())
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		fmt.Println("Question:", questionPrompt)
		fmt.Println("Answer:", answer)
		fmt.Println("IsCorrect:", isCorrect)

		if isCorrect {
			score++
		}
		sumOfQuestions++

		fmt.Println(questionPrompt, answer, isCorrect)
		question := Question{QuestionPrompt: questionPrompt}
		response := Response{Answer: answer, IsCorrect: isCorrect}
		testResult := TestResult{Question: question, Response: response}

		testResults = append(testResults, testResult)
	}
	// to calculate the percentage of the right answers
	var percentage float64
	if sumOfQuestions > 0 {
		percentage = (float64(score) / float64(sumOfQuestions)) * 100
		fmt.Println("percentage is ", percentage)
	} else {
		fmt.Println("questions dont exist")
	}
	//percentage := ((float64(score)  / float64(sumOfQuestions)) * 100)

	data := struct {
		TestResults []TestResult
		Score       int
		Percentage  float64
	}{
		TestResults: testResults,
		Score:       score,
		Percentage:  percentage,
	}
	//fmt.Println(data)     delete later
	//fmt.Println("successfully executed test results")
	templates.ExecuteTemplate(w, "testresults.html", data)
}
