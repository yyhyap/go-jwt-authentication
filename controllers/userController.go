package controllers

import (
	"context"
	"fmt"
	"golang-jwt-project/database"
	"time"

	helper "golang-jwt-project/helpers"
	"golang-jwt-project/models"

	"log"
	"net/http"

	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var validate = validator.New()

func HashPassword(password string) string {
	// 14 >>> cost
	// Bcrypt uses a cost parameter that specify the number of cycles to use in the algorithm.
	// Increasing this number the algorithm will spend more time to generate the hash output.
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)

	if err != nil {
		log.Panic(err)
	}

	return string(bytes)
}

func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		msg = fmt.Sprint("email or password is incorrect")
		check = false
	}

	return check, msg
}

func Signup() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

		var user models.User

		// bind the user struct from the JSON
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			defer cancel()
			return
		}

		// compare the JSON with the struct
		validationErr := validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
			defer cancel()
			return
		}

		password := HashPassword(*user.Password)
		user.Password = &password

		/*
			Unlike regular variable declarations, a short variable declaration may redeclare variables provided
			they were originally declared earlier in the same block (or the parameter lists if the block is the function body)
			with the same type, and at least one of the non-blank variables is new. As a consequence, redeclaration can only
			appear in a multi-variable short declaration. Redeclaration does not introduce a new variable;
			it just assigns a new value to the original.
		*/

		// M is an unordered representation of a BSON document. This type should be used when the order of the elements does not
		// matter. This type is handled as a regular map[string]interface{} when encoding and decoding. Elements will be
		// serialized in an undefined, random order.
		emailCount, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		defer cancel()

		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking with the email"})
			return
		}

		phoneCount, err := userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		defer cancel()

		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking with the phone"})
			return
		}

		if emailCount > 0 || phoneCount > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "this email or phone number already exists"})
		}

		user.Created_at, err = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while parsing created_at"})
			return
		}

		user.Updated_at, err = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while parsing updated_at"})
			return
		}

		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()
		token, refreshToken, err := helper.GenerateAllTokens(*user.Email, *user.First_name, *user.Last_name, *user.User_type, *&user.User_id)

		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while getting token and refreshToken from helper"})
			return
		}

		user.Token = &token
		user.Refresh_token = &refreshToken

		resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
		defer cancel()

		if insertErr != nil {
			msg := fmt.Sprintf("User was not created")
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		c.JSON(http.StatusOK, resultInsertionNumber)
	}
}

// login function using email
func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

		var user models.User
		var foundUser models.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			defer cancel()
			return
		}

		// if found one user by the email, bind the user to 'foundUser'
		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		defer cancel()

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "email or password is incorrect"})
			return
		}

		// check if the password is match
		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		defer cancel()

		if !passwordIsValid {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		if foundUser.Email == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user not found"})
		}

		token, refreshToken, err := helper.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, *foundUser.User_type, *&foundUser.User_id)

		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while getting token and refreshToken from helper"})
			return
		}

		helper.UpdateAllTokens(token, refreshToken, foundUser.User_id)

		err = userCollection.FindOne(ctx, bson.M{"user_id": foundUser.User_id}).Decode(&foundUser)
		defer cancel()

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, foundUser)
	}
}

// can only accessed by the admin
func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := helper.CheckUserType(c, "ADMIN"); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

		//  convert string to int
		recordPerPage, err := strconv.Atoi(c.Query("recordPerPage"))

		if err != nil || recordPerPage < 1 {
			recordPerPage = 10
		}

		page, err1 := strconv.Atoi(c.Query("page"))

		if err1 != nil || page < 1 {
			page = 1
		}

		startIndex := (page - 1) * recordPerPage
		// startIndex, err2 := strconv.Atoi(c.Query("startIndex"))

		// if err2 != nil || startIndex < 0 {
		// 	startIndex = (page - 1) * recordPerPage
		// }

		// https://docs.mongodb.com/manual/core/aggregation-pipeline/
		// match stage >>> filter
		matchStage := bson.D{
			{"$match", bson.D{{}}},
		}
		// if there are any records in database with same id, with be grouped together, and total_count will be the sum of them
		// push >>> access to the data, and the count, (if didnt specify $push, only can access to the count)
		// $push, $$ROOT >>> https://stackoverflow.com/questions/61804268/what-is-root-in-mongodb-aggregate-and-how-it-works
		groupStage := bson.D{
			{"$group", bson.D{
				{"_id", bson.D{
					{"_id", "null"},
				}},
				{"total_count", bson.D{
					{"$sum", 1},
				}},
				{"data", bson.D{
					{"$push", "$$ROOT"},
				}},
			}},
		}
		// project stage define what data should go to the users, what should not
		// {"_id", 0} >>> dont want to show id
		// {"total_count", 1} >>> show the total_count
		projectStage := bson.D{
			{"$project", bson.D{
				// {"_id", 1},
				{"_id", 0},
				{"total_count", 1},
				// https://docs.mongodb.com/manual/reference/operator/aggregation/slice/
				// https://medium.com/@SaifAbid/slice-interfaces-8c78f8b6345d#:~:text=The%20slice%20of%20interfaces%20is,is%20an%20empty%20Interface%7B%7D.
				// $data >>> data from groupStage
				{"user_items", bson.D{{"$slice", []interface{}{"$data", startIndex, recordPerPage}}}},
			}},
		}

		result, err := userCollection.Aggregate(ctx, mongo.Pipeline{matchStage, groupStage, projectStage})
		defer cancel()

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while listing user items"})
		}

		// a slice of 'bson.M'
		var allUsers []bson.M

		// function All must be a pointer to a slice, hence using a slicce of 'bson.M'
		if err := result.All(ctx, &allUsers); err != nil {
			log.Fatal(err)
		}

		c.JSON(http.StatusOK, allUsers)
	}
}

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("user_id")

		// for logging purpose
		// "user_type" and "uid" are got from c.Set in authMiddleware
		userType := c.GetString("user_type")
		uid := c.GetString("uid")
		log.Println("userType: ", userType)
		log.Println("uid: ", uid)

		if err := helper.MatchUserTypeToUid(c, userId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		// Package context defines the Context type, which carries deadlines, cancellation signals,
		// and other request-scoped values across API boundaries and between processes.
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

		var user models.User
		// deserialize into user struct
		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		defer cancel()

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
		}

		c.JSON(http.StatusOK, user)
	}
}
