package helpers

import (
	"context"
	"fmt"
	"golang-jwt-project/database"
	"log"
	"time"

	jwt "github.com/golang-jwt/jwt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type SignedDetails struct {
	Email      string
	First_name string
	Last_name  string
	Uid        string
	User_type  string
	jwt.StandardClaims
}

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

var SECRET_KEY string = GetEnvVariable("SECRET_KEY")

func GenerateAllTokens(email string, firstName string, lastName string, userType string, uid string) (signedToken string, signedRefreshToken string, err error) {

	if SECRET_KEY == "" {
		SECRET_KEY = "test"
	}

	claims := &SignedDetails{
		Email:      email,
		First_name: firstName,
		Last_name:  lastName,
		User_type:  userType,
		Uid:        uid,
		StandardClaims: jwt.StandardClaims{
			// 24 hours
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(24)).Unix(),
		},
	}

	refreshClaims := &SignedDetails{
		StandardClaims: jwt.StandardClaims{
			// 1 week
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(168)).Unix(),
		},
	}

	/*
		Unlike regular variable declarations, a short variable declaration may redeclare variables provided
		they were originally declared earlier in the same block (or the parameter lists if the block is the function body)
		with the same type, and at least one of the non-blank variables is new. As a consequence, redeclaration can only
		appear in a multi-variable short declaration. Redeclaration does not introduce a new variable;
		it just assigns a new value to the original.
	*/

	signedToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(SECRET_KEY))

	if err != nil {
		log.Panic(err)
		return
	}

	signedRefreshToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString([]byte(SECRET_KEY))

	if err != nil {
		log.Panic(err)
		return
	}

	return signedToken, signedRefreshToken, err
}

func UpdateAllTokens(signedToken string, signedRefreshToken string, userId string) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	// D is an ordered representation of a BSON document. This type should be used when the order of the elements matters,
	// such as MongoDB command documents.
	var updateObj primitive.D

	// everytime after login, will get a new token and refresh token
	// will update MongoDB with latest token, refresh_token and updated_at

	// E represents a BSON element for a D. It is usually used inside a D.
	updateObj = append(updateObj, bson.E{"token", signedToken})
	updateObj = append(updateObj, bson.E{"refresh_token", signedRefreshToken})

	Updated_at, err := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

	if err != nil {
		log.Panic(err)
		defer cancel()
		return
	}

	updateObj = append(updateObj, bson.E{"updated_at", Updated_at})

	upsert := true
	filter := bson.M{"user_id": userId}
	opt := options.UpdateOptions{
		Upsert: &upsert,
	}

	// update MongoDB with latest token, refresh_token and updated_at
	result, err := userCollection.UpdateOne(
		ctx,
		filter,
		bson.D{
			// $set >>> MongoDB: The $set operator replaces the value of a field with the specified value.
			{"$set", updateObj},
		},
		&opt,
	)
	defer cancel()

	if err != nil {
		log.Panic(err)
		return
	}

	_ = result

	return
}

func ValidateToken(signedToken string) (claims *SignedDetails, msg string) {

	if SECRET_KEY == "" {
		SECRET_KEY = "test"
	}

	token, err := jwt.ParseWithClaims(
		signedToken,
		&SignedDetails{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SECRET_KEY), nil
		},
	)

	if err != nil {
		msg = err.Error()
		// will return both (claims *SignedDetails, msg string)
		return
	}

	// https://stackoverflow.com/questions/45405626/decoding-jwt-token-in-golang
	// type-assert `Claims` into a variable of the appropriate type
	// .(*SignedDetails) >>> Type Assertion
	// https://go.dev/tour/methods/15
	// https://stackoverflow.com/questions/38816843/explain-type-assertions-in-go
	claims, ok := token.Claims.(*SignedDetails)

	if !ok {
		msg = fmt.Sprintf("the token is invalid")
		return
	}

	if claims.ExpiresAt < time.Now().Local().Unix() {
		msg = fmt.Sprintf("token has expired")
		return
	}

	return claims, msg
}
