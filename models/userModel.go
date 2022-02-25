package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// why use pointer for struct fields:
// https://stackoverflow.com/questions/59964619/difference-using-pointer-in-struct-fields
type User struct {
	ID            primitive.ObjectID `bson:"_id"`
	First_name    *string            `json:"first_name" validate:"required,min=2,max=100"`
	Last_name     *string            `json:"last_name" validate:"required,min=2,max=100"`
	Password      *string            `json:"password" validate:"required,min=6"`
	Email         *string            `json:"email" validate:"email,required"` // email >>> validation type
	Phone         *string            `json:"phone" validate:"required"`
	Token         *string            `json:"token"`
	User_type     *string            `json:"user_type" validate:"required,eq=ADMIN|eq=USER"` // eq=ADMIN|eq=USER >>> same concept as ENUM
	Refresh_token *string            `json:"refresh_token"`
	Created_at    time.Time          `json:"created_at"`
	Updated_at    time.Time          `json:"updated_at"`
	User_id       string             `json:"user_id"` // if not using pointer, if deserializing the JSON into object, when this field is null, will be default value of the primitive, which is ""
}
