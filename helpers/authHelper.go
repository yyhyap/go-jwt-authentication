package helpers

import (
	"errors"
	"log"

	"github.com/gin-gonic/gin"
)

func MatchUserTypeToUid(c *gin.Context, userId string) (err error) {
	// "user_type" and "uid" are got from c.Set in authMiddleware
	userType := c.GetString("user_type")
	uid := c.GetString("uid")
	err = nil

	log.Println("userType: ", userType)
	log.Println("uid: ", uid)

	// user can only access his own data
	if userType == "USER" && uid != userId {
		err = errors.New("unauthorized to access this resource")
		return err
	}

	err = CheckUserType(c, userType)
	return err
}

func CheckUserType(c *gin.Context, role string) (err error) {
	userType := c.GetString("user_type")
	err = nil

	if userType != role {
		err = errors.New("unauthorized to access this resource")
		return err
	}

	return err
}
