package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sjzar/chatlog/internal/chatlog/database"
)

func (s *Service) checkDBStateMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		switch s.db.State {
		case database.StateInit:
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database is not ready"})
			c.Abort()
			return
		case database.StateDecrypting:
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database is decrypting, please wait"})
			c.Abort()
			return
		case database.StateError:
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database is error: " + s.db.StateMsg})
			c.Abort()
			return
		}

		c.Next()
	}
}
