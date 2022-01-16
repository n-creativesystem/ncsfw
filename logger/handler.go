package logger

// type writeLogger struct {
// 	log Logger
// }

// func (log *writeLogger) Write(p []byte) (int, error) {
// 	log.log.Info(string(p))
// 	return len(p), nil
// }

// func NewWriter(log Logger) io.Writer {
// 	return &writeLogger{
// 		log: log,
// 	}
// }

// const (
// 	logKey = "logger"
// )

// func GetLogger(c *gin.Context) Logger {
// 	if v, ok := c.Get(logKey); ok {
// 		return v.(Logger)
// 	}
// 	return std
// }

// func SetLogger(c *gin.Context, logger Logger) {
// 	c.Set(logKey, logger)
// }
