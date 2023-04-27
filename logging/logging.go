package logging

import (
	"log"
	"os"
)

var (
	infoLogger    = log.New(os.Stdout, "INFO", log.Ldate|log.Ltime)
	warningLogger = log.New(os.Stdout, "WARN", log.Ldate|log.Ltime)
	errorLogger   = log.New(os.Stdout, "ERROR", log.Ldate|log.Ltime)
)

func Info(message string) {
	infoLogger.Println(message)
}

func Warn(message string) {
	warningLogger.Println(message)
}

func Error(message string, err error) {
	errorLogger.Println(message)
	if err != nil {
		errorLogger.Println(err)
	}
}
