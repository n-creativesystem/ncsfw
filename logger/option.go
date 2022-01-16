package logger

import "github.com/sirupsen/logrus"

type option struct {
	lvl          Level
	reportCaller *ReportCaller
	formatter    logrus.Formatter
	exitFunc     func(int)

	hookLevels []Level
}

type Option interface {
	apply(opt *option)
}

type levelOption struct {
	lvl Level
}

func (o levelOption) apply(opt *option) {
	opt.lvl = o.lvl
}

func WithLevel(lvl Level) Option {
	return levelOption{lvl}
}

type ReportFormat func(string) string

type ReportCaller struct {
	File       bool
	FileFormat ReportFormat
	Func       bool
	FuncFormat ReportFormat
}

type reportCallerOption struct {
	reportCaller *ReportCaller
}

func (o reportCallerOption) apply(opt *option) {
	opt.reportCaller = o.reportCaller
}

func WithReportCallerOption(reportCaller *ReportCaller) Option {
	return reportCallerOption{reportCaller}
}

type exitFuncOption struct {
	exitFunc func(int)
}

func (o exitFuncOption) apply(opt *option) {
	opt.exitFunc = o.exitFunc
}

func WithExitFunc(exitFunc func(int)) Option {
	return exitFuncOption{exitFunc}
}

type hookLevelOption struct {
	hookLevel []Level
}

func (o hookLevelOption) apply(opt *option) {
	opt.hookLevels = o.hookLevel
}

func WithHookLevels(levels []Level) Option {
	return hookLevelOption{levels}
}
