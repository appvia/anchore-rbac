/*
Copyright 2018 Rohith Jayawardene <gambol99@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"encoding/json"
	"io/ioutil"
	"path"

	"github.com/fsnotify/fsnotify"
	"github.com/ghodss/yaml"
)

// Watcher is the quick wrapper to provide reloadable configuration
type Watcher interface {
	// Read is used to read content from the file
	Read(interface{}) error
	// Watch is called to add a handler to the events
	Watch(WatcherHandler) (chan struct{}, error)
}

// WatcherHandler is the contract to the watcher events
type WatcherHandler interface {
	// Updated indicates the config has been updated
	Updated()
	// Error is called on a watcher error
	Error(error)
}

// WatcherHandlerFuncs is a wrapper to the handler
type WatcherHandlerFuncs struct {
	// UpdatedFunc is called on updates
	UpdatedFunc func()
	// Error is called on an error
	ErrorFunc func(error)
}

// Updated is called on an update to config
func (w *WatcherHandlerFuncs) Updated() {
	if w.UpdatedFunc != nil {
		w.UpdatedFunc()
	}
}

// Errors is called on a error upstream
func (w *WatcherHandlerFuncs) Error(err error) {
	if w.ErrorFunc != nil {
		w.ErrorFunc(err)
	}
}

type watchImpl struct {
	filename string
}

// NewWatcher returns a new configuration
func NewWatcher(filename string) Watcher {
	return &watchImpl{filename: filename}
}

// Read is responsible for reading in the configuration
func (c *watchImpl) Read(data interface{}) error {
	content, err := ioutil.ReadFile(c.filename)
	if err != nil {
		return err
	}
	switch path.Ext(c.filename) {
	case ".json":
		err = json.Unmarshal(content, data)
	case ".yaml":
		fallthrough
	case ".yml":
		fallthrough
	default:
		return yaml.Unmarshal(content, data)
	}

	return err
}

// Watch starts watching the configu
func (c *watchImpl) Watch(handler WatcherHandler) (chan struct{}, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	if err := watcher.Add(path.Dir(c.filename)); err != nil {
		return nil, err
	}
	stopCh := make(chan struct{}, 0)

	go func() {
		for {
			select {
			case err := <-watcher.Errors:
				go handler.Error(err)
			case ev := <-watcher.Events:
				if ev.Op&fsnotify.Write == fsnotify.Write || ev.Op&fsnotify.Create == fsnotify.Create {
					if ev.Name == c.filename {
						go handler.Updated()
					}
				}
			case <-stopCh:
				watcher.Close()
				return
			}
		}
	}()

	return stopCh, nil
}
