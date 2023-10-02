#
# Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.  You may
# obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

USE_DOCKER=0

CONTAINER_TOOL=docker

ifeq ($(OS),Windows_NT)
	goos := windows
	ifeq ($(PROCESSOR_ARCHITEW6432),AMD64)
		goarch := arm64
	else
		ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
			goarch := arm64
		endif
	endif
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		goos := linux
	endif
	ifeq ($(UNAME_S),Darwin)
		goos := darwin
	endif
	UNAME_P := $(shell uname -p)
	UNAME_M := $(shell uname -m)
	ifneq ($(filter arm64%,$(UNAME_M)),)
		goarch := arm64
	endif
endif

WEBSITE_SRC_PATH := origin_ui/src
WEBSITE_OUT_PATH := origin_ui/src/out
WEBSITE_CACHE_PATH := origin_ui/src/.next
WEBSITE_SRC_FILES := $(shell find $(WEBSITE_SRC_PATH)/app -type f) \
						$(shell find $(WEBSITE_SRC_PATH)/components -type f) \
						$(shell find $(WEBSITE_SRC_PATH)/helpers -type f) \
						$(shell find $(WEBSITE_SRC_PATH)/public -type f) \
						origin_ui/src/tsconfig.json \
						origin_ui/src/next.config.js \
						origin_ui/src/package.json \
						origin_ui/src/package-lock.json \
						origin_ui/src/Dockerfile

WEBSITE_OUT_FILE := $(WEBSITE_OUT_FILES)/index.html

WEBSITE_CLEAN_LIST := $(WEBSITE_OUT_PATH) \
						$(WEBSITE_CACHE_PATH)


.PHONY: all
all: pelican-build

.PHONY: web-clean
web-clean:
	@echo CLEAN $(WEBSITE_CLEAN_LIST)
	@rm -rf $(WEBSITE_CLEAN_LIST)

.PHONY: web-build
web-build: origin_ui/src/out/index.html
origin_ui/src/out/index.html : $(WEBSITE_SRC_FILES)
	go generate ./...
ifeq ($(USE_DOCKER),0)
	@cd $(WEBSITE_SRC_PATH) && npm install && npm run build
else
	@cd $(WEBSITE_SRC_PATH) && $(CONTAINER_TOOL) build -t origin-ui . && $(CONTAINER_TOOL) run --rm -v `pwd`:/webapp origin-ui npm run build
endif

.PHONY: web-serve
web-serve:
ifeq ($(USE_DOCKER),0)
	@cd $(WEBSITE_SRC_PATH) && npm install && npm run dev
else
	@cd $(WEBSITE_SRC_PATH) && $(CONTAINER_TOOL) build -t origin-ui . && $(CONTAINER_TOOL) run --rm -v `pwd`:/webapp -p 3000:3000 origin-ui npm run dev
endif


PELICAN_DIST_PATH := dist

.PHONY: pelican-clean
pelican-clean:
	@echo CLEAN $(PELICAN_DIST_PATH)
	@rm -rf $(PELICAN_DIST_PATH)

.PHONY: pelican-build
pelican-build: origin_ui/src/out/index.html
	@echo PELICAN BUILD
ifeq ($(USE_DOCKER),0)
	@goreleaser --clean --snapshot
else
	@$(CONTAINER_TOOL) run -w /app -v $(PWD):/app goreleaser/goreleaser --clean --snapshot
endif

.PHONY: pelican-serve-test-origin
pelican-serve-test-origin: pelican-build
	@echo SERVE TEST ORIGIN
	@cd $(PELICAN_DIST_PATH)/pelican_$(goos)_$(goarch) && cp pelican osdf && ./osdf origin serve  -f https://osg-htc.org -v /tmp/stash/:/test

.PHONY: pelican-build-server-image
pelican-build-server-image:
	@echo BUILD SERVER IMAGE
	@$(CONTAINER_TOOL) build -t pelican-server -f images/Dockerfile .
