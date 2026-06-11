# devman - OpenWrt Device Manager
GO ?= go
CGO_ENABLED ?= 0
LDFLAGS ?= -s -w
OUT ?= devmand

all: $(OUT)

$(OUT): devman/src/main.go devman/src/go.mod
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -C devman/src -ldflags="$(LDFLAGS)" -o ../../$(OUT) .

clean:
	rm -f $(OUT)

.PHONY: all clean
