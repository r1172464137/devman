include $(TOPDIR)/rules.mk

PKG_NAME:=devman
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/r1172464137/devman.git
PKG_SOURCE_VERSION:=HEAD
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_USE_MIPS16:=0
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/devman
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Device Manager daemon
  DEPENDS:=+libc
  URL:=https://github.com/r1172464137/devman
endef

define Package/devman/description
  Real-time device monitoring and control daemon.
  Auto-discovers LAN devices, tracks per-device bandwidth,
  supports block/limit via nftables.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	cd $(PKG_BUILD_DIR) && \
	CGO_ENABLED=0 $(GO) build -ldflags="-s -w" -o devman .
endef

define Package/devman/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/devman $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/devman.init $(1)/etc/init.d/devman
	$(INSTALL_DIR) $(1)/usr/lib/devman
	$(INSTALL_BIN) ./files/block.sh $(1)/usr/lib/devman/
	$(INSTALL_BIN) ./files/limit.sh $(1)/usr/lib/devman/
	$(INSTALL_BIN) ./files/dhcp-hook.sh $(1)/usr/lib/devman/
endef

$(eval $(call BuildPackage,devman))
