#
# Copyright (C) 2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk


PKG_NAME:=dnsstub
PKG_VERSION:=0.3
PKG_RELEASE:=0


PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/xiamr/dnsstub/releases/download/v$(PKG_VERSION)/
PKG_HASH := 59bc365d232291f0a2e8178884bd7d47fbbf3bb87a4d75a2abeb4fd384df9914

PKG_LICENSE:=GPL-3.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Miao-Ren Xia <xiamr@ihep.ac.cn>


include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/$(PKG_NAME)
  SECTION:=utils
  CATEGORY:=Network
  TITLE:= DNS forwarder
  URL:=https://github.com/xiamr/dnsstub
  MAINTAINER:=Miao-Ren Xia <xiamr@ihep.ac.cn>
  DEPENDS:=+librt +boost +boost-container +boost-atomic +boost-thread +boost-log +boost-program_options
endef

define Package/$(PKG_NAME)/description
  tiny dns cache server implementation for avoiding dns contamination
endef


define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/dnsstub $(1)/usr/bin
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
