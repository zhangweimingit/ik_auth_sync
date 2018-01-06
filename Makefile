# Copyright (C) 2008-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=ik_auth_sync
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/ik_auth_sync
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=iKuai
	TITLE:=ik_auth_sync
	DEPENDS:=+libpthread +libstdcpp +boost-program_options boost-system +libcrypto +libopenssl +lib_event
endef

include $(TOPDIR)/package/ik_apps/ik_rules.mk

define Package/ik_auth_sync/description
	iKuai auth sync client
endef

define Build/Compile
$(Build/Compile/kmod)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
        CXX="$(TARGET_CXX)" \
        EXTRA_CPPFLAGS="$(IK_APP_CFLAGS) -I$(STAGING_DIR)/usr/include -I$(TOOLCHAIN_DIR)" \
        EXTRA_LDFLAGS="$(IK_BIN_LDFLAGS) -lcrypto -likevent"
endef

define Package/ik_auth_sync/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ik_auth_sync $(1)/usr/bin/
endef

$(eval $(call BuildPackage,ik_auth_sync))
