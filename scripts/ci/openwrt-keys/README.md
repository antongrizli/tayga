# OpenWrt feed signing keys

`d310c6f2833e97f7` is the public usign key of the OpenWrt 24.10 release builds.
It was taken from `etc/opkg/keys/` of the sha256-pinned
`openwrt-24.10.8-armsr-armv8-rootfs.tar.gz` used by `basic.yml`, and the workflow
checks that the rootfs it downloads still carries byte-identical key material.
`scripts/ci/openwrt_feed.py` verifies a feed's `Packages` index against it and
then checks every downloaded package against the signed `SHA256sum`, so package
pins no longer break when OpenWrt rebuilds a feed.

Changing this file changes what CI trusts: review it like a pinned hash.
