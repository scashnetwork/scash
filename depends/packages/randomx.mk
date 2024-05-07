package=randomx
$(package)_version=1.2.1
$(package)_download_path=https://github.com/tevador/RandomX/archive/refs/tags/
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=2e6dd3bed96479332c4c8e4cab2505699ade418a07797f64ee0d4fa394555032
$(package)_patches=custom_configuration.patch

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/custom_configuration.patch
endef

define $(package)_config_cmds
  $($(package)_cmake)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
