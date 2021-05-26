include Makefile.common

REDHAT:=$(shell pwd)
SCRIPTS:=$(REDHAT)/scripts
RPMBUILD:=$(REDHAT)/rpmbuild

# Hide command calls without debug option
ifeq ($(DEBUG),1)
  DS=
else
  DS=@
endif

BREW_OPTIONS:=$(BREW_FLAGS) --scratch

# Hide progress bar in scripts
ifeq ($(NOPROGRESS),1)
  BREW_OPTIONS:=$(BREW_OPTIONS) --noprogress
endif

# Do not wait for build finish
ifeq ($(NOWAIT),1)
  BREW_OPTIONS:=$(BREW_OPTIONS) --nowait
endif

# create an empty localversion file if you don't want a local buildid
ifneq ($(NOLOCALVERSION),1)
  ifeq ($(LOCALVERSION),)
    LOCALVERSION=$(shell cat ../localversion 2>/dev/null)
  endif
  ifeq ($(LOCALVERSION),)
    LOCALVERSION:=$(shell id -u -n | tr -dc '[:alnum:]')$(shell date +"%Y%m%d%H%M")
  else
    LOCALVERSION:=$(LOCALVERSION)
  endif
else
  LOCALVERSION:=
endif

.PHONY: rh-brew rh-brew-module rh-srpm rh-srpm-gcc rh-prep rh-help rh-clean-sources rh-rhel-koji rh-rhel-koji-gcc rh-env-prep rh-env-prep-gcc rh-local rh-local-gcc

all: rh-help

rh-brew: rh-rhel-koji

rh-clean-sources:
	$(DS)for i in $(RPMBUILD)/SOURCES/*; do \
		rm -f $$i; \
	done; \

rh-prep: rh-clean-sources
	$(DS)if [ -n "$(SOURCES_FILELIST)" ]; then \
		echo "Copying Sources: $(SOURCES_FILELIST)"; \
		cp $(SOURCES_FILELIST) $(RPMBUILD)/SOURCES; \
	fi
	$(DS)$(SCRIPTS)/process-patches.sh "$(SCRIPTS)" "$(NAME)" "$(VERSION)" "$(RELEASE)" "$(DATE)" "$(COMMIT)" "$(TARFILE)" "$(TARURL)" "$(SPECFILE)" "$(MARKER)" "$(LOCALVERSION)" "$(ZRELEASE)" "$(RC)" "$(CLANG)"
	$(DS)if [ -n "$(TARSHA512)" -a -e $(REDHAT)/$(TARFILE) -a "`$(SCRIPTS)/tarball_checksum.sh $(TARFILE)`" != "$(TARSHA512)" ]; then \
        echo "$(TARFILE) sha512sum does not match (expected: $(TARSHA512), got `$(SCRIPTS)/tarball_checksum.sh $(TARFILE)`"; \
		exit 1; \
    fi

rh-srpm: rh-prep
	$(DS)rpmbuild --define "_sourcedir $(RPMBUILD)/SOURCES" --define "_builddir $(RPMBUILD)/BUILD" --define "_srcrpmdir $(RPMBUILD)/SRPMS" --define "_rpmdir $(RPMBUILD)/RPMS" --define "_specdir $(RPMBUILD)/SPECS" --define "dist $(DIST)" --nodeps -bs $(RPMBUILD)/SPECS/$(SPECFILE)

rh-srpm-gcc: CLANG=0
rh-srpm-gcc: rh-srpm

rh-rhel-koji: rh-srpm
	@echo "Build $(SRPM_NAME) as $(BUILD_TARGET)"
	$(DS)brew build $(BREW_OPTIONS) $(BUILD_TARGET) $(RPMBUILD)/SRPMS/$(SRPM_NAME)

rh-rhel-koji-gcc: CLANG=0
rh-rhel-koji-gcc: rh-rhel-koji

rh-env-prep: rh-prep
	$(DS)sudo dnf install wget rpm-build
	$(DS)sudo dnf builddep $(RPMBUILD)/SPECS/$(SPECFILE) || echo "Build dependency installation FAILED."
	$(DS)mkdir -p ../build
	$(DS)cd ..; meson subprojects download
	$(DS)cd ../build; $(shell rpmspec -P $(RPMBUILD)/SPECS/$(SPECFILE) | ../.distro/scripts/extract_build_cmd.py | \
	              sed "s/--with-git-submodules=ignore/--with-git-submodules=update/g")

rh-env-prep-gcc: CLANG=0
rh-env-prep-gcc: rh-env-rpep

rh-local: rh-env-prep
	$(MAKE) -C $(REDHAT)/../build  VL_LDFLAGS=-Wl,--build-id

rh-local-gcc: CLANG=0
rh-local-gcc: rh-local

rh-help:
	@echo "rh-srpm:              Create srpm (for clang compiler)"
	@echo "rh-srpm-gcc:          Create srpm (for gcc compiler)"
	@echo "rh-rhel-koji:         Build package using RHEL 9 koji (using clang compiler)"
	@echo "rh-rhel-koji-gcc:     Build package using RHEL 9 koji (using gcc compiler)"
	@echo "rh-env-prep:          Install rpms required for redhat build and run configure (using clang compiler)"
	@echo "rh-local:             Run local (non-rpm) build (using clang compiler). Runs rh-env-prep on each call "
	@echo "rh-env-prep-gcc:      Install rpms required for redhat build and run configure (using gcc compiler)"
	@echo "rh-local-gcc:         Run local (non-rpm) build (using gcc compiler). Runs rh-env-prep on each call "
	@echo "rh-help:              Print out help"
