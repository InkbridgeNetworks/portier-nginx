# Allow version to be manually specified in the case we have a shallow repo
ifndef VERSION
  LATEST_TAG := $(shell git tag --sort=-v:refname | head -n 1)
  COMMITS_SINCE_TAG := $(shell git rev-list --count $(LATEST_TAG)..HEAD)
  VERSION = $(patsubst v%,%,$(LATEST_TAG))-$(COMMITS_SINCE_TAG)
endif

# Where the makefile is located. We need absolute paths in rockspec files
# otherwise luarocks cannot find the tarball.
CWD := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

# Determine which flavour of tar we have, so we can add version prefixes
ifeq ($(findstring GNU,$(shell tar --version 2>/dev/null | head -n 1)),GNU)
    TAR_REWRITE_FLAG = --transform=s
else
    TAR_REWRITE_FLAG = -s
endif

# Two rocks from one tree. Both install modules under the `portier.` prefix, so
# the module list for each rock is built from an explicit file list rather than
# from a per-package directory: portier-sp takes src/portier/sp/ plus the two
# shared modules, portier-idp takes src/portier/idp/.
PACKAGES = portier-sp portier-idp

portier-sp_FILES = $(wildcard src/portier/sp/*.lua) src/portier/config.lua src/portier/token.lua
portier-sp_EXTRA = etc/nginx/portier-sp-http.conf
portier-idp_FILES = $(wildcard src/portier/idp/*.lua)
portier-idp_EXTRA = etc/nginx/portier-idp-http.conf etc/nginx/portier-idp.conf webroot/index.html

ROCKSPECS = $(PACKAGES:%=%-$(VERSION).rockspec)
ARCHIVES = $(PACKAGES:%=%-$(VERSION).tar.gz)

.PHONY: all
all: $(ROCKSPECS) $(ARCHIVES)

# Module name is the source path under src/ with / turned into . and the
# .lua suffix removed: src/portier/sp/access.lua -> portier.sp.access
%-$(VERSION).rockspec: %.rockspec.in
	@MOD_LIST=""; \
	for file in $($*_FILES); do \
		mod=$${file#src/}; \
		mod=$${mod%.lua}; \
		mod=$$(echo "$$mod" | tr '/' '.'); \
		MOD_LIST="$$MOD_LIST\n      [\"$$mod\"] = \"$$file\","; \
	done; \
	MOD_LIST="   modules = {$$MOD_LIST\n   }"; \
	sed -e 's|@VERSION@|$(VERSION)|' -e 's|@CWD@|$(CWD)|' -e "s|@MOD_LIST@|$${MOD_LIST}|" $< > $@

%-$(VERSION).tar.gz:
	@tar $(TAR_REWRITE_FLAG)"|^|$*-$(VERSION)/|" -czf $@ $($*_FILES) $($*_EXTRA)

# Syntax check. luac -p on a host with PUC Lua; CI sets LUAC to
# "luajit -bl" inside the OpenResty image, which has no luac.
LUAC ?= luac -p

.PHONY: check
check:
	@for f in src/portier/*.lua src/portier/*/*.lua; do $(LUAC) $$f >/dev/null || exit 1; done

.PHONY: clean
clean:
	@rm -f *.rockspec *.tar.gz
