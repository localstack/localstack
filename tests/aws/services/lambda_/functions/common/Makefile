# Top-level Makefile to invoke all make targets in sub-directories

# Based on https://stackoverflow.com/a/72209214/6875981
SUBDIRS := $(patsubst %/,%,$(wildcard */))

.PHONY: all $(MAKECMDGOALS) $(SUBDIRS)
$(MAKECMDGOALS) all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)
