## base.mk: 799083f+, see https://github.com/jmesmon/trifles.git
# Usage:
#
# == Targets ==
# all
#
# $(TARGETS_BIN)	executable binaries (built in all VARIANTS)
# $(TARGETS_STATIC_LIB)	static libraries (built in all VARIANTS)
# $(VARIANTS)		a collection of the global bins & slibs built with
#			particular flags
#
# show-cflags		Set the var FILE=some-c-file.c to see cflags for a
#                       particular file set VARIANT=variant-dir for the complete picture
#
# show-targets-bin
# show-targets-slib
# show-targets-all
#
# install
# clean
# TARGET.clean		clean all variants of TARGET
# VARIANT.clean		clean a signal variant
# VARIANT/TARGET.clean	clean a single target in a particular variant
# TARGET.install
#
# == For use by the one who runs 'make' (or in some cases the Makefile) ==
# $(O)		    set to a directory to write build output to that directory
# $(V)              when defined, prints the commands that are run.
# $(CFLAGS)         expected to be overridden by the user or build system.
# $(LDFLAGS)        same as CFLAGS, except for LD.
# $(ASFLAGS)
# $(CXXFLAGS)
# $(CPPFLAGS)
#
# $(CROSS_COMPILE)  a prefix on $(CC) and other tools.
#                   "CROSS_COMPILE=arm-linux-" (note the trailing '-')
# $(CC)
# $(CXX)
# $(LD)
# $(AS)
# $(AR)
# $(FLEX)
# $(BISON)
# $(RANLIB)
# $(NM)
#
# == Required in the makefile ==
# all::		    place this target at the top.
# $(obj-sometarget) the list of objects (generated by CC) that make up a target
#                   (in the list TARGET).
# $(TARGETS_BINS)   a list of executable binaries (the output of LD).
# $(TARGETS_STATIC_LIB)  a list of static libraries (created using AR).
#
# == Optional (for use in the makefile) ==
# $(NO_INSTALL)     when defined, no install target is emitted.
# $(ALL_CFLAGS)     non-overriden flags. Append (+=) things that are absolutely
#                   required for the build to work into this.
# $(ALL_LDFLAGS)    same as ALL_CFLAGS, except for LD.
#		    example for adding some library:
#
#			sometarget: ALL_LDFLAGS += -lrt
#
#		    Note that in some cases (none I can point out, I just find
#		    this shifty) this usage could have unintended consequences
#		    (such as some of the ldflags being passed to other link
#		    commands). The use of $(ldflags-sometarget) is recommended
#		    instead.
#
# $(ALL_CPPFLAGS)
#
# $(O_)		    use this as the output directory if you're writing new rules
#
# $(ldflags-some-target)
# $(ldflags-some-variant)
# $(ldflags-some-variant/some-target)
#
# $(cflags-some-object-without-suffix)
# $(cflags-some-variant)
# $(cflags-some-variant/some-object-without-suffix)
#
# $(cxxflags-some-object-without-suffix)
# $(cxxflags-some-variant)
# $(cxxflags-some-variant/some-object-without-suffix)
#
# $(asflags-some-object-without-suffix)
# $(asflags-some-variant)
# $(asflags-some-variant/some-object-without-suffix)
#
# OBJ_TRASH		$(1) expands to the object. Expanded for every object.
# TARGET_TRASH		$* expands to the target. Expanded for every target.
# TRASH
# BIN_EXT		Add an extention to each binary produced (.elf, .exe)
#
# ON_EACH_OBJ		a list of functions to $(call) for every object target
# 			$1 = object
# ON_EACH_VARIANT	a list of functions to be evaluated for every variant.
#			$1 = variant, $2 = full output dir
#
# == How to use with FLEX + BISON support ==
#
# obj-foo = name.tab.o name.ll.o
# name.ll.o : name.tab.h
# TRASH += name.ll.c name.tab.c name.tab.h
# # Optionally
# PP_name = not_quite_name_
#

# TODO:
# - install disable per target.
# - flag tracking per target.'.obj.o.cmd'
# - profile guided optimization support.
# - build with different flags placed into different output directories.
# - library building (shared & static)
# - per-target CFLAGS (didn't I hack this in already?)
# - will TARGETS always be outputs from Linking?
# - continous build mechanism ('watch' is broken)
# - handle the mess that is linking for C++ vs C vs ld -r
# - CCLD vs LD and LDFLAGS
# - per target CCLD/LD
# - C++ and CCLD choices (per-target?)
# - check if certain code builds
# - check if certain flags work
# - check if certain headers/libs are installed
# - use the above 3 to conditionally enable certain targets

# Delete the default suffixes
.SUFFIXES:

.PHONY: all
all::

ifdef MAKE_DEBUG
debug = $(warning $1)
else
debug =
endif

# Provide a dummy target to force rules to always run
.PHONY: FORCE

# Output to current directory by default
O = .

# No variants by default
VARIANTS = .

# TARGETS_BIN should be used in new code
TARGETS_BIN ?= $(TARGETS)
TARGETS_ALL = $(TARGETS_BIN) $(TARGETS_STATIC_LIB)

# link against things here
PREFIX  ?= $(HOME)

ifdef WANT_VERSION
VERSION := $(shell $(HOME)/trifles/setlocalversion)
VERSION_FLAGS = -DVERSION=$(VERSION)
endif

# Prioritize environment specified variables over our defaults
var-def = $(if $(findstring $(origin $(1)),default undefined),$(eval $(1) = $(2)))

# overriding these in a Makefile while still allowing the user to
# override them is tricky.
$(call var-def,CC,$(CROSS_COMPILE)gcc)
$(call var-def,CXX,$(CROSS_COMPILE)g++)
$(call var-def,AR,$(CROSS_COMPILE)gcc-ar)
$(call var-def,RANLIB,$(CROSS_COMPILE)gcc-ranlib)
$(call var-def,NM,$(CROSS_COMPILE)gcc-nm)
$(call var-def,CCLD,$(CC))
$(call var-def,LD,ld)
$(call var-def,AS,$(CC))
$(call var-def,RM,rm -f)
$(call var-def,FLEX,flex)
$(call var-def,BISON,bison)

# FIXME: checking these is completely wrong, we sould be detecting if certain
# flags are supported by the compiler by running it with them.
IS_CLANG := $(shell echo | $(CC) -v 2>&1 | head -n1 | grep -q '^clang' && echo 1 || echo 0)
IS_GCC   := $(shell echo | $(CC) -v 2>&1 | tail -n1 | grep -q '^gcc'   && echo 1 || echo 0)

ifeq ($(IS_CLANG),1)
CC_TYPE ?= clang
endif
ifeq ($(IS_GCC),1)
CC_TYPE ?= gcc
endif

show-cc_type:
	@echo $(CC_TYPE)

CC_PREFIX = $(patsubst %gcc,%,$(CC))

show-cc_prefix:
	@echo $(CC_PREFIX)

show-cc:
	@echo $(CC)

ifdef DEBUG
ifeq ($(IS_GCC),1)
OPT=-Og
else
OPT=-O0
endif
else
OPT=-Os
endif

DBG_FLAGS = -ggdb3 -gdwarf-4 -fvar-tracking-assignments
ifndef NO_SANITIZE
DBG_FLAGS += -fsanitize=address
ifeq ($(IS_CLANG),1)
DBG_FLAGS += -fsanitize=undefined
endif
endif

ifndef NO_LTO
# TODO: use -flto=jobserver
ifeq ($(CC_TYPE),gcc)
CFLAGS  ?= -flto $(DBG_FLAGS) -pipe
LDFLAGS ?= $(ALL_CFLAGS) $(OPT) -fuse-linker-plugin
else ifeq ($(CC_TYPE),clang)
CFLAGS  ?= -emit-llvm $(DBG_FLAGS) -pipe
LDFLAGS ?= $(OPT)
endif
else
CFLAGS  ?= $(OPT) $(DBG_FLAGS) -pipe
endif

# c/c+++ shared flags
COMMON_CFLAGS += -Wall
COMMON_CFLAGS += -Wundef -Wshadow
COMMON_CFLAGS += -Wcast-align
COMMON_CFLAGS += -Wwrite-strings

# C only flags that just turn on some warnings
C_CFLAGS = $(COMMON_CFLAGS)
C_CFLAGS += -Wstrict-prototypes
C_CFLAGS += -Wmissing-prototypes
C_CFLAGS += -Wold-style-definition
C_CFLAGS += -Wmissing-declarations
C_CFLAGS += -Wundef
C_CFLAGS += -Wbad-function-cast

# -Wpointer-arith		I like pointer arithmetic
# -Wnormalized=id		not supported by clang
# -Wunsafe-loop-optimizations	not supported by clang

ALL_CFLAGS += -std=gnu11

ALL_CPPFLAGS += $(CPPFLAGS)

ALL_CFLAGS   += $(ALL_CPPFLAGS) $(C_CFLAGS) $(CFLAGS)
ALL_CXXFLAGS += $(ALL_CPPFLAGS) $(COMMON_CFLAGS) $(CXXFLAGS)

ifndef NO_BUILD_ID
LDFLAGS += -Wl,--build-id
else
LDFLAGS += -Wl,--build-id=none
endif

ifndef NO_AS_NEEDED
LDFLAGS += -Wl,--as-needed
else
LDFLAGS += -Wl,--no-as-needed
endif

ALL_LDFLAGS += $(LDFLAGS)
ALL_ASFLAGS += $(ASFLAGS)

# FIXME: need to exclude '-I', '-l', '-L' options
# - potentially seperate those flags from ALL_*?
MAKE_ENV = CC="$(CC)" CCLD="$(CCLD)" AS="$(AS)" CXX="$(CXX)" AR="$(AR)" RANLIB="$(RANLIB)" NM="$(NM)"
         # CFLAGS="$(ALL_CFLAGS)" \
	   LDFLAGS="$(ALL_LDFLAGS)" \
	   CXXFLAGS="$(ALL_CXXFLAGS)" \
	   ASFLAGS="$(ALL_ASFLAGS)"

ifdef VERBOSE
V=$(VERBOSE)
endif

ifndef V
define q
@printf "  %-7s %s\n" "$1" "$2" ;
endef
else
define q
endef
endif

QUIET_CC    = $(call q,CC,$@)
QUIET_CXX   = $(call q,CXX,$@)
QUIET_LINK  = $(call q,LINK,$@)
QUIET_LSS   = $(call q,LSS,$@)
QUIET_SYM   = $(call q,SYM,$@)
QUIET_FLEX  = $(call q,FLEX,$@)
QUIET_BISON = $(call q,BISON,$*.tab.c $*.tab.h)
QUIET_AS    = $(call q,AS,$@)
QUIET_MAKE  = $(call q,MAKE,$@)
QUIET_AR    = $(call q,AR,$@)

define sub-make-no-clean
$1 : FORCE
	+$$(QUIET_MAKE)$$(MAKE) $$(MAKE_ENV) $$(MFLAGS) $3 -C $$(dir $$@) $$(notdir $$@)
endef

define sub-make-clean
$(call sub-make-no-clean,$(1),$(2))
.PHONY: $(1)
clean: $(1)
endef

define sub-make
$(call sub-make-no-clean,$(1),$(2))
$(call sub-make-clean,$(dir $(1))clean,$(2))
endef

# Avoid deleting .o files
.SECONDARY:

# Others append deps to clean to cleanup their own mess
.PHONY: clean
clean:
	$(RM) $(TRASH) $(obj-trash)

# $1 = object file
# Output = dependency file
obj-to-dep = $(foreach obj,$(1),$(dir $(obj)).$(notdir $(obj)).d)
obj-all    = $(foreach target,$(TARGETS_ALL),$(obj-$(target)))

$(foreach obj,$(obj-all),$(foreach act,$(ON_EACH_OBJ),$(eval $(call $(act),$(obj)))))

# $1 - variant
# Output - full path to dep files for every object for the given variant
variant-deps = $(addprefix $(O_)/$1,$(call obj-to-dep,$(obj-all)))

# $1 = target name
# $2 = output dir
target-obj = $(addprefix $(2)/,$(obj-$(1)))

# flags-template flag-prefix vars message
# Defines a target '.TRACK-$(flag-prefix)FLAGS'.
# if $(ALL_$(flag-prefix)FLAGS) or $(var) changes, any rules depending on this
# target are rebuilt.
# $1 = the XXX in ALL_XXXFLAGS
# $2 = another var or set of vars to tack on, typically the command name
# $3 = descriptive string
# $4 = output dir
define flags-template
TRACK_$(1)FLAGS = $(foreach var,$(2),$$($(var))):$$(subst ','\'',$$(ALL_$(1)FLAGS))
$(4)/.TRACK-$(1)FLAGS: FORCE
	@FLAGS='$$(TRACK_$(1)FLAGS)'; \
	if test x"$$$$FLAGS" != x"`cat $(4)/.TRACK-$(1)FLAGS 2>/dev/null`" ; then \
		echo 1>&2 "    * new $(3)"; \
		echo "$$$$FLAGS" >$(4)/.TRACK-$(1)FLAGS; \
	fi
TRASH += $(4)/.TRACK-$(1)FLAGS
endef

parser-prefix = $(if $(PP_$*),$(PP_$*),$*_)
dep-gen = -MMD -MF $(call obj-to-dep,$@)

# $1 = bin name ("foo")
# $2 = output dir
# $3 = variant name
define BIN-LINK
$(call debug,BIN-LINK $1 $2 $3)
$2/$1$(BIN_EXT): $2/.TRACK-LDFLAGS $(call target-obj,$(1),$2)
	$$(QUIET_LINK)$$(CCLD) -o $$@ $$(call target-obj,$(1),$2) $$(ALL_LDFLAGS) $$(ldflags-$(1)) $$(ldflags-$3)

$3: $2/$1$(BIN_EXT)

.PHONY: $2/$1$(BIN_EXT).clean
$2/$1$(BIN_EXT).clean:
	$$(RM) $$(call target-obj,$1,$2) $2/$1$(BIN_EXT) $$(TARGET_TRASH)
$3.clean: $2/$1.clean

endef

# $1 = slib name ("libfoo.a")
# $2 = output dir
# $3 = variant name
define SLIB-LINK
$(call debug,SLIB-LINK $1 $2 $3)
$(2)/$(1): $(2)/.TRACK-ARFLAGS $(call target-obj,$(1),$2)
	$$(QUIET_AR)$$(AR) -o $$@ $$(call target-obj,$(1),$2) $$(ALL_ARFLAGS) $$(arflags-$(1)) $$(arflags-$3)

$3: $2/$1

.PHONY: $2/$1$(BIN_EXT).clean
$2/$1.clean:
	$$(RM) $$(call target-obj,$1,$2) $2/$1 $$(TARGET_TRASH)
$3.clean: $2/$1.clean

endef

# Provide $target.clean which maps to a clean across all variants
# $1 = bin-name
define DEF-CLEAN-TARGET
$(call debug,DEF-CLEAN-TARGET $1)
.PHONY: $1.clean
$1.clean: $(foreach variant,$(VARIANTS),$(variant)/$1.clean)

endef

$(foreach target,$(TARGETS_BIN),$(eval $(call DEF-CLEAN-TARGET,$(target))))
$(foreach target,$(TARGETS_STATIC_LIB),$(eval $(call DEF-CLEAN-TARGET,$(target))))

# $1 = variant directory
# $2 = full output directory ($(O)/$(1))
define VARIANT-DEF_
$(call debug,VARIANT-DEF_ $1 $2)

.PHONY: $1.clean
$1.clean:

.PHONY: $1
$1:

all:: $1

clean: $1.clean

$(call flags-template,AR,AR,object archiver flags,$2)
$(call flags-template,AS,AS,assembler build flags,$2)
$(call flags-template,C,CC,c build flags,$2)
$(call flags-template,CXX,CXX,c++ build flags,$2)
$(call flags-template,LD,LD,link flags,$2)

$(foreach target,$(TARGETS_BIN),$(call BIN-LINK,$(target),$2,$1))
$(foreach slib,$(TARGETS_STATIC_LIB),$(call SLIB-LINK,$(slib),$2,$1))

$2/%.tab.h $2/%.tab.c : %.y
	$$(QUIET_BISON)$$(BISON) --locations -d \
		-p '$$(parser-prefix)' -k -b $$* $$<

$2/%.ll.c: %.l
	$$(QUIET_FLEX)$$(FLEX) -P '$$(parser-prefix)' --bison-locations --bison-bridge -o $$@ $$<

$2/%.o: %.c $2/.TRACK-CFLAGS
	$$(QUIET_CC)$$(CC) $$(dep-gen) -c -o $$@ $$< $$(ALL_CFLAGS) $$(cflags-$$*) $$(cflags-$1) $$(cflags-$1/$$*)

$2/%.o: %.cc $2/.TRACK-CXXFLAGS
	$$(QUIET_CXX)$$(CXX) $$(dep-gen) -c -o $$@ $$< $$(ALL_CXXFLAGS) $$(cxxflags-$$*) $$(cxxflags-$1) $$(cxxflags-$1/$$*)

$2/%.o: %.S $2/.TRACK-ASFLAGS
	$$(QUIET_AS)$$(AS) -c $$(ALL_ASFLAGS) $$< -o $$@ $$(asflags-$$*) $$(asflags-$1) $$(asflags-$1/$$*)


$(call debug,ON_EACH_VARIANT $(ON_EACH_VARIANT) +++)
$(foreach each_var_func,$(ON_EACH_VARIANT),$(call $(each_var_func),$1,$2))
$(call debug,ON_EACH_VARIANT ---)

#-include $(call variant-deps,$1)
endef

# $1 = variant directory
define VARIANT-DEF
$(call debug,VARIANT-DEF $1)
$(call VARIANT-DEF_,$(1),$(O)/$(1))
endef

$(foreach variant,$(VARIANTS),$(eval $(call VARIANT-DEF,$(variant))))

# XXX: Should these show all VARIANTS of their TARGETS?
.PHONY: show-targets-bin
show-targets-bin:
	@echo $(TARGETS_BIN)

.PHONY: show-targets-slib
show-targets-slib:
	@echo $(TARGETS_STATIC_LIB)

.PHONY: show-targets-all
show-targets-all: show-targets-bin show-targets-slib

.PHONY: show-cflags
show-cflags:
	@echo $(ALL_CFLAGS) $(cflags-$(FILE:.c=)) $(cflags-$(VARIANT)) $(cflags-$(VARIANT)/$(FILE:.c=))

###
### Things below here don't know about variants
###

ifndef NO_INSTALL
# install into here
DESTDIR ?= $(PREFIX)
# binarys go here
BINDIR  ?= $(DESTDIR)/bin
.PHONY: install %.install
%.install: %
	mkdir -p $(BINDIR)
	install $* $(BINDIR)
install: $(foreach target,$(TARGETS_BIN),$(target).install)
endif

