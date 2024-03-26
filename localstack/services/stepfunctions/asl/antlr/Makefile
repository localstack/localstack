# Define default ANTLR4 tool dump directory.
ANTLR4_DIR = .antlr

# Define the default input and output directory for ANTLR4 grammars.
ANTLR4_SRC_DIR = .
ANTLR4_TARGET_DIR = $(ANTLR4_SRC_DIR)/runtime
ANTLR4_GRAMMAR_FILES = $(wildcard $(ANTLR4_SRC_DIR)/*.g4)

# Define the default ANTLR4 version and jar file.
ANTLR4_VERSION ?= 4.13.1
ANTLR4_JAR ?= $(ANTLR4_DIR)/antlr-$(ANTLR4_VERSION)-complete.jar

# Define the download path for ANTLR4 parser generator.
ANTLR4_URL = https://www.antlr.org/download/antlr-$(ANTLR4_VERSION)-complete.jar

# Define the default ANTLR4 run command and options.
RUN_ANTLR4 = java -jar $(ANTLR4_JAR) -Dlanguage=Python3 -visitor

install:        ## Install the dependencies for compiling the ANTLR4 project.
	@npm i -g --save-dev antlr-format@2.1.4
	@mkdir -p $(ANTLR4_DIR)
	@curl -o $(ANTLR4_JAR) $(ANTLR4_URL)

build: $(ANTLR4_GRAMMAR_FILES)        ## Build the ANTLR4 project.
	@echo "Compiling grammar files in $(ANTLR_SRC_DIR)"
	@mkdir -p $(ANTLR4_TARGET_DIR)
	@for grammar in $^ ; do \
		echo "Processing $$grammar..."; \
		$(RUN_ANTLR4) $$grammar -o $(ANTLR4_TARGET_DIR) -Xexact-output-dir; \
	done

format:
	@antlr-format *.g4

clean:        ## Clean up the ANTLR4 project directory.
	rm -rf $(ANTLR4_TARGET_DIR)
	rm -rf $(ANTLR4_DIR)

.PHONY: install build format clean
