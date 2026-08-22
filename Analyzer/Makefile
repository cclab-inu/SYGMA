LLVM_CONFIG ?= llvm-config
CLANG_CXX ?= g++
CLANG_CPP_LIB ?= -l:libclang-cpp.so.14

LLVM_CXXFLAGS := $(shell $(LLVM_CONFIG) --cxxflags)
LLVM_LDFLAGS := $(shell $(LLVM_CONFIG) --ldflags --system-libs --libs core irreader analysis)

.PHONY: all clean

all: systematic_analysis clang_kernel_extractor llvm_hook_verifier

systematic_analysis: $(wildcard *.go) go.mod
	go build -buildvcs=false -o $@ .

clang_kernel_extractor: tools/clang_extractor.cpp
	$(CLANG_CXX) $(LLVM_CXXFLAGS) -std=c++17 $< -o $@ $(LLVM_LDFLAGS) $(CLANG_CPP_LIB)

llvm_hook_verifier: tools/llvm_hook_verifier.cpp
	$(CLANG_CXX) $(LLVM_CXXFLAGS) -std=c++17 $< -o $@ $(LLVM_LDFLAGS)

clean:
	rm -f systematic_analysis clang_kernel_extractor llvm_hook_verifier
