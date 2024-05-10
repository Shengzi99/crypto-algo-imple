CC = gcc
CXX = g++

CFLAGS = -Wall -maes -O3 -funroll-loops
CXXFLAGS = -Wall -maes -O3 -funroll-loops

SRCDIR = .
OBJDIR = obj
BINDIR = bin

SOURCES := $(wildcard $(SRCDIR)/*.c)
OBJECTS := $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SOURCES))

all: $(BINDIR)/main

$(OBJDIR)/%.o : $(SRCDIR)/%.c
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BINDIR)/main: main.cpp $(OBJECTS) 
	$(CXX) $(CXXFLAGS) $^ -o $@

echo:
	echo $(SOURCES)
	echo $(OBJECTS)

.PHONY: clean
clean:
	rm -rf $(OBJDIR)/*
	rm -rf $(BINDIR)/*