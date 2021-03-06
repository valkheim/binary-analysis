NAME = load

BASE = ..
OUTBIN = $(BASE)/bin

IFLAGS = -I $(BASE)

CXXFLAGS = -Wall -Werror
CXXFLAGS += -DPACKAGE
CXXFLAGS += -DPACKAGE_VERSION

all: compile link bin

compile:
	g++ -c $(CXXFLAGS) $(IFLAGS) loader.cpp main.cpp

link:
	g++ loader.o main.o -lbfd -o $(NAME)

bin:
	mv $(NAME) $(OUTBIN)

clean:
	rm -f loader.o main.o
