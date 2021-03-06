NAME = gadgets

BASE = ..
OUTBIN = $(BASE)/bin

IFLAGS = -I $(BASE)
IFLAGS += -I ./zydis-patch

CXXFLAGS = -std=gnu++2a
CXXFLAGS += -Werror -Wall
CXXFLAGS += -DPACKAGE
CXXFLAGS += -DPACKAGE_VERSION

LDFLAGS = -lfmt
LDFLAGS += -lbfd # https://ftp.gnu.org/old-gnu/Manuals/bfd-2.9.1/bfd.html
LDFLAGS += -lZydis # https://zydis.re

all: compile link bin

compile:
	g++ -c $(CXXFLAGS) $(IFLAGS) main.cpp ../loader/loader.cpp

link:
	g++ loader.o main.o $(LDFLAGS) -o $(NAME)

bin:
	mv $(NAME) $(OUTBIN)

clean:
	rm -f loader.o main.o

