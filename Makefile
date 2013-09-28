# Project: combina

CC = gcc
OBJ = src/combina.o
LINKOBJ = src/combina.o
LIBS = -largtable2 -lcrypto
CINCS = -I"include"
BIN = combina
CFLAGS = -O2 -Wall -ansi -static
RM = rm -f
BINDIR=/usr/local/bin
MANDIR=/usr/local/man/man1

all: combina

$(BIN): $(OBJ)
	$(CC) $(LINKOBJ) -o combina $(LIBS)

src/combina.o: src/combina.c
	$(CC) -c src/combina.c -o src/combina.o $(CFLAGS) $(CINCS)

install: combina
	mkdir -p $(DESTDIR)/$(BINDIR) && cp combina $(DESTDIR)/$(BINDIR)

clean:
	${RM} $(OBJ) $(BIN) $(DESTDIR)/$(BINDIR)/combina $(DESTDIR)/$(MANDIR)/combina.1.gz
