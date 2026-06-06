appname=framespam
srcfile=framespam.c

CC=gcc
CFLAGS=-O -Wall
LDFLAGS=-lpcap

prefix=/usr/local
bindir=$(prefix)/bin



all: $(appname)

$(appname): $(srcfile)
	$(CC) $(CFLAGS) $(LDFLAGS) $(srcfile) -o $(appname)

install: $(appname)
	install -d $(bindir)
	install -s $(appname) $(bindir)
	
uninstall:
	rm -i $(bindir)/$(appname)

clean:
	rm $(appname)
