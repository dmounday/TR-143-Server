PROG=dldiag httpserver updecho
SRC=dldiag.c

LIBS=gslib/gslib.a gslib/auxsrc/cpelog.o gslib/auxsrc/dns_lookup.o

//SYSLIBS+=-L/usr/local/ssl/lib/
//SYSLIBS+= -ldl -lssl -lcrypto
//CFLAGS+=-I/usr/local/ssl/include

subdirs: 
	for n in gslib; do $(MAKE) CFLAGS='$(CFLAGS)' -C $$n || exit; done
	
all: httpserver  udpecho subdirs

httpserver: httpserver.o
	$(CC) $(CFLAGS) httpserver.c $(LIBS) $(SYSLIBS) -o httpserver
dldiag: dldiag.o
	$(CC) $(CFLAGS) dldiag.c $(LIBS) $(SYSLIBS) -o dldiag

udpecho: UDPEcho.o
	$(CC) $(CFLAGS) UDPEcho.c $(LIBS) $(SYSLIBS) -o udpecho
	
clean:
	-rm $(PROG) $(PROG).o UDPEcho.o
	for n in gslib; do $(MAKE) clean -C $$n || exit; done 
