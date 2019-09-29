PROGRAM		= SEdetector
CC			= i686-w64-mingw32-gcc
CFLAGS		= -Wall
LIBS		= 
OBJS		= main.o checkSE.o
DLLNAME		= apimonitor
DLLFLAGS	= -shared -fPIC

all:	$(PROGRAM)

$(PROGRAM):	$(OBJS)
		$(CC) $(CFLAG) $(LIBS) -o $(PROGRAM) $(OBJS)

dll:	$(DLLNAME).c
	$(CC) $(DLLFLAGS) $(LIBS) -o $(DLLNAME).dll $(DLLNAME)

clean:
	rm -f *.o *~ *.dll *.exe
