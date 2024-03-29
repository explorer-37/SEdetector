PROGRAM		= SEdetector
#CC			= i686-w64-mingw32-gcc
CC			= gcc
CFLAGS		= -Wall -Wextra -m64
LIBS		= 
OBJS		= main.o checkSE.o
DLLNAME		= apimonitor
DLLFLAGS	= -shared -fPIC
DLLLIBS		= 

all:	exe dll

exe:	$(OBJS)
		$(CC) $(CFLAG) $(LIBS) -o $(PROGRAM) $(OBJS)

dll:	$(DLLNAME).c
	$(CC) $(CLAG) $(DLLFLAGS) $(DLLLIBS) -o $(DLLNAME).dll $(DLLNAME).c

clean:
	rm -f *.o *~ *.dll *.exe
