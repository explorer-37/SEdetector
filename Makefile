PROGRAM = SEdetector
CC	= gcc
CFLAGS	= -Wall
LIBS	= 
OBJS	= main.o

all:	$(PROGRAM)

$(PROGRAM):	$(OBJS)
		$(CC) $(OBJS) $(CFLAG) $(LIBS) -o $(PROGRAM)

clean:;		rm -f *.o *~ *.dll *.exe
