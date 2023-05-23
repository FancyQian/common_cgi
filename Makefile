EXEC = cgi-bin
SRC += cgi-bin.c
all: $(EXEC) 

$(EXEC):$(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o