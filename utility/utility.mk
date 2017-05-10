LIBDLL  = utility.a

LIBSRC  = $(wildcard *.c)
LIBOBJ  = $(patsubst %.c,%.o,$(LIBSRC))
LIBINC  = $(wildcard ../include/*.h)

.PHONY:clean

$(LIBDLL): $(LIBOBJ) 
	rm -rf $@
	cp hybServKit.a $@ 
	ar -r $@ $^
%.o: %.c $(LIBINC)
	$(CC) -c $< -o $@ -I ../include  -g -Wall

clean:
	rm -f  $(LIBOBJ) $(LIBDLL)
