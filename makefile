TARGET  = meow
CC      = gcc

INCLUDES =  include
ALLSRC =  $(wildcard sys/*.c handler/*.c misc/*.c) 
ALLOBJ =  $(patsubst %.c,%.o,$(ALLSRC))
ALLINC =  $(wildcard $(INCLUDES)/*.h)
LIBDLL =  $(INCLUDES)/utility.a 

.PHONY:clean all

$(TARGET): $(ALLOBJ) $(LIBDLL) $(ALLINC)  
	$(CC) -o $@  $(ALLOBJ) $(LIBDLL) -I $(INCLUDES) -lpthread -lmysqlclient -I/usr/include/mysql/ -L/usr/lib64/mysql
	@echo "...Finished!"
sys/%.o: sys/%.c $(ALLINC)
	$(CC) -c $< -o $@ -I $(INCLUDES) -g -Wall
misc/%.o: misc/%.c $(ALLINC)
	$(CC) -c $< -o $@ -I $(INCLUDES) -g -Wall
handler/%.o: handler/%.c $(ALLINC)
	$(CC) -c $< -o $@ -I $(INCLUDES) -g -Wall
	
all:
	@$(MAKE) -f $(INCLUDES)/mklib.mk
	@$(MAKE)
clean: 
	rm -f sys/*.o handler/*.o misc/*.o include/*.o
	
#  $@--目标文件，$^--所有的依赖文件，$<--第一个依赖文件。
