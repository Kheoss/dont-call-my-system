compile:
	g++ src/binary_modifier.cpp -o syscall_counter -lcapstone 

compileBFD:
	g++ src/binary_modifier.cpp -o syscall_counter -lbfd

execute:
	./syscall_counter hello hardened_program

compileExample:
	g++ -o test_program test_program.cpp

