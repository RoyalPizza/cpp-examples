mkdir -p bin obj
clang++ -g -O0 -c main.cpp -o obj/main.o 
clang++ obj/main.o -o bin/main
