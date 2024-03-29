#####################################################################
# Malloc
######################################################################

***********
Main Files:
***********

mm.c
	My solution malloc package.

mdriver.c	
	The malloc driver that tests your mm.c file

mdriver
        Once you've run make, run ./mdriver to test your solution.

traces/
	Directory that contains the trace files that the driver uses
	to test your solution. Files corners.rep, short2.rep, and malloc.rep
	are tiny trace files that you can use for debugging correctness.

**********************************
Other support files for the driver
**********************************

config.h	Configures the malloc driver
fsecs.{c,h}	Wrapper function for the different timer packages
clock.{c,h}	Routines for accessing the Pentium and Alpha cycle counters
fcyc.{c,h}	Timer functions based on cycle counters
ftimer.{c,h}	Timer functions based on interval timers and gettimeofday()
memlib.{c,h}	Models the heap and sbrk function

*******************************
Building and running the driver
*******************************
To build the driver, type "make" to the shell.

To run the driver on a tiny test trace:

	unix> ./mdriver -f traces/malloc.rep

To get a list of the driver flags:

	unix> ./mdriver -h
