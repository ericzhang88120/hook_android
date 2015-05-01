#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

typedef int(*_MyFunc)();
int main(int argc,char* argv[])
{
	printf("dlopen so \n");
	void* sohanle = dlopen("/data/local/tmp/libtarget.so",RTLD_LAZY);

	if(sohanle == NULL)
	{
		printf("ERROR: %s\n",dlerror());
		exit(0);
	}

	_MyFunc myfunc = (_MyFunc)dlsym(sohanle,"helloprint");

	if(myfunc == NULL)
	{
		printf("ERROR: %s\n",dlerror());
		exit(0);
	}
	
	printf("address %p\n",myfunc);
	while(1)
	{
		myfunc();
		sleep(1);
	}

	dlclose(sohanle);
	return 0;
}

