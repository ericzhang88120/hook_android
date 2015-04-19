#include "util.h"

int find_pid_of(const char* process_name)
{
	int id;
	pid_t pid = -1;
	DIR* dir;
	FILE *fp;
	char filename[128];
	char cmdline[256];

	struct dirent* entry;

	if(process_name == NULL)
	{
		return -1;
	}

	dir = opendir("/proc");

	if(dir ==NULL)
	{
		return -1;
	}
	while((entry=readdir(dir))!=NULL)
	{
		id = atoi(entry->d_name);
		if(id != 0)
		{
			sprintf(filename,"/proc/%d/cmdline",id);
			fp = fopen(filename,"r");
			if(fp)
			{
				fgets(cmdline, sizeof(cmdline), fp);
				fclose(fp);

				if(strcmp(process_name,cmdline)==0)
				{
					pid = id;
					break;
				}
			}
		}
	}
	closedir(dir);
	return pid;
		
}


