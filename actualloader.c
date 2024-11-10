#define _XOPEN_SOURCE 700
#include "loader.h"
#include <signal.h>
typedef void (*void_func_t)(void);
Elf32_Ehdr *ehdr;
Elf32_Phdr *phdr;
FILE *object_file;
int page_faults=0;
int page_allocations=0;
int total_fragmentations=0;
const size_t KB4 = 4096; // 4KB page size

/*
 * release memory and other cleanups
 */
void loader_cleanup() {
     
   if(ehdr){
	 free(ehdr);
       ehdr=NULL;	 
}
if(phdr){
	free(phdr);
	phdr=NULL;
}

}

void page_fault_handler(int sig, siginfo_t *si, void *unused) {
    // printf("in segfault");
    void *where = si->si_addr; // Address that caused the fault
    page_faults++; // Count this page fault

    // Determine which segment the faulting address belongs to
    for (unsigned short i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD ) {
            if ((uintptr_t)where >= phdr[i].p_vaddr &&
                (uintptr_t)where < phdr[i].p_vaddr + phdr[i].p_memsz) {
                    printf("segoffset = %d", phdr[i].p_offset);

            //     // Determine the offset within the segment
                uintptr_t pagepos = ((uintptr_t)where / KB4) * KB4;
                void *mapped_page = mmap((void*) pagepos, KB4,
                                         PROT_READ | PROT_WRITE | PROT_EXEC,
                                         MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
                if (mapped_page == MAP_FAILED) {
                    perror("mmap");
                    exit(1);
                }
                if(phdr[i].p_vaddr+phdr[i].p_filesz-pagepos<KB4){
                    total_fragmentations+=KB4-(phdr[i].p_vaddr+phdr[i].p_filesz-pagepos);
                }
                // Calculate offset in file to load contents into the mapped page
                size_t offset_in_segment = pagepos - phdr[i].p_vaddr;
                fseek(object_file, phdr[i].p_offset +offset_in_segment, SEEK_SET);
                int read=fread(mapped_page, 1, KB4, object_file);
                // printf("%duwu",phdr[i].p_filesz);
                // printf("%d |||| %d |||| %d |||| %d",(uintptr_t)where,phdr[i].p_vaddr,phdr[i].p_offset,offset_in_segment);
                // total_fragmentations+=KB4-read;
                page_allocations++; // Count this page allocation
            // printf("||||||||||||||");
            // exit(1);
            
            
                return;
            }
        }
    }
}

/*
 * Load and run the ELF executable file
 */
void load_and_run_elf(const char* exe) {
    // const char *object_file_name = argv[1];
    object_file = fopen(exe, "rb");
    if (object_file == NULL) {
            fprintf(stderr, "Unable to open file\n");
            exit(1);
            // return 1;
    }

    // printf("2");
	ehdr = malloc(sizeof(Elf32_Ehdr));
    fread(ehdr, sizeof(Elf32_Ehdr),1,object_file);

	if(memcmp(ehdr->e_ident,ELFMAG,SELFMAG)!=0){
			fprintf(stderr,"Invalid ELF header!\n");
			loader_cleanup();
			exit(1);
    }
    

	if (ehdr->e_ident[EI_CLASS]!=ELFCLASS32||
			ehdr->e_ident[EI_DATA]!=ELFDATA2LSB)
		{
			fprintf(stderr,"Not 32 bit and little endian\n");
			loader_cleanup();
			exit(1);}

	if (ehdr->e_type!=ET_EXEC){
		fprintf(stderr,"Not Executable file");
		loader_cleanup();
		exit(1);
    }
	unsigned short phcount = ehdr->e_phnum;
	unsigned short phsize = ehdr->e_phentsize;
	phdr = malloc(phcount* sizeof(Elf32_Phdr));

    // printf("phoff %x", ehdr->e_phoff);
    fseek(object_file, ehdr->e_phoff, SEEK_SET);
	if (fread(phdr, phcount * phsize, 1, object_file) != 1) {
        fprintf(stderr, "Failed to read program headers\n");
        loader_cleanup();
        exit(1);
    }
    // printf("3\n");

// printf("3");
    // printf("ehdr entry is %x\n", ehdr->e_entry);
	// for(unsigned short i = 0; i<phcount; i++)
	// {
    //     // printf("type is %d\n", phdr[i].p_type);
	// 	if(phdr[i].p_type==PT_LOAD && phdr[i].p_flags==PF_R+PF_X)
    //     // if(phdr[i].p_vaddr < ehdr->e_entry && phdr[i].p_vaddr+phdr[i].p_align > ehdr->e_entry)
	// 	{
	// 		// printf("found");
	// 		void* virt = mmap(NULL, phdr[i].p_memsz, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	// 		if (virt == MAP_FAILED) {
    //             fprintf(stderr, "Memory mapping failed\n");
    //             loader_cleanup();
    //             exit(1);
    //         }
    //         // printf("offset is %x\n", phdr[i].p_offset);
    //         // printf("size if %x\n", phdr[i].p_memsz);
	// 		fseek(object_file, phdr[i].p_offset, SEEK_SET);
	// 		fread(virt, phdr[i].p_filesz, 1, object_file);
    //         // printf("virt = %p\n", virt);
    //         // printf("v = %x\n", phdr[i].p_vaddr);
    //         // printf("bracker = %x\n",  (ehdr->e_entry - phdr[i].p_vaddr));


	// 		break;
	// 	}
	// }
            typedef int (*func_ptr_t)(void);

            func_ptr_t func = (func_ptr_t)(ehdr->e_entry); //lhs = function pointer, rhs = ?
            int ans = func();
            

  			printf("User _start return value = %d\n",ans);
            printf("page faults=%d , page allocations=%d , fragmentation=%d",page_faults,page_allocations,total_fragmentations);
}
  // 1. Load entire binary content into the memory from the ELF file.
  // 2. Iterate through the PHDR table and find the section of PT_LOAD 
  //    type that contains the address of the entrypoint method in fib.c
  // 3. Allocate memory of the size "p_memsz" using mmap function 
  //    and then copy the segment content
  // 4. Navigate to the entrypoint address into the segment loaded in the memory in above step
  // 5. Typecast the address to that of function pointer matching "_start" method in fib.c.
  // 6. Call the "_start" method and print the value returned from the "_start"
  

int main(int argc, char** argv) 
{
  if(argc != 2) {
    printf("Usage: %s <ELF Executable> \n",argv[0]);
    exit(1); 
  }
  struct sigaction sa;

    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = page_fault_handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1){
        perror("sigaction");
        exit(1);
    }
        
  printf("1");
  
  // 1. carry out necessary checks on the input ELF file
  // 2. passing it to the loader for carrying out the loading/execution
  const char *object_file_name = argv[1];
  load_and_run_elf(object_file_name);
  // 3. invoke the cleanup routine inside the loader  
  loader_cleanup();
  return 0;
}