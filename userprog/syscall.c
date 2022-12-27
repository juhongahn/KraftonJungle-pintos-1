#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

typedef int pid_t;

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
static void check_address(void *addr);

static void halt (void) NO_RETURN;
static void exit (int status) NO_RETURN;
static pid_t fork (const char *thread_name);
static int exec (const char *file);
static int wait (pid_t pid);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned length);
static int write (int fd, const void *buffer, unsigned length);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// FIXME: 검증 대상 변경, 위치 변경
	/* 포인터 유효성 검증 */
	check_address(f->rsp);

	switch (f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;

	case SYS_EXIT:
		break;

	case SYS_FORK:
		break;

	case SYS_EXEC:
		break;

	case SYS_CREATE:
		check_address(f->R.rsi);
		bool success = create(f->R.rsi, f->R.rdi);
		f->R.rax = success;
		break;

	case SYS_REMOVE:
		check_address(f->R.rsi);
		bool success = remove(f->R.rsi);
		f->R.rax = success;
		break;

	case SYS_OPEN:
		check_address(f->R.rsi);
		int fd = open(f->R.rsi);
		f->R.rax = fd;
		break;

	case SYS_FILESIZE:
		check_address(f->R.rsi);
		int file_size = filesize(f->R.rsi);
		f->R.rax = file_size;
		break;

	case SYS_READ:
		break;

	case SYS_WRITE:
		break;

	case SYS_SEEK:
		break;

	case SYS_TELL:
		break;

	case SYS_CLOSE:
		check_address(f->R.rsi);
		close(f->R.rsi);
		break;

	default:
		break;
	}

	thread_exit ();
}

static void
check_address(void *addr) {
	// TODO:
	// 1. 포인터 유효성 검증
	//		<유효하지 않은 포인터>
	//		- 널 포인터
	//		- virtual memory와 매핑 안 된 영역
	//		- 커널 가상 메모리 주소 공간을 가리키는 포인터 (=PHYS_BASE 위의 영역)
	if (
		!addr
		|| pml4_get_page(thread_current()->pml4, addr)
		|| is_kernel_vaddr(addr)
	) {
		// 2. 유저 영역을 벗어난 영역일 경우 프로세스 종료((exit(-1)))
		exit(-1);
	}
}

// ! TODO: 시스템 콜의 반환값을 rax 레지스터에 저장하기

void
halt (void) {
	power_off();
}

void
exit (int status) {
	// TODO: blocked by wait
}

pid_t
fork (const char *thread_name){
}

int
exec (const char *file) {
}

int
wait (pid_t pid) {
}

bool
create (const char *file, unsigned initial_size) {
	return filesys_create(file, initial_size);
}

bool
remove (const char *file) {
	return filesys_remove(file);
}

int
open (const char *file) {
	struct thread *curr_t = thread_current();
	struct file *f = filesys_open(file);

	if (f) { // FIXME: next_fd 갱신 로직 최적화
		curr_t->fdt[curr_t->next_fd] = f;
		return curr_t->next_fd++;
	}
	else {
		return -1;
	}
}

int
filesize (int fd) {
	struct thread *curr_t = thread_current();
	struct file *file_p = curr_t->fdt[fd];
	return file_length(file_p);
}

int
read (int fd, void *buffer, unsigned size) {
}

int
write (int fd, const void *buffer, unsigned size) {
}

void
seek (int fd, unsigned position) {
}

unsigned
tell (int fd) {
}

void
close (int fd) {// FIXME: next_fd 갱신 로직 최적화
	struct thread *curr_t = thread_current();
	struct file *file_p = curr_t->fdt[fd];
	file_close(file_p);
	curr_t->fdt[fd] = NULL;
}
